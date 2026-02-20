"""
Real-Time Live Anomaly Detector.

Captures actual network packets from a real interface using Scapy,
extracts flow-based features, and runs ML predictions in real time.
Requires root/sudo for raw packet capture.
"""

import os
import sys
import time
import logging
import warnings
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
from collections import deque, defaultdict
from typing import Optional, List

# Suppress sklearn feature-name warnings (we guarantee correct column order)
warnings.filterwarnings(
    "ignore",
    message="X does not have valid feature names",
    category=UserWarning,
)

logger = logging.getLogger(__name__)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.config import MODELS_DIR
from src.utils.siem_logger import SIEMLogger

try:
    from src.models.live_capture import LiveNetworkCapture, SCAPY_AVAILABLE
except ImportError:
    SCAPY_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════
#  FEATURE COLUMNS (must match training order exactly)
# ═══════════════════════════════════════════════════════════════
UNSW_FEATURES = [
    "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes",
    "dbytes", "rate", "sttl", "dttl", "sload", "dload", "sloss",
    "dloss", "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb",
    "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean", "dmean",
    "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl",
    "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd",
    "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports",
]


class AnomalyDetector:
    """
    Real-time live network anomaly detector.
    Captures actual packets from a network interface, extracts flow features,
    and runs ML predictions using the trained UNSW-NB15 XGBoost model.
    """

    # Confidence threshold — predictions below this are demoted to NORMAL
    # to reduce false alerts on ambiguous / borderline flows.
    ANOMALY_CONFIDENCE_THRESHOLD = 0.65

    # Well-known benign traffic patterns that are safe to whitelist.
    # These produce noisy false positives because the training data
    # doesn't include normal everyday traffic like mDNS, NTP, DHCP, etc.
    _SAFE_DST_PORTS = {
        123,   # NTP
        5353,  # mDNS
        1900,  # SSDP / UPnP
    }
    _SAFE_MULTICAST_PREFIXES = ("224.", "239.", "ff02:", "255.255.255.255")

    def __init__(self, dataset="unsw", interface=None):
        self.dataset = dataset
        self.interface = interface

        # ML artifacts
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.encoders = None

        # Live capture engine
        self._capture: Optional[LiveNetworkCapture] = None

        # Detection state
        self._running = False
        self._detection_buffer: deque = deque(maxlen=1000)
        self._history: deque = deque(maxlen=2000)

        # SIEM-compatible event logger (Splunk / CEF)
        self.siem_logger = SIEMLogger()

        # Stats
        self.stats = {
            "total_packets": 0,
            "normal_count": 0,
            "anomaly_count": 0,
            "anomaly_rate": 0.0,
            "start_time": None,
            "interface": None,
            "raw_packets": 0,
        }

        self._load_model()

    # ══════════════════════════════════════════════════════════
    #  Load Model & Preprocessing Artifacts
    # ══════════════════════════════════════════════════════════

    def _load_model(self):
        model_path = os.path.join(MODELS_DIR, f"best_model_{self.dataset}.pkl")
        scaler_path = os.path.join(MODELS_DIR, f"scaler_{self.dataset}.pkl")
        features_path = os.path.join(MODELS_DIR, f"feature_names_{self.dataset}.pkl")
        encoders_path = os.path.join(MODELS_DIR, f"encoders_{self.dataset}.pkl")

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")

        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.feature_names = joblib.load(features_path)
        self.encoders = joblib.load(encoders_path) if os.path.exists(encoders_path) else {}

        logger.info(f"[Detector] Loaded {self.dataset} model ({type(self.model).__name__})")
        logger.info(f"[Detector] Features: {len(self.feature_names)}, Encoders: {list(self.encoders.keys())}")

    # ══════════════════════════════════════════════════════════
    #  Feature Encoding for Real Packets
    # ══════════════════════════════════════════════════════════

    def _encode_features(self, raw_features: dict) -> Optional[np.ndarray]:
        """
        Convert raw flow features dict → scaled numpy array matching model input.
        Handles label encoding of categorical cols (proto, service, state)
        using the SAME encoders from training.
        """
        try:
            # Extract only the 42 ML features (skip _ prefixed metadata)
            row = {}
            for feat in UNSW_FEATURES:
                row[feat] = raw_features.get(feat, 0)

            df = pd.DataFrame([row])

            # Label-encode categorical columns
            for col, le in self.encoders.items():
                if col in df.columns:
                    val = str(df[col].iloc[0])
                    if val in le.classes_:
                        df[col] = le.transform([val])[0]
                    else:
                        # Unseen category → encode as 0 (fallback)
                        df[col] = 0

            # Ensure column order matches training
            df = df[self.feature_names]

            # Scale using the training scaler (pass DataFrame to preserve feature names)
            X = self.scaler.transform(df)
            return X
        except Exception as e:
            logger.warning(f"Feature encoding error: {e}")
            return None

    def _predict(self, X: np.ndarray):
        """Run ML prediction. Returns (prediction, confidence)."""
        pred = self.model.predict(X)[0]
        try:
            proba = self.model.predict_proba(X)[0]
            confidence = float(proba[1])  # P(anomaly)
        except Exception:
            confidence = float(pred)
        return int(pred), confidence

    def _severity_from_confidence(self, confidence: float, is_anomaly: bool) -> str:
        if not is_anomaly:
            return "NONE"
        if confidence > 0.9:
            return "CRITICAL"
        if confidence > 0.75:
            return "HIGH"
        if confidence > 0.5:
            return "MEDIUM"
        return "LOW"

    # ══════════════════════════════════════════════════════════
    #  Real Packet Callback (called by LiveNetworkCapture)
    # ══════════════════════════════════════════════════════════

    def _is_whitelisted(self, features: dict) -> bool:
        """
        Return True for traffic patterns known to be benign that
        the model tends to misclassify (multicast, mDNS, NTP, etc.).
        """
        dst_ip = features.get("_dst_ip", "")
        dst_port = features.get("_dst_port", 0)

        # Multicast / broadcast traffic
        if dst_ip.startswith(self._SAFE_MULTICAST_PREFIXES):
            return True

        # Well-known benign service ports
        if dst_port in self._SAFE_DST_PORTS:
            return True

        return False

    def _on_flow_ready(self, features: dict):
        """
        Called by LiveNetworkCapture when a flow's features are extracted
        from REAL network packets. Runs ML prediction on the flow.
        Low-confidence anomaly predictions are demoted to NORMAL to
        reduce false alerts.
        """
        X = self._encode_features(features)
        if X is None:
            return

        pred, confidence = self._predict(X)

        # ── Whitelist gate: known-benign traffic forced to NORMAL ──
        whitelisted = self._is_whitelisted(features)

        # ── Confidence gate: demote low-confidence anomaly predictions ──
        is_anomaly = (
            pred == 1
            and confidence >= self.ANOMALY_CONFIDENCE_THRESHOLD
            and not whitelisted
        )
        severity = self._severity_from_confidence(confidence, is_anomaly)

        detection = {
            "timestamp": features.get("_timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]),
            "prediction": 1 if is_anomaly else 0,
            "label": "ANOMALY" if is_anomaly else "NORMAL",
            "confidence": round(confidence, 4),
            "severity": severity,
            "actual": None,  # Unknown in live mode
            "packet_id": self.stats["total_packets"] + 1,
            # REAL network metadata from actual packets
            "src_ip": features.get("_src_ip", "?"),
            "dst_ip": features.get("_dst_ip", "?"),
            "src_port": features.get("_src_port", 0),
            "dst_port": features.get("_dst_port", 0),
            "protocol": features.get("_protocol", "?"),
            "service": features.get("service", "-"),
            "state": features.get("state", "?"),
            "flow_packets": features.get("_flow_pkts", 0),
            "flow_bytes": features.get("sbytes", 0) + features.get("dbytes", 0),
            "duration": features.get("dur", 0),
        }

        self._update_stats(detection)
        self._detection_buffer.append(detection)
        self._history.append(detection)

        # Write to SIEM-compatible log files
        self.siem_logger.log_detection(detection)

    # ══════════════════════════════════════════════════════════
    #  Stats & History
    # ══════════════════════════════════════════════════════════

    def _update_stats(self, detection: dict):
        self.stats["total_packets"] += 1
        if detection["prediction"] == 1:
            self.stats["anomaly_count"] += 1
        else:
            self.stats["normal_count"] += 1
        total = self.stats["total_packets"]
        if total > 0:
            self.stats["anomaly_rate"] = round(
                self.stats["anomaly_count"] / total * 100, 2
            )

    def get_stats(self) -> dict:
        uptime = 0
        if self.stats["start_time"]:
            uptime = round(time.time() - self.stats["start_time"], 1)
        if self._capture:
            self.stats["raw_packets"] = self._capture.packet_count
        return {**self.stats, "uptime_sec": uptime, "history_size": len(self._history)}

    def get_recent_history(self, n=50) -> list:
        return list(self._history)[-n:]

    def get_timeline_data(self) -> dict:
        if not self._history:
            return {"timestamps": [], "anomaly_counts": [], "normal_counts": []}
        timeline = defaultdict(lambda: {"anomaly": 0, "normal": 0})
        for d in self._history:
            ts = d["timestamp"][:19]
            if d["prediction"] == 1:
                timeline[ts]["anomaly"] += 1
            else:
                timeline[ts]["normal"] += 1
        timestamps = sorted(timeline.keys())[-30:]
        return {
            "timestamps": timestamps,
            "anomaly_counts": [timeline[t]["anomaly"] for t in timestamps],
            "normal_counts": [timeline[t]["normal"] for t in timestamps],
        }

    def get_severity_distribution(self) -> dict:
        sevs = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
        for d in list(self._history)[-200:]:
            sevs[d.get("severity", "NONE")] += 1
        return sevs

    def drain_buffer(self) -> list:
        """Drain the detection buffer (for live mode WebSocket broadcast)."""
        items = list(self._detection_buffer)
        self._detection_buffer.clear()
        return items

    # ══════════════════════════════════════════════════════════
    #  Start / Stop
    # ══════════════════════════════════════════════════════════

    def start(self):
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy not installed. Cannot capture packets.\n"
                "Install: pip install scapy\n"
                "Run with: sudo ./venv/bin/python main.py serve"
            )
        self.stats["start_time"] = time.time()
        self._running = True

        self._capture = LiveNetworkCapture(interface=self.interface)
        iface = self.interface or LiveNetworkCapture.auto_detect_interface()
        self.stats["interface"] = iface
        self._capture.start(callback=self._on_flow_ready)
        logger.info(f"🔴 LIVE detection started on interface: {iface}")

    def stop(self):
        self._running = False
        if self._capture:
            self._capture.stop()
            self._capture = None
        logger.info("Detection stopped")

    @property
    def is_running(self):
        return self._running

    def detect_once(self, batch_size=5) -> list:
        """Drain the buffer of real-time detections from live capture."""
        return self.drain_buffer()
