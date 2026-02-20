"""
SIEM-Compatible Security Event Logger.

Writes structured JSON logs that are natively ingestible by:
  • Splunk  (JSON source type / HEC)
  • Elastic SIEM / Logstash
  • IBM QRadar (JSON log source)
  • ArcSight / any CEF-capable SIEM

Each log line is a **single JSON object** (one event per line = NDJSON),
which is the format Splunk's `_json` source type expects.

Log files:
  logs/anomaly_detections.json   – all detection events (NDJSON)
  logs/anomaly_alerts.json       – anomaly-only events for alert pipelines

Rotation: 10 MB per file, keeps 20 backups (≈200 MB max).
"""

import os
import json
import logging
import socket
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Optional

# ─── Resolve project paths ────────────────────────────────────
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.config import LOGS_DIR


# ═══════════════════════════════════════════════════════════════
#  SIEM JSON Formatter
# ═══════════════════════════════════════════════════════════════

class SIEMJsonFormatter(logging.Formatter):
    """
    Formats log records as flat JSON objects with SIEM-standard field names.
    Follows Common Information Model (CIM) naming used by Splunk.
    """

    HOSTNAME = socket.gethostname()

    def format(self, record: logging.LogRecord) -> str:
        # The detection dict is passed via record.msg
        event: dict = record.msg if isinstance(record.msg, dict) else {}

        # ── Build SIEM-compatible event ──
        log_entry = {
            # === Splunk CIM / Standard fields ===
            "time": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "_time": datetime.now(timezone.utc).isoformat(),
            "host": self.HOSTNAME,
            "source": "NetworkAnomalyDetection",
            "sourcetype": "nads:detection",
            "index": "network_security",

            # === Event classification ===
            "event_id": event.get("packet_id", 0),
            "event_type": "anomaly_detection",
            "action": event.get("label", "UNKNOWN"),
            "severity": event.get("severity", "NONE"),
            "severity_id": self._severity_to_id(event.get("severity", "NONE")),

            # === ML prediction ===
            "prediction": event.get("prediction", 0),
            "confidence": event.get("confidence", 0.0),
            "model_label": event.get("label", "UNKNOWN"),

            # === Network fields (Splunk CIM: Network Traffic) ===
            "src_ip": event.get("src_ip", "0.0.0.0"),
            "src_port": event.get("src_port", 0),
            "dest_ip": event.get("dst_ip", "0.0.0.0"),
            "dest_port": event.get("dst_port", 0),
            "transport": event.get("protocol", "unknown"),
            "app": event.get("service", "-"),
            "connection_state": event.get("state", "unknown"),

            # === Flow metadata ===
            "flow_packets": event.get("flow_packets", 0),
            "flow_bytes": event.get("flow_bytes", 0),
            "flow_duration": event.get("duration", 0),

            # === MITRE ATT&CK compatible tags ===
            "category": ["network", "intrusion_detection"],
            "type": ["connection", "anomaly"] if event.get("prediction") == 1 else ["connection", "allowed"],
        }

        return json.dumps(log_entry, default=str)

    @staticmethod
    def _severity_to_id(severity: str) -> int:
        """Map severity string to numeric ID (Splunk CIM compatible)."""
        return {
            "CRITICAL": 10,
            "HIGH": 8,
            "MEDIUM": 5,
            "LOW": 3,
            "NONE": 1,
        }.get(severity, 0)


# ═══════════════════════════════════════════════════════════════
#  CEF (Common Event Format) Formatter — ArcSight / QRadar
# ═══════════════════════════════════════════════════════════════

class CEFFormatter(logging.Formatter):
    """
    Formats events in CEF (Common Event Format) for ArcSight, QRadar, etc.
    CEF: Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """

    def format(self, record: logging.LogRecord) -> str:
        event: dict = record.msg if isinstance(record.msg, dict) else {}

        severity = self._cef_severity(event.get("severity", "NONE"))
        sig_id = "ANOMALY" if event.get("prediction") == 1 else "NORMAL"
        name = f"Network {event.get('label', 'UNKNOWN')} Detected"

        extensions = (
            f"src={event.get('src_ip', '0.0.0.0')} "
            f"spt={event.get('src_port', 0)} "
            f"dst={event.get('dst_ip', '0.0.0.0')} "
            f"dpt={event.get('dst_port', 0)} "
            f"proto={event.get('protocol', 'unknown')} "
            f"app={event.get('service', '-')} "
            f"cn1={event.get('confidence', 0.0)} cn1Label=Confidence "
            f"cn2={event.get('flow_packets', 0)} cn2Label=FlowPackets "
            f"cn3={event.get('flow_bytes', 0)} cn3Label=FlowBytes "
            f"cs1={event.get('state', 'unknown')} cs1Label=ConnectionState "
            f"rt={event.get('timestamp', '')}"
        )

        return (
            f"CEF:0|NADS|NetworkAnomalyDetection|1.0|{sig_id}|"
            f"{name}|{severity}|{extensions}"
        )

    @staticmethod
    def _cef_severity(severity: str) -> int:
        """CEF severity: 0-3 Low, 4-6 Medium, 7-8 High, 9-10 Critical."""
        return {
            "CRITICAL": 10,
            "HIGH": 8,
            "MEDIUM": 5,
            "LOW": 3,
            "NONE": 0,
        }.get(severity, 0)


# ═══════════════════════════════════════════════════════════════
#  Logger Factory
# ═══════════════════════════════════════════════════════════════

class SIEMLogger:
    """
    Central SIEM-compatible logger for the anomaly detection system.
    Writes to rotating log files in JSON (Splunk) and CEF formats.
    """

    def __init__(self, log_dir: str = None):
        self.log_dir = log_dir or LOGS_DIR
        os.makedirs(self.log_dir, exist_ok=True)

        # ── All detections (JSON / Splunk format) ──
        self._all_logger = self._create_logger(
            name="nads.detections",
            filename="anomaly_detections.json",
            formatter=SIEMJsonFormatter(),
        )

        # ── Anomaly-only alerts (JSON / Splunk format) ──
        self._alert_logger = self._create_logger(
            name="nads.alerts",
            filename="anomaly_alerts.json",
            formatter=SIEMJsonFormatter(),
        )

        # ── CEF format (ArcSight / QRadar) ──
        self._cef_logger = self._create_logger(
            name="nads.cef",
            filename="anomaly_detections.cef",
            formatter=CEFFormatter(),
        )

        self._event_count = 0
        self._alert_count = 0

    def _create_logger(
        self, name: str, filename: str, formatter: logging.Formatter
    ) -> logging.Logger:
        """Create a dedicated rotating file logger."""
        filepath = os.path.join(self.log_dir, filename)

        handler = RotatingFileHandler(
            filepath,
            maxBytes=10 * 1024 * 1024,  # 10 MB per file
            backupCount=20,             # keep 20 rotations (≈200 MB)
            encoding="utf-8",
        )
        handler.setFormatter(formatter)

        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        # Prevent duplicate handlers on re-init
        logger.handlers = [handler]
        logger.propagate = False

        return logger

    def log_detection(self, detection: dict):
        """
        Log a single detection event.
        - Always writes to anomaly_detections.json (all events)
        - Always writes to anomaly_detections.cef (all events, CEF format)
        - Only writes to anomaly_alerts.json if it's an actual anomaly
        """
        self._event_count += 1
        self._all_logger.info(detection)
        self._cef_logger.info(detection)

        # Only anomalies go to the alerts log
        if detection.get("prediction") == 1:
            self._alert_count += 1
            self._alert_logger.info(detection)

    @property
    def stats(self) -> dict:
        return {
            "total_logged": self._event_count,
            "alerts_logged": self._alert_count,
            "log_dir": self.log_dir,
            "log_files": {
                "all_detections": os.path.join(self.log_dir, "anomaly_detections.json"),
                "alerts_only": os.path.join(self.log_dir, "anomaly_alerts.json"),
                "cef_format": os.path.join(self.log_dir, "anomaly_detections.cef"),
            },
        }

    def get_recent_logs(self, n: int = 100, alerts_only: bool = False) -> list:
        """Read the last N log entries from the JSON log file."""
        filename = "anomaly_alerts.json" if alerts_only else "anomaly_detections.json"
        filepath = os.path.join(self.log_dir, filename)

        if not os.path.exists(filepath):
            return []

        lines = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                # Read all lines and return the last N
                all_lines = f.readlines()
                for line in all_lines[-n:]:
                    line = line.strip()
                    if line:
                        lines.append(json.loads(line))
        except Exception:
            pass

        return lines
