"""
Real Network Packet Capture & Flow-Based Feature Extraction.

Captures ACTUAL packets from a real network interface using Scapy,
groups them into flows, and extracts the exact 42 features that
the UNSW-NB15 trained model expects.

Requires:
  - sudo / root privileges for raw packet capture
  - scapy, psutil
"""

import time
import threading
import logging
from collections import defaultdict
from datetime import datetime
from typing import Optional, Callable, Dict, List

import numpy as np

logger = logging.getLogger(__name__)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available — live capture disabled")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════
#  Well-known port → service mapping (matches UNSW-NB15 labels)
# ═══════════════════════════════════════════════════════════════
PORT_TO_SERVICE = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 80: "http",
    110: "pop3", 143: "imap", 443: "ssl", 993: "ssl",
    995: "ssl", 587: "smtp", 465: "smtp", 6667: "irc",
    6697: "irc", 161: "snmp", 162: "snmp", 1812: "radius",
    1813: "radius", 8080: "http", 8443: "ssl", 3389: "http",
}

# Protocol number → name
PROTO_NUM_TO_NAME = {
    1: "icmp", 6: "tcp", 17: "udp", 2: "igmp",
    47: "gre", 50: "esp", 51: "ah", 58: "ipv6-icmp",
    89: "ospf", 132: "sctp",
}


def detect_service(src_port: int, dst_port: int) -> str:
    """Detect application-layer service from port numbers."""
    if dst_port in PORT_TO_SERVICE:
        return PORT_TO_SERVICE[dst_port]
    if src_port in PORT_TO_SERVICE:
        return PORT_TO_SERVICE[src_port]
    return "-"


def detect_state(flags_history: Dict[str, int], is_tcp: bool) -> str:
    """Infer connection state from TCP flags seen."""
    if not is_tcp:
        return "INT"  # Internal / non-TCP

    syn = flags_history.get("SYN", 0)
    ack = flags_history.get("ACK", 0)
    fin = flags_history.get("FIN", 0)
    rst = flags_history.get("RST", 0)

    if rst > 0:
        return "RST"
    if fin > 0 and ack > 0:
        return "FIN"
    if syn > 0 and ack > 0 and fin == 0:
        return "CON"  # Connected / established
    if syn > 0 and ack == 0:
        return "REQ"  # SYN sent, no response yet
    if ack > 0:
        return "ACC"  # ACK only
    return "INT"


# ═══════════════════════════════════════════════════════════════
#  Flow Tracker — groups packets into bidirectional flows
# ═══════════════════════════════════════════════════════════════

class FlowTracker:
    """
    Accumulates packets into bidirectional flows and extracts
    the 42 features matching the UNSW-NB15 training schema.
    """

    def __init__(self, flow_timeout: float = 15.0, min_packets: int = 5):
        self.flows: Dict[tuple, dict] = {}
        self.flow_timeout = flow_timeout
        self.min_packets = min_packets

        # Connection-tracking counters (ct_* features)
        self._ct_srv_src = defaultdict(int)
        self._ct_dst_ltm = defaultdict(int)
        self._ct_src_dport = defaultdict(int)
        self._ct_dst_sport = defaultdict(int)
        self._ct_dst_src = defaultdict(int)
        self._ct_src_ltm = defaultdict(int)
        self._ct_srv_dst = defaultdict(int)
        self._ct_state_ttl = defaultdict(int)

    def _flow_key(self, pkt):
        """Bidirectional flow key from packet."""
        if IP not in pkt:
            return None
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        src_port = dst_port = 0
        if TCP in pkt:
            src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport
        fwd = (src_ip, dst_ip, src_port, dst_port, proto)
        rev = (dst_ip, src_ip, dst_port, src_port, proto)
        return min(fwd, rev)

    def process_packet(self, pkt) -> Optional[dict]:
        """
        Feed a packet into flow tracking.
        Returns feature dict when a flow is complete, else None.
        """
        if IP not in pkt:
            return None
        key = self._flow_key(pkt)
        if key is None:
            return None

        now = time.time()
        pkt_len = len(pkt)
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ttl = pkt[IP].ttl

        # ── Create new flow ──
        if key not in self.flows:
            self.flows[key] = {
                "start": now,
                "last": now,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": key[2],
                "dst_port": key[3],
                "proto_num": key[4],
                "fwd_pkts": 0,
                "bwd_pkts": 0,
                "fwd_bytes": [],
                "bwd_bytes": [],
                "fwd_iat": [],
                "bwd_iat": [],
                "last_fwd": now,
                "last_bwd": now,
                "flags": defaultdict(int),
                "sttl": ttl,
                "dttl": ttl,
                "syn_time": None,
                "synack_time": None,
                "ack_time": None,
                "total_pkts": 0,
                "http_methods": 0,
                "swin": 0,       # source TCP window
                "dwin": 0,       # destination TCP window
                "stcpb": 0,      # source TCP base sequence number
                "dtcpb": 0,      # destination TCP base sequence number
            }

        flow = self.flows[key]
        flow["last"] = now
        flow["total_pkts"] += 1
        is_forward = (src_ip == flow["src_ip"])

        if is_forward:
            flow["fwd_pkts"] += 1
            flow["fwd_bytes"].append(pkt_len)
            flow["sttl"] = ttl
            if flow["fwd_pkts"] > 1:
                flow["fwd_iat"].append(now - flow["last_fwd"])
            flow["last_fwd"] = now
        else:
            flow["bwd_pkts"] += 1
            flow["bwd_bytes"].append(pkt_len)
            flow["dttl"] = ttl
            if flow["bwd_pkts"] > 1:
                flow["bwd_iat"].append(now - flow["last_bwd"])
            flow["last_bwd"] = now

        # TCP flags + window + sequence numbers
        if TCP in pkt:
            flags = pkt[TCP].flags
            tcp_win = pkt[TCP].window
            tcp_seq = pkt[TCP].seq

            # Track TCP window sizes per direction
            if is_forward:
                flow["swin"] = tcp_win
                if flow["stcpb"] == 0:
                    flow["stcpb"] = tcp_seq  # base sequence number
            else:
                flow["dwin"] = tcp_win
                if flow["dtcpb"] == 0:
                    flow["dtcpb"] = tcp_seq

            if flags & 0x02:
                flow["flags"]["SYN"] += 1
                if flow["syn_time"] is None:
                    flow["syn_time"] = now
            if flags & 0x12 == 0x12:  # SYN+ACK
                flow["synack_time"] = now
            if flags & 0x10:
                flow["flags"]["ACK"] += 1
                if flow["ack_time"] is None:
                    flow["ack_time"] = now
            if flags & 0x01: flow["flags"]["FIN"] += 1
            if flags & 0x04: flow["flags"]["RST"] += 1
            if flags & 0x08: flow["flags"]["PSH"] += 1
            if flags & 0x20: flow["flags"]["URG"] += 1

        # ── Emit flow when ready ──
        duration = now - flow["start"]
        is_finished = (
            flow["flags"].get("FIN", 0) >= 2 or
            flow["flags"].get("RST", 0) > 0
        )
        is_timeout = duration > self.flow_timeout
        has_enough = flow["total_pkts"] >= self.min_packets and duration >= 1.0

        if is_finished or is_timeout or has_enough:
            features = self._extract_features(key, flow)
            del self.flows[key]
            return features

        return None

    def flush_expired(self) -> List[dict]:
        """Flush all flows that have timed out. Returns list of feature dicts."""
        now = time.time()
        expired_keys = [
            k for k, v in self.flows.items()
            if (now - v["last"]) > self.flow_timeout
        ]
        results = []
        for k in expired_keys:
            feat = self._extract_features(k, self.flows[k])
            del self.flows[k]
            results.append(feat)
        return results

    def _safe_std(self, arr):
        return float(np.std(arr)) if len(arr) > 1 else 0.0

    def _safe_mean(self, arr):
        return float(np.mean(arr)) if arr else 0.0

    def _extract_features(self, key, flow) -> dict:
        """
        Extract the exact 42 features the UNSW-NB15 model expects.
        Also returns metadata prefixed with _ for display purposes.
        """
        duration = max(flow["last"] - flow["start"], 0.0001)

        fwd_b = flow["fwd_bytes"] or [0]
        bwd_b = flow["bwd_bytes"] or [0]
        fwd_iat = flow["fwd_iat"] or [0]
        bwd_iat = flow["bwd_iat"] or [0]
        all_iat = fwd_iat + bwd_iat

        total_fwd = sum(fwd_b)
        total_bwd = sum(bwd_b)

        is_tcp = (flow["proto_num"] == 6)
        proto_name = PROTO_NUM_TO_NAME.get(flow["proto_num"], str(flow["proto_num"]))
        service = detect_service(flow["src_port"], flow["dst_port"])
        state = detect_state(flow["flags"], is_tcp)

        # SYN→ACK and ACK→data timings
        synack_time = 0.0
        if flow["syn_time"] and flow["synack_time"]:
            synack_time = flow["synack_time"] - flow["syn_time"]
        ackdat_time = 0.0
        if flow["synack_time"] and flow["ack_time"]:
            ackdat_time = flow["ack_time"] - flow["synack_time"]

        # TCP RTT = synack + ackdat (round-trip from handshake)
        tcprtt = synack_time + ackdat_time

        # Connection tracking
        src = flow["src_ip"]
        dst = flow["dst_ip"]
        self._ct_srv_src[(service, src)] += 1
        self._ct_dst_ltm[dst] += 1
        self._ct_src_dport[(src, flow["dst_port"])] += 1
        self._ct_dst_sport[(dst, flow["src_port"])] += 1
        self._ct_dst_src[(dst, src)] += 1
        self._ct_src_ltm[src] += 1
        self._ct_srv_dst[(service, dst)] += 1
        self._ct_state_ttl[(state, flow["sttl"])] += 1

        return {
            # ── Display metadata (stripped before ML) ──
            "_src_ip": flow["src_ip"],
            "_dst_ip": flow["dst_ip"],
            "_src_port": flow["src_port"],
            "_dst_port": flow["dst_port"],
            "_protocol": proto_name.upper(),
            "_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "_flow_pkts": flow["total_pkts"],

            # ── The 42 ML features (order matters!) ──
            "dur": round(duration, 6),
            "proto": proto_name,
            "service": service,
            "state": state,
            "spkts": flow["fwd_pkts"],
            "dpkts": flow["bwd_pkts"],
            "sbytes": total_fwd,
            "dbytes": total_bwd,
            "rate": round(flow["total_pkts"] / duration, 4),
            "sttl": flow["sttl"],
            "dttl": flow["dttl"],
            "sload": round((total_fwd * 8) / duration, 4),
            "dload": round((total_bwd * 8) / duration, 4),
            "sloss": max(0, flow["fwd_pkts"] - flow["bwd_pkts"]),
            "dloss": max(0, flow["bwd_pkts"] - flow["fwd_pkts"]),
            "sinpkt": round(self._safe_mean(fwd_iat) * 1000, 4),  # ms
            "dinpkt": round(self._safe_mean(bwd_iat) * 1000, 4),
            "sjit": round(self._safe_std(fwd_iat) * 1000, 4),
            "djit": round(self._safe_std(bwd_iat) * 1000, 4),
            "swin": flow["swin"],
            "stcpb": flow["stcpb"],
            "dtcpb": flow["dtcpb"],
            "dwin": flow["dwin"],
            "tcprtt": round(tcprtt, 6),
            "synack": round(synack_time, 6),
            "ackdat": round(ackdat_time, 6),
            "smean": round(self._safe_mean(fwd_b), 2),
            "dmean": round(self._safe_mean(bwd_b), 2),
            "trans_depth": flow["http_methods"],  # 0 for non-HTTP flows
            "response_body_len": total_bwd,
            "ct_srv_src": self._ct_srv_src.get((service, src), 1),
            "ct_state_ttl": self._ct_state_ttl.get((state, flow["sttl"]), 1),
            "ct_dst_ltm": self._ct_dst_ltm.get(dst, 1),
            "ct_src_dport_ltm": self._ct_src_dport.get((src, flow["dst_port"]), 1),
            "ct_dst_sport_ltm": self._ct_dst_sport.get((dst, flow["src_port"]), 1),
            "ct_dst_src_ltm": self._ct_dst_src.get((dst, src), 1),
            "is_ftp_login": 1 if service in ("ftp", "ftp-data") else 0,
            "ct_ftp_cmd": 1 if service in ("ftp", "ftp-data") else 0,
            "ct_flw_http_mthd": flow["http_methods"],
            "ct_src_ltm": self._ct_src_ltm.get(src, 1),
            "ct_srv_dst": self._ct_srv_dst.get((service, dst), 1),
            "is_sm_ips_ports": 1 if (src == dst and flow["src_port"] == flow["dst_port"]) else 0,
        }


# ═══════════════════════════════════════════════════════════════
#  Live Network Capture Engine
# ═══════════════════════════════════════════════════════════════

class LiveNetworkCapture:
    """
    Captures real packets from an actual network interface.
    Extracts flow features and fires a callback for ML prediction.
    """

    def __init__(self, interface: str = None):
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is required for live capture.\n"
                "Install: pip install scapy\n"
                "Run with: sudo python main.py serve --mode live"
            )
        self.interface = interface
        self.flow_tracker = FlowTracker()
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._flush_thread: Optional[threading.Thread] = None
        self._callback: Optional[Callable] = None
        self._packet_count = 0

    @staticmethod
    def list_interfaces() -> list:
        """List available network interfaces with IPs."""
        interfaces = []
        if PSUTIL_AVAILABLE:
            stats = psutil.net_if_stats()
            for name, addrs in psutil.net_if_addrs().items():
                ips = [a.address for a in addrs if a.family.name == "AF_INET"]
                is_up = stats.get(name, None)
                interfaces.append({
                    "name": name,
                    "ips": ips,
                    "is_up": is_up.isup if is_up else False,
                    "is_loopback": name == "lo",
                })
        return interfaces

    @staticmethod
    def auto_detect_interface() -> str:
        """Find the best active non-loopback interface."""
        if PSUTIL_AVAILABLE:
            stats = psutil.net_if_stats()
            for name, addrs in psutil.net_if_addrs().items():
                if name == "lo":
                    continue
                if not stats.get(name, None) or not stats[name].isup:
                    continue
                for addr in addrs:
                    if addr.family.name == "AF_INET" and not addr.address.startswith("127."):
                        return name
        return conf.iface if SCAPY_AVAILABLE else "eth0"

    def start(self, callback: Callable):
        """Start packet capture. callback(features_dict) for each flow."""
        if self.is_running:
            return
        self._callback = callback
        self.is_running = True
        iface = self.interface or self.auto_detect_interface()
        logger.info(f"🔴 LIVE CAPTURE starting on interface: {iface}")

        self._thread = threading.Thread(
            target=self._capture_loop, args=(iface,), daemon=True
        )
        self._thread.start()

        # Periodic flush of timed-out flows
        self._flush_thread = threading.Thread(
            target=self._flush_loop, daemon=True
        )
        self._flush_thread.start()

    def _capture_loop(self, iface: str):
        try:
            sniff(
                iface=iface,
                prn=self._on_packet,
                stop_filter=lambda _: not self.is_running,
                store=False,
            )
        except PermissionError:
            logger.error(
                "❌ Permission denied! Live capture needs root.\n"
                "   Run: sudo /path/to/venv/bin/python main.py serve --mode live"
            )
            self.is_running = False
        except Exception as e:
            logger.error(f"Capture error: {e}")
            self.is_running = False

    def _on_packet(self, pkt):
        self._packet_count += 1
        features = self.flow_tracker.process_packet(pkt)
        if features and self._callback:
            self._callback(features)

    def _flush_loop(self):
        """Periodically flush expired flows."""
        while self.is_running:
            time.sleep(5)
            for feat in self.flow_tracker.flush_expired():
                if self._callback:
                    self._callback(feat)

    def stop(self):
        self.is_running = False
        logger.info("Live capture stopped")

    @property
    def packet_count(self):
        return self._packet_count
