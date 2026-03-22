# vm_lab/flow_extractor.py
# Live packet capture → dual feature extraction → real-time IDS alerts.
#
# Captures traffic on a network interface (e.g. vboxnet0),
# groups packets into flows, extracts NSL-KDD + CICIDS features from each flow,
# and POSTs to the /api/predict/dual endpoint.
#
# Requirements:
#   pip install scapy requests
#   Must be run with sudo (packet capture requires root)
#
# Usage:
#   sudo python flow_extractor.py --interface vboxnet0
#   sudo python flow_extractor.py --interface eth1 --api http://localhost:8000
#   sudo python flow_extractor.py --interface vboxnet0 --timeout 30 --verbose

import argparse
import time
import json
import threading
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except ImportError:
    print("[ERROR] scapy not installed. Run: pip install scapy")
    exit(1)

try:
    import requests
except ImportError:
    print("[ERROR] requests not installed. Run: pip install requests")
    exit(1)


# ── Port → NSL-KDD service mapping ───────────────────────────────────────────
# Maps common destination ports to the NSL-KDD 'service' field name.
PORT_TO_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain", 80: "http", 110: "pop_3", 111: "sunrpc",
    113: "auth", 119: "nntp", 143: "imap4", 161: "snmp",
    179: "bgp", 389: "ldap", 443: "http_443", 445: "netbios_ssn",
    512: "exec", 513: "login", 514: "shell", 515: "printer",
    520: "efs", 543: "klogin", 544: "kshell",
    1080: "SOCKs", 2784: "http_2784", 3306: "sql_net",
    5190: "aol", 6000: "X11", 6667: "IRC",
    8001: "http_8001", 8080: "http_8001",
}

# TCP flag string → NSL-KDD 'flag' field
# Derived from the combination of TCP flags seen across the flow
def classify_tcp_flag(syn, fin, rst, ack, flow_complete):
    """Map TCP flag counts to NSL-KDD flag categories."""
    if rst > 0 and syn > 0: return "RSTO"
    if rst > 0:              return "REJ" if not ack else "RSTR"
    if syn > 0 and fin > 0: return "SF"
    if syn > 0 and not fin: return "S0" if not ack else "S1"
    if fin > 0:             return "SF" if flow_complete else "SH"
    return "OTH"


# ── Flow record ───────────────────────────────────────────────────────────────

class Flow:
    """Tracks all packets belonging to a single network flow."""

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip    = src_ip
        self.dst_ip    = dst_ip
        self.src_port  = src_port
        self.dst_port  = dst_port
        self.protocol  = protocol         # "tcp", "udp", "icmp"

        self.start_time   = time.time()
        self.last_seen    = time.time()

        # Packet lists: fwd = src→dst, bwd = dst→src
        self.fwd_packets  = []   # list of (timestamp, payload_len, flags)
        self.bwd_packets  = []

        # TCP flag counters
        self.syn_count = self.fin_count = self.rst_count = 0
        self.ack_count = self.psh_count = self.urg_count = 0

    def add_packet(self, ts, payload_len, is_forward, flags=None):
        self.last_seen = ts
        if is_forward:
            self.fwd_packets.append((ts, payload_len))
        else:
            self.bwd_packets.append((ts, payload_len))

        if flags:
            if flags & 0x02: self.syn_count += 1
            if flags & 0x01: self.fin_count += 1
            if flags & 0x04: self.rst_count += 1
            if flags & 0x10: self.ack_count += 1
            if flags & 0x08: self.psh_count += 1
            if flags & 0x20: self.urg_count += 1

    @property
    def duration_seconds(self):
        return max(self.last_seen - self.start_time, 0)

    @property
    def is_complete(self):
        return self.fin_count > 0 or self.rst_count > 0


# ── Feature extraction ────────────────────────────────────────────────────────

def safe_mean(values):
    return sum(values) / len(values) if values else 0.0

def safe_std(values):
    if len(values) < 2: return 0.0
    m = safe_mean(values)
    return (sum((x - m) ** 2 for x in values) / len(values)) ** 0.5

def inter_arrival_times(packets):
    """Compute list of inter-arrival times from (timestamp, size) list."""
    if len(packets) < 2: return []
    ts = [p[0] for p in packets]
    return [ts[i+1] - ts[i] for i in range(len(ts)-1)]

def flow_to_dual_features(flow: Flow) -> dict:
    """
    Extract a unified feature dict from a completed flow.
    Contains enough fields to satisfy both FeatureAdapter.adapt() calls.
    Missing or uncomputable features default to 0.
    """
    dur_us  = flow.duration_seconds * 1_000_000   # microseconds (CICIDS)
    dur_sec = flow.duration_seconds                # seconds (NSL-KDD)

    fwd_sizes = [p[1] for p in flow.fwd_packets]
    bwd_sizes = [p[1] for p in flow.bwd_packets]
    all_sizes = fwd_sizes + bwd_sizes

    total_fwd_bytes = sum(fwd_sizes)
    total_bwd_bytes = sum(bwd_sizes)
    total_bytes     = total_fwd_bytes + total_bwd_bytes
    total_packets   = len(flow.fwd_packets) + len(flow.bwd_packets)

    bytes_per_sec   = total_bytes   / dur_sec if dur_sec > 0 else 0.0
    packets_per_sec = total_packets / dur_sec if dur_sec > 0 else 0.0

    fwd_iats = inter_arrival_times(flow.fwd_packets)
    bwd_iats = inter_arrival_times(flow.bwd_packets)
    all_iats = inter_arrival_times(
        sorted(flow.fwd_packets + flow.bwd_packets, key=lambda p: p[0])
    )

    service   = PORT_TO_SERVICE.get(flow.dst_port, "other")
    tcp_flag  = classify_tcp_flag(
        flow.syn_count, flow.fin_count, flow.rst_count,
        flow.ack_count, flow.is_complete
    )
    serr_rate = 1.0 if (flow.syn_count > 0 and flow.ack_count == 0) else 0.0
    rerr_rate = 1.0 if (flow.rst_count > 0) else 0.0

    return {
        # ── NSL-KDD features ──────────────────────────────────────────────
        "duration":                    int(dur_sec),
        "protocol_type":               flow.protocol,
        "service":                     service,
        "flag":                        tcp_flag,
        "src_bytes":                   total_fwd_bytes,
        "dst_bytes":                   total_bwd_bytes,
        "land":                        1 if flow.src_ip == flow.dst_ip else 0,
        "wrong_fragment":              0,
        "urgent":                      flow.urg_count,
        "hot":                         0,
        "num_failed_logins":           0,
        "logged_in":                   1 if flow.ack_count > 3 else 0,
        "num_compromised":             0,
        "root_shell":                  0,
        "su_attempted":                0,
        "num_root":                    0,
        "num_file_creations":          0,
        "num_shells":                  0,
        "num_access_files":            0,
        "num_outbound_cmds":           0,
        "is_host_login":               0,
        "is_guest_login":              0,
        "count":                       total_packets,
        "srv_count":                   len(flow.fwd_packets),
        "serror_rate":                 serr_rate,
        "srv_serror_rate":             serr_rate,
        "rerror_rate":                 rerr_rate,
        "srv_rerror_rate":             rerr_rate,
        "same_srv_rate":               1.0 if len(fwd_sizes) > 0 else 0.0,
        "diff_srv_rate":               0.0,
        "srv_diff_host_rate":          0.0,
        "dst_host_count":              min(total_packets, 255),
        "dst_host_srv_count":          min(len(flow.fwd_packets), 255),
        "dst_host_same_srv_rate":      1.0,
        "dst_host_diff_srv_rate":      0.0,
        "dst_host_same_src_port_rate": 1.0 if flow.src_port < 1024 else 0.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate":        serr_rate,
        "dst_host_srv_serror_rate":    serr_rate,
        "dst_host_rerror_rate":        rerr_rate,
        "dst_host_srv_rerror_rate":    rerr_rate,

        # ── CICIDS features ───────────────────────────────────────────────
        "Destination Port":            flow.dst_port,
        "Flow Duration":               int(dur_us),
        "Total Fwd Packets":           len(flow.fwd_packets),
        "Total Backward Packets":      len(flow.bwd_packets),
        "Total Length of Fwd Packets": total_fwd_bytes,
        "Total Length of Bwd Packets": total_bwd_bytes,
        "Fwd Packet Length Max":       max(fwd_sizes) if fwd_sizes else 0,
        "Fwd Packet Length Min":       min(fwd_sizes) if fwd_sizes else 0,
        "Fwd Packet Length Mean":      safe_mean(fwd_sizes),
        "Fwd Packet Length Std":       safe_std(fwd_sizes),
        "Bwd Packet Length Max":       max(bwd_sizes) if bwd_sizes else 0,
        "Bwd Packet Length Min":       min(bwd_sizes) if bwd_sizes else 0,
        "Bwd Packet Length Mean":      safe_mean(bwd_sizes),
        "Bwd Packet Length Std":       safe_std(bwd_sizes),
        "Flow Bytes/s":                bytes_per_sec,
        "Flow Packets/s":              packets_per_sec,
        "Flow IAT Mean":               safe_mean(all_iats),
        "Flow IAT Std":                safe_std(all_iats),
        "Flow IAT Max":                max(all_iats) if all_iats else 0,
        "Flow IAT Min":                min(all_iats) if all_iats else 0,
        "Fwd IAT Total":               sum(fwd_iats),
        "Fwd IAT Mean":                safe_mean(fwd_iats),
        "Fwd IAT Std":                 safe_std(fwd_iats),
        "Fwd IAT Max":                 max(fwd_iats) if fwd_iats else 0,
        "Fwd IAT Min":                 min(fwd_iats) if fwd_iats else 0,
        "Bwd IAT Total":               sum(bwd_iats),
        "Bwd IAT Mean":                safe_mean(bwd_iats),
        "Bwd IAT Std":                 safe_std(bwd_iats),
        "Bwd IAT Max":                 max(bwd_iats) if bwd_iats else 0,
        "Bwd IAT Min":                 min(bwd_iats) if bwd_iats else 0,
        "Fwd PSH Flags":               flow.psh_count if flow.protocol == "tcp" else 0,
        "Bwd PSH Flags":               0,
        "Fwd URG Flags":               flow.urg_count,
        "Bwd URG Flags":               0,
        "Fwd Header Length":           len(flow.fwd_packets) * 20,  # approx TCP header
        "Bwd Header Length":           len(flow.bwd_packets) * 20,
        "Fwd Packets/s":               len(flow.fwd_packets) / dur_sec if dur_sec > 0 else 0,
        "Bwd Packets/s":               len(flow.bwd_packets) / dur_sec if dur_sec > 0 else 0,
        "Min Packet Length":           min(all_sizes) if all_sizes else 0,
        "Max Packet Length":           max(all_sizes) if all_sizes else 0,
        "Packet Length Mean":          safe_mean(all_sizes),
        "Packet Length Std":           safe_std(all_sizes),
        "Packet Length Variance":      safe_std(all_sizes) ** 2,
        "FIN Flag Count":              flow.fin_count,
        "SYN Flag Count":              flow.syn_count,
        "RST Flag Count":              flow.rst_count,
        "PSH Flag Count":              flow.psh_count,
        "ACK Flag Count":              flow.ack_count,
        "URG Flag Count":              flow.urg_count,
        "CWE Flag Count":              0,
        "ECE Flag Count":              0,
        "Down/Up Ratio":               total_bwd_bytes / total_fwd_bytes if total_fwd_bytes > 0 else 0,
        "Average Packet Size":         safe_mean(all_sizes),
        "Avg Fwd Segment Size":        safe_mean(fwd_sizes),
        "Avg Bwd Segment Size":        safe_mean(bwd_sizes),
        "Fwd Avg Bytes/Bulk":          0,
        "Fwd Avg Packets/Bulk":        0,
        "Fwd Avg Bulk Rate":           0,
        "Bwd Avg Bytes/Bulk":          0,
        "Bwd Avg Packets/Bulk":        0,
        "Bwd Avg Bulk Rate":           0,
        "Subflow Fwd Packets":         len(flow.fwd_packets),
        "Subflow Fwd Bytes":           total_fwd_bytes,
        "Subflow Bwd Packets":         len(flow.bwd_packets),
        "Subflow Bwd Bytes":           total_bwd_bytes,
        "Init_Win_bytes_forward":      0,
        "Init_Win_bytes_backward":     0,
        "act_data_pkt_fwd":            sum(1 for s in fwd_sizes if s > 0),
        "min_seg_size_forward":        min(fwd_sizes) if fwd_sizes else 0,
        "Active Mean":                 dur_us,
        "Active Std":                  0,
        "Active Max":                  dur_us,
        "Active Min":                  dur_us,
        "Idle Mean":                   0,
        "Idle Std":                    0,
        "Idle Max":                    0,
        "Idle Min":                    0,
    }


# ── Flow tracker ──────────────────────────────────────────────────────────────

class FlowTracker:
    """
    Maintains a table of active flows.
    A flow is keyed by (src_ip, dst_ip, src_port, dst_port, protocol).
    Flows are exported when:
      - A FIN or RST is seen (clean teardown)
      - They exceed the idle timeout (5 seconds of no packets)
    """

    IDLE_TIMEOUT = 5.0   # seconds

    def __init__(self, on_flow_complete):
        self.flows             = {}
        self.on_flow_complete  = on_flow_complete
        self.lock              = threading.Lock()

    def _flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """Canonical key: always put lower IP first so fwd/bwd are consistent."""
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        return (dst_ip, src_ip, dst_port, src_port, protocol)

    def process_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ts     = time.time()

        if pkt.haslayer(TCP):
            protocol = "tcp"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags    = pkt[TCP].flags
            payload  = len(pkt[TCP].payload)
        elif pkt.haslayer(UDP):
            protocol = "udp"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            flags    = None
            payload  = len(pkt[UDP].payload)
        elif pkt.haslayer(ICMP):
            protocol = "icmp"
            src_port = dst_port = 0
            flags    = None
            payload  = len(pkt[ICMP].payload)
        else:
            return

        key        = self._flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
        is_forward = (src_ip, src_port) <= (dst_ip, dst_port)

        with self.lock:
            if key not in self.flows:
                self.flows[key] = Flow(
                    key[0], key[1], key[2], key[3], protocol
                )

            flow = self.flows[key]
            flow.add_packet(ts, payload, is_forward, flags)

            # Export on clean teardown
            if flags and (flags & 0x01 or flags & 0x04):   # FIN or RST
                self._export(key)

    def _export(self, key):
        """Export a flow and remove it from the active table."""
        flow = self.flows.pop(key, None)
        if flow and len(flow.fwd_packets) + len(flow.bwd_packets) >= 2:
            self.on_flow_complete(flow)

    def expire_idle_flows(self):
        """Periodically called to export flows that have been idle too long."""
        now = time.time()
        with self.lock:
            expired = [k for k, f in self.flows.items()
                       if now - f.last_seen > self.IDLE_TIMEOUT]
            for key in expired:
                self._export(key)


# ── API poster ────────────────────────────────────────────────────────────────

def post_to_api(features: dict, api_url: str, verbose: bool) -> dict:
    """POST a feature dict to /api/predict/dual and return the result."""
    try:
        res = requests.post(
            f"{api_url}/api/predict/dual",
            json={"features": features},
            timeout=5,
        )
        res.raise_for_status()
        return res.json()
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Cannot connect to API at {api_url}. Is the backend running?")
        return {}
    except Exception as e:
        if verbose:
            print(f"[WARN] API error: {e}")
        return {}


# ── Main ──────────────────────────────────────────────────────────────────────

def print_alert(flow: Flow, result: dict):
    """Print a formatted alert line to the terminal."""
    level = result.get("risk_level", "?")
    score = result.get("risk_score", 0)
    nsl_r = result.get("nslkdd_rf_prediction", "?")
    nsl_i = result.get("nslkdd_if_prediction", "?")
    cic_r = result.get("cicids_rf_prediction",  "?")
    cic_i = result.get("cicids_if_prediction",  "?")
    ts    = datetime.now().strftime("%H:%M:%S")

    level_color = {
        "Low": "\033[92m", "Medium": "\033[93m",
        "High": "\033[91m", "Critical": "\033[91;1m",
    }.get(level, "")
    reset = "\033[0m"

    print(
        f"[{ts}] {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port} "
        f"({flow.protocol.upper()}) | "
        f"{level_color}[{level:8s}] Risk:{score:5.1f}{reset} | "
        f"NSL RF:{nsl_r} IF:{nsl_i}  CIC RF:{cic_r} IF:{cic_i}"
    )


def run(interface: str, api_url: str, flow_timeout: int, verbose: bool):
    print(f"[FlowExtractor] Sniffing on '{interface}' → {api_url}/api/predict/dual")
    print(f"[FlowExtractor] Flow idle timeout: {FlowTracker.IDLE_TIMEOUT}s")
    print(f"[FlowExtractor] Press Ctrl+C to stop\n")

    def on_flow_complete(flow: Flow):
        features = flow_to_dual_features(flow)
        result   = post_to_api(features, api_url, verbose)
        if result:
            print_alert(flow, result)

    tracker = FlowTracker(on_flow_complete)

    # Background thread to expire idle flows
    def expire_loop():
        while True:
            time.sleep(2)
            tracker.expire_idle_flows()

    t = threading.Thread(target=expire_loop, daemon=True)
    t.start()

    # Start packet capture (blocking)
    sniff(iface=interface, prn=tracker.process_packet, store=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XAI-IDS Live Flow Extractor")
    parser.add_argument("--interface", default="vboxnet0",
                        help="Network interface to sniff (default: vboxnet0)")
    parser.add_argument("--api",       default="http://localhost:8000",
                        help="Backend API URL (default: http://localhost:8000)")
    parser.add_argument("--timeout",   type=int, default=5,
                        help="Flow idle timeout in seconds (default: 5)")
    parser.add_argument("--verbose",   action="store_true",
                        help="Print API errors and debug info")
    args = parser.parse_args()

    FlowTracker.IDLE_TIMEOUT = args.timeout
    run(args.interface, args.api, args.timeout, args.verbose)