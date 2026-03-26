# vm_lab/flow_extractor.py
# Live packet capture → aggregate flow features → dual model prediction.
#
# Key design: flows are grouped by (src_ip, dst_ip) pair.
# When a burst goes idle (no new flows for 3s), ALL flows in the burst
# are aggregated into one NSL-KDD-style feature vector before posting.
# This gives correct count, serror_rate, diff_srv_rate etc.
#
# Requirements:  pip install scapy requests
# Windows:       must run as Administrator + Npcap installed
#
# Usage:
#   Windows:  python vm_lab/flow_extractor.py --interface "\Device\NPF_{guid}"
#   Linux:    sudo python vm_lab/flow_extractor.py --interface vboxnet0

import argparse
import time
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


# ── Port → NSL-KDD service name ───────────────────────────────────────────────
PORT_TO_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain", 80: "http", 110: "pop_3", 111: "sunrpc",
    113: "auth", 143: "imap4", 161: "snmp", 443: "http_443",
    445: "netbios_ssn", 512: "exec", 513: "login", 514: "shell",
    3306: "sql_net", 6667: "IRC", 8080: "http_8001",
}


# ── Flow — tracks one TCP/UDP/ICMP connection ─────────────────────────────────

class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip    = src_ip
        self.dst_ip    = dst_ip
        self.src_port  = src_port
        self.dst_port  = dst_port
        self.protocol  = protocol
        self.start_time = time.time()
        self.last_seen  = time.time()
        self.fwd_packets = []   # (timestamp, payload_len) src→dst
        self.bwd_packets = []   # (timestamp, payload_len) dst→src
        self.syn_count = self.fin_count = self.rst_count = 0
        self.ack_count = self.psh_count = self.urg_count = 0

    def add_packet(self, ts, payload_len, is_forward, flags=None):
        self.last_seen = ts
        (self.fwd_packets if is_forward else self.bwd_packets).append((ts, payload_len))
        if flags:
            if flags & 0x02: self.syn_count += 1
            if flags & 0x01: self.fin_count += 1
            if flags & 0x04: self.rst_count += 1
            if flags & 0x10: self.ack_count += 1
            if flags & 0x08: self.psh_count += 1
            if flags & 0x20: self.urg_count += 1

    @property
    def duration(self):
        return max(self.last_seen - self.start_time, 0)

    @property
    def flag(self):
        """Map TCP flags to NSL-KDD flag category."""
        s, f, r, a = self.syn_count, self.fin_count, self.rst_count, self.ack_count
        if r > 0 and s > 0: return "RSTO"
        if r > 0 and a > 0: return "RSTR"
        if r > 0:            return "REJ"
        if s > 0 and f > 0: return "SF"
        if s > 0 and a > 0: return "S1"
        if s > 0:            return "S0"
        if f > 0:            return "SF"
        return "OTH"

    @property
    def is_syn_error(self):
        return self.flag in ("S0", "S1", "S2", "S3")

    @property
    def is_rst_error(self):
        return self.flag in ("REJ", "RSTO", "RSTR")


# ── Helper math ───────────────────────────────────────────────────────────────

def safe_mean(values):
    return sum(values) / len(values) if values else 0.0

def safe_std(values):
    if len(values) < 2: return 0.0
    m = safe_mean(values)
    return (sum((x - m) ** 2 for x in values) / len(values)) ** 0.5

def iats(packets):
    ts = [p[0] for p in packets]
    return [ts[i+1] - ts[i] for i in range(len(ts) - 1)] if len(ts) > 1 else []


# ── Feature aggregation ───────────────────────────────────────────────────────

def aggregate_features(flows: list) -> dict:
    """
    Compute NSL-KDD + CICIDS features from a BURST of flows
    (e.g. all flows from one nmap scan or one DoS attack).

    Using a burst gives correct count, serror_rate, diff_srv_rate etc.
    because those are statistics ACROSS many connections, not within one.
    """
    n = len(flows)

    # ── Aggregate counts ──────────────────────────────────────────────────────
    total_fwd   = sum(sum(p[1] for p in f.fwd_packets) for f in flows)
    total_bwd   = sum(sum(p[1] for p in f.bwd_packets) for f in flows)
    all_fwd_pkt = [p for f in flows for p in f.fwd_packets]
    all_bwd_pkt = [p for f in flows for p in f.bwd_packets]
    all_pkt     = all_fwd_pkt + all_bwd_pkt
    fwd_sizes   = [p[1] for p in all_fwd_pkt]
    bwd_sizes   = [p[1] for p in all_bwd_pkt]
    all_sizes   = fwd_sizes + bwd_sizes

    total_dur   = sum(f.duration for f in flows)
    avg_dur     = total_dur / n

    # ── NSL-KDD rate features (computed across the burst) ────────────────────
    serr_rate   = sum(1 for f in flows if f.is_syn_error) / n
    rerr_rate   = sum(1 for f in flows if f.is_rst_error) / n

    # How many unique destination ports — high = port scan
    unique_ports   = len(set(f.dst_port for f in flows))
    diff_srv_rate  = unique_ports / n
    same_srv_rate  = 1.0 - diff_srv_rate

    # Use the most common flag and service in the burst
    from collections import Counter
    dominant_flag    = Counter(f.flag    for f in flows).most_common(1)[0][0]
    dominant_service = Counter(
        PORT_TO_SERVICE.get(f.dst_port, "other") for f in flows
    ).most_common(1)[0][0]

    # Reference flow for IP/port info
    ref = flows[0]

    # ── CICIDS IAT features ───────────────────────────────────────────────────
    all_iats_val = iats(sorted(all_pkt, key=lambda p: p[0]))
    fwd_iats_val = iats(all_fwd_pkt)
    bwd_iats_val = iats(all_bwd_pkt)

    dur_us   = avg_dur * 1_000_000
    dur_sec  = avg_dur
    bytes_ps = (total_fwd + total_bwd) / total_dur if total_dur > 0 else 0
    pkts_ps  = len(all_pkt) / total_dur            if total_dur > 0 else 0

    return {
        # ── NSL-KDD ───────────────────────────────────────────────────────────
        "duration":                    int(avg_dur),
        "protocol_type":               ref.protocol,
        "service":                     dominant_service,
        "flag":                        dominant_flag,
        "src_bytes":                   total_fwd,
        "dst_bytes":                   total_bwd,
        "land":                        0,
        "wrong_fragment":              0,
        "urgent":                      sum(f.urg_count for f in flows),
        "hot":                         0,
        "num_failed_logins":           0,
        "logged_in":                   1 if any(f.ack_count > 3 for f in flows) else 0,
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
        "count":                       min(n, 511),          # ← number of flows in burst
        "srv_count":                   min(n, 511),
        "serror_rate":                 round(serr_rate, 3),  # ← fraction with SYN errors
        "srv_serror_rate":             round(serr_rate, 3),
        "rerror_rate":                 round(rerr_rate, 3),
        "srv_rerror_rate":             round(rerr_rate, 3),
        "same_srv_rate":               round(same_srv_rate, 3),
        "diff_srv_rate":               round(diff_srv_rate, 3),  # ← high for port scan
        "srv_diff_host_rate":          0.0,
        "dst_host_count":              min(n, 255),
        "dst_host_srv_count":          min(n, 255),
        "dst_host_same_srv_rate":      round(same_srv_rate, 3),
        "dst_host_diff_srv_rate":      round(diff_srv_rate, 3),
        "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate":        round(serr_rate, 3),
        "dst_host_srv_serror_rate":    round(serr_rate, 3),
        "dst_host_rerror_rate":        round(rerr_rate, 3),
        "dst_host_srv_rerror_rate":    round(rerr_rate, 3),

        # ── CICIDS ────────────────────────────────────────────────────────────
        "Destination Port":            ref.dst_port,
        "Flow Duration":               int(dur_us),
        "Total Fwd Packets":           len(all_fwd_pkt),
        "Total Backward Packets":      len(all_bwd_pkt),
        "Total Length of Fwd Packets": total_fwd,
        "Total Length of Bwd Packets": total_bwd,
        "Fwd Packet Length Max":       max(fwd_sizes) if fwd_sizes else 0,
        "Fwd Packet Length Min":       min(fwd_sizes) if fwd_sizes else 0,
        "Fwd Packet Length Mean":      safe_mean(fwd_sizes),
        "Fwd Packet Length Std":       safe_std(fwd_sizes),
        "Bwd Packet Length Max":       max(bwd_sizes) if bwd_sizes else 0,
        "Bwd Packet Length Min":       min(bwd_sizes) if bwd_sizes else 0,
        "Bwd Packet Length Mean":      safe_mean(bwd_sizes),
        "Bwd Packet Length Std":       safe_std(bwd_sizes),
        "Flow Bytes/s":                bytes_ps,
        "Flow Packets/s":              pkts_ps,
        "Flow IAT Mean":               safe_mean(all_iats_val),
        "Flow IAT Std":                safe_std(all_iats_val),
        "Flow IAT Max":                max(all_iats_val) if all_iats_val else 0,
        "Flow IAT Min":                min(all_iats_val) if all_iats_val else 0,
        "Fwd IAT Total":               sum(fwd_iats_val),
        "Fwd IAT Mean":                safe_mean(fwd_iats_val),
        "Fwd IAT Std":                 safe_std(fwd_iats_val),
        "Fwd IAT Max":                 max(fwd_iats_val) if fwd_iats_val else 0,
        "Fwd IAT Min":                 min(fwd_iats_val) if fwd_iats_val else 0,
        "Bwd IAT Total":               sum(bwd_iats_val),
        "Bwd IAT Mean":                safe_mean(bwd_iats_val),
        "Bwd IAT Std":                 safe_std(bwd_iats_val),
        "Bwd IAT Max":                 max(bwd_iats_val) if bwd_iats_val else 0,
        "Bwd IAT Min":                 min(bwd_iats_val) if bwd_iats_val else 0,
        "Fwd PSH Flags":               sum(f.psh_count for f in flows),
        "Bwd PSH Flags":               0,
        "Fwd URG Flags":               sum(f.urg_count for f in flows),
        "Bwd URG Flags":               0,
        "Fwd Header Length":           len(all_fwd_pkt) * 20,
        "Bwd Header Length":           len(all_bwd_pkt) * 20,
        "Fwd Packets/s":               len(all_fwd_pkt) / total_dur if total_dur > 0 else 0,
        "Bwd Packets/s":               len(all_bwd_pkt) / total_dur if total_dur > 0 else 0,
        "Min Packet Length":           min(all_sizes) if all_sizes else 0,
        "Max Packet Length":           max(all_sizes) if all_sizes else 0,
        "Packet Length Mean":          safe_mean(all_sizes),
        "Packet Length Std":           safe_std(all_sizes),
        "Packet Length Variance":      safe_std(all_sizes) ** 2,
        "FIN Flag Count":              sum(f.fin_count for f in flows),
        "SYN Flag Count":              sum(f.syn_count for f in flows),
        "RST Flag Count":              sum(f.rst_count for f in flows),
        "PSH Flag Count":              sum(f.psh_count for f in flows),
        "ACK Flag Count":              sum(f.ack_count for f in flows),
        "URG Flag Count":              sum(f.urg_count for f in flows),
        "CWE Flag Count":              0,
        "ECE Flag Count":              0,
        "Down/Up Ratio":               total_bwd / total_fwd if total_fwd > 0 else 0,
        "Average Packet Size":         safe_mean(all_sizes),
        "Avg Fwd Segment Size":        safe_mean(fwd_sizes),
        "Avg Bwd Segment Size":        safe_mean(bwd_sizes),
        "Fwd Avg Bytes/Bulk":          0,
        "Fwd Avg Packets/Bulk":        0,
        "Fwd Avg Bulk Rate":           0,
        "Bwd Avg Bytes/Bulk":          0,
        "Bwd Avg Packets/Bulk":        0,
        "Bwd Avg Bulk Rate":           0,
        "Subflow Fwd Packets":         len(all_fwd_pkt),
        "Subflow Fwd Bytes":           total_fwd,
        "Subflow Bwd Packets":         len(all_bwd_pkt),
        "Subflow Bwd Bytes":           total_bwd,
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


# ── Flow aggregator ───────────────────────────────────────────────────────────

class FlowAggregator:
    """
    Groups completed flows by (src_ip, dst_ip) pair.
    When a group goes idle (no new flow for IDLE_SECS), exports the
    whole burst as one aggregated prediction instead of one per flow.

    This is critical for correct NSL-KDD stats:
      nmap  →  1024 flows in 2s  →  aggregated  →  count=1024, serror_rate=0.9
      DoS   →  many flows        →  aggregated  →  count=high, serror_rate=1.0
    """

    IDLE_SECS = 3.0   # seconds of no new flows before flushing a group

    def __init__(self, on_burst_complete):
        self.groups          = defaultdict(list)   # (src,dst) → [Flow, ...]
        self.last_seen       = {}                  # (src,dst) → timestamp
        self.on_burst_complete = on_burst_complete
        self.lock            = threading.Lock()

    def add(self, flow: Flow):
        key = (flow.src_ip, flow.dst_ip)
        with self.lock:
            self.groups[key].append(flow)
            self.last_seen[key] = time.time()

    def flush_idle(self):
        """Called periodically — exports groups that have gone idle."""
        now     = time.time()
        to_flush = []
        with self.lock:
            for key, ts in list(self.last_seen.items()):
                if now - ts >= self.IDLE_SECS:
                    to_flush.append(key)

        for key in to_flush:
            with self.lock:
                flows = self.groups.pop(key, [])
                self.last_seen.pop(key, None)
            if flows:
                self.on_burst_complete(flows)


# ── Individual flow tracker (per-packet) ─────────────────────────────────────

class FlowTracker:
    """Tracks active flows at the packet level. Hands completed flows to FlowAggregator."""

    IDLE_TIMEOUT = 5.0

    def __init__(self, aggregator: FlowAggregator, vm_ips: set = None):
        self.flows      = {}
        self.aggregator = aggregator
        self.vm_ips     = vm_ips   # if set, only capture traffic between these IPs
        self.lock       = threading.Lock()

    def _key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        return (dst_ip, src_ip, dst_port, src_port, protocol)

    def process_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ts     = time.time()

        # Only process packets between the two VMs — ignore Windows host traffic
        if self.vm_ips and not ({src_ip, dst_ip} <= self.vm_ips):
            return

        if pkt.haslayer(TCP):
            proto    = "tcp"
            sp, dp   = pkt[TCP].sport, pkt[TCP].dport
            flags    = pkt[TCP].flags
            payload  = len(pkt[TCP].payload)
        elif pkt.haslayer(UDP):
            proto    = "udp"
            sp, dp   = pkt[UDP].sport, pkt[UDP].dport
            flags    = None
            payload  = len(pkt[UDP].payload)
        elif pkt.haslayer(ICMP):
            proto    = "icmp"
            sp = dp  = 0
            flags    = None
            payload  = len(pkt[ICMP].payload)
        else:
            return

        key        = self._key(src_ip, dst_ip, sp, dp, proto)
        is_forward = (src_ip, sp) <= (dst_ip, dp)

        with self.lock:
            if key not in self.flows:
                self.flows[key] = Flow(key[0], key[1], key[2], key[3], proto)
            flow = self.flows[key]
            flow.add_packet(ts, payload, is_forward, flags)

            # Export on FIN or RST — clean teardown
            if flags and (flags & 0x01 or flags & 0x04):
                self._export(key)

    def _export(self, key):
        flow = self.flows.pop(key, None)
        if flow and (len(flow.fwd_packets) + len(flow.bwd_packets)) >= 1:
            self.aggregator.add(flow)   # hand to aggregator, not directly to API

    def expire_idle(self):
        now = time.time()
        with self.lock:
            expired = [k for k, f in self.flows.items()
                       if now - f.last_seen > self.IDLE_TIMEOUT]
        for key in expired:
            with self.lock:
                self._export(key)


# ── API call ──────────────────────────────────────────────────────────────────

def post_prediction(features: dict, api_url: str, flows: list, verbose: bool):
    """POST aggregated features to /api/predict/dual and print alert."""
    try:
        res = requests.post(
            f"{api_url}/api/predict/dual",
            json={"features": features},
            timeout=5,
        )
        res.raise_for_status()
        result = res.json()

        level   = result.get("risk_level", "?")
        score   = result.get("risk_score", 0)
        nsl_r   = result.get("nslkdd_rf_prediction", "?")
        nsl_i   = result.get("nslkdd_if_prediction", "?")
        cic_r   = result.get("cicids_rf_prediction",  "?")
        cic_i   = result.get("cicids_if_prediction",  "?")
        n       = len(flows)
        src_ip  = flows[0].src_ip
        dst_ip  = flows[0].dst_ip
        ts      = datetime.now().strftime("%H:%M:%S")

        colors = {
            "Low":      "\033[92m",
            "Medium":   "\033[93m",
            "High":     "\033[91m",
            "Critical": "\033[91;1m",
        }
        reset = "\033[0m"
        col   = colors.get(level, "")

        print(f"[{ts}] {src_ip} → {dst_ip} "
              f"({n} flows) | "
              f"{col}[{level:8s}] Risk:{score:5.1f}{reset} | "
              f"NSL RF:{nsl_r} IF:{nsl_i}  CIC RF:{cic_r} IF:{cic_i}")

    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Cannot connect to API at {api_url}. Is the backend running?")
    except Exception as e:
        if verbose:
            print(f"[WARN] API error: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

def run(interface: str, api_url: str, kali_ip: str, target_ip: str, verbose: bool):
    vm_ips = {kali_ip, target_ip}
    print(f"[FlowExtractor] Interface : {interface}")
    print(f"[FlowExtractor] API       : {api_url}/api/predict/dual")
    print(f"[FlowExtractor] Filtering : {kali_ip} ↔ {target_ip} only")
    print(f"[FlowExtractor] Mode      : burst aggregation (3s idle flush)")
    print(f"[FlowExtractor] Press Ctrl+C to stop\n")

    def on_burst_complete(flows: list):
        features = aggregate_features(flows)
        post_prediction(features, api_url, flows, verbose)

    aggregator = FlowAggregator(on_burst_complete)
    tracker    = FlowTracker(aggregator, vm_ips)

    # Background thread — flushes idle flows and bursts
    def background():
        while True:
            time.sleep(1)
            tracker.expire_idle()
            aggregator.flush_idle()

    t = threading.Thread(target=background, daemon=True)
    t.start()

    sniff(iface=interface, prn=tracker.process_packet, store=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XAI-IDS Live Flow Extractor")
    parser.add_argument("--interface", default="vboxnet0",
                        help="Network interface to sniff")
    parser.add_argument("--api",       default="http://localhost:8000",
                        help="Backend API URL")
    parser.add_argument("--kali",      default="192.168.232.129",
                        help="Kali Linux IP address (attacker)")
    parser.add_argument("--target",    default="192.168.232.130",
                        help="Metasploitable IP address (victim)")
    parser.add_argument("--verbose",   action="store_true",
                        help="Print API errors and warnings")
    args = parser.parse_args()

    run(args.interface, args.api, args.kali, args.target, args.verbose)