# vm_lab/traffic_simulator.py
# Simulates normal and attack traffic logs for VM-based testing.
# Mimics what Kali Linux → Metasploitable traffic would look like
# as NSL-KDD formatted records.

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import random
import time
import csv
import json
import argparse
from datetime import datetime

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# NSL-KDD feature columns (no label/difficulty)
COLUMNS = [
    "duration","protocol_type","service","flag",
    "src_bytes","dst_bytes","land","wrong_fragment","urgent",
    "hot","num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count",
    "serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate",
    "dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
    "dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate"
]

PROTOCOLS = ["tcp", "udp", "icmp"]
SERVICES  = ["http", "ftp", "ssh", "smtp", "dns", "https", "ftp_data", "other", "private"]
FLAGS     = ["SF", "S0", "REJ", "RSTO", "SH", "RSTR", "S1", "S2", "S3", "OTH"]


# ── Traffic Generators ────────────────────────────────────────────────────────

def gen_normal():
    """Simulate a normal TCP/HTTP connection."""
    return {
        "duration":                 random.randint(0, 100),
        "protocol_type":            random.choice(["tcp", "udp"]),
        "service":                  random.choice(["http", "https", "ftp_data", "smtp"]),
        "flag":                     "SF",
        "src_bytes":                random.randint(100, 5000),
        "dst_bytes":                random.randint(100, 8000),
        "land":                     0,
        "wrong_fragment":           0,
        "urgent":                   0,
        "hot":                      random.randint(0, 2),
        "num_failed_logins":        0,
        "logged_in":                random.choice([0, 1]),
        "num_compromised":          0,
        "root_shell":               0,
        "su_attempted":             0,
        "num_root":                 0,
        "num_file_creations":       random.randint(0, 2),
        "num_shells":               0,
        "num_access_files":         random.randint(0, 3),
        "num_outbound_cmds":        0,
        "is_host_login":            0,
        "is_guest_login":           0,
        "count":                    random.randint(1, 50),
        "srv_count":                random.randint(1, 50),
        "serror_rate":              round(random.uniform(0, 0.05), 2),
        "srv_serror_rate":          round(random.uniform(0, 0.05), 2),
        "rerror_rate":              round(random.uniform(0, 0.05), 2),
        "srv_rerror_rate":          round(random.uniform(0, 0.05), 2),
        "same_srv_rate":            round(random.uniform(0.8, 1.0), 2),
        "diff_srv_rate":            round(random.uniform(0, 0.1), 2),
        "srv_diff_host_rate":       round(random.uniform(0, 0.1), 2),
        "dst_host_count":           random.randint(100, 255),
        "dst_host_srv_count":       random.randint(100, 255),
        "dst_host_same_srv_rate":   round(random.uniform(0.8, 1.0), 2),
        "dst_host_diff_srv_rate":   round(random.uniform(0, 0.1), 2),
        "dst_host_same_src_port_rate": round(random.uniform(0, 0.1), 2),
        "dst_host_srv_diff_host_rate": round(random.uniform(0, 0.1), 2),
        "dst_host_serror_rate":     round(random.uniform(0, 0.05), 2),
        "dst_host_srv_serror_rate": round(random.uniform(0, 0.05), 2),
        "dst_host_rerror_rate":     round(random.uniform(0, 0.05), 2),
        "dst_host_srv_rerror_rate": round(random.uniform(0, 0.05), 2),
    }


def gen_dos_neptune():
    """Simulate DoS Neptune (SYN flood) attack."""
    return {
        "duration":                 0,
        "protocol_type":            "tcp",
        "service":                  "private",
        "flag":                     "S0",
        "src_bytes":                0,
        "dst_bytes":                0,
        "land":                     0,
        "wrong_fragment":           0,
        "urgent":                   0,
        "hot":                      0,
        "num_failed_logins":        0,
        "logged_in":                0,
        "num_compromised":          0,
        "root_shell":               0,
        "su_attempted":             0,
        "num_root":                 0,
        "num_file_creations":       0,
        "num_shells":               0,
        "num_access_files":         0,
        "num_outbound_cmds":        0,
        "is_host_login":            0,
        "is_guest_login":           0,
        "count":                    random.randint(100, 511),
        "srv_count":                random.randint(1, 20),
        "serror_rate":              round(random.uniform(0.9, 1.0), 2),
        "srv_serror_rate":          round(random.uniform(0.9, 1.0), 2),
        "rerror_rate":              0.0,
        "srv_rerror_rate":          0.0,
        "same_srv_rate":            round(random.uniform(0.05, 0.15), 2),
        "diff_srv_rate":            round(random.uniform(0.05, 0.15), 2),
        "srv_diff_host_rate":       0.0,
        "dst_host_count":           random.randint(200, 255),
        "dst_host_srv_count":       random.randint(1, 20),
        "dst_host_same_srv_rate":   round(random.uniform(0.05, 0.15), 2),
        "dst_host_diff_srv_rate":   round(random.uniform(0.05, 0.10), 2),
        "dst_host_same_src_port_rate": round(random.uniform(0.0, 0.05), 2),
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate":     round(random.uniform(0.9, 1.0), 2),
        "dst_host_srv_serror_rate": round(random.uniform(0.9, 1.0), 2),
        "dst_host_rerror_rate":     0.0,
        "dst_host_srv_rerror_rate": 0.0,
    }


def gen_probe_portscan():
    """Simulate probe/port-scan (ipsweep/portsweep style)."""
    return {
        "duration":                 0,
        "protocol_type":            "tcp",
        "service":                  "private",
        "flag":                     "REJ",
        "src_bytes":                0,
        "dst_bytes":                0,
        "land":                     0,
        "wrong_fragment":           0,
        "urgent":                   0,
        "hot":                      0,
        "num_failed_logins":        0,
        "logged_in":                0,
        "num_compromised":          0,
        "root_shell":               0,
        "su_attempted":             0,
        "num_root":                 0,
        "num_file_creations":       0,
        "num_shells":               0,
        "num_access_files":         0,
        "num_outbound_cmds":        0,
        "is_host_login":            0,
        "is_guest_login":           0,
        "count":                    random.randint(1, 50),
        "srv_count":                random.randint(1, 20),
        "serror_rate":              0.0,
        "srv_serror_rate":          0.0,
        "rerror_rate":              round(random.uniform(0.8, 1.0), 2),
        "srv_rerror_rate":          round(random.uniform(0.8, 1.0), 2),
        "same_srv_rate":            round(random.uniform(0.0, 0.1), 2),
        "diff_srv_rate":            round(random.uniform(0.4, 0.6), 2),
        "srv_diff_host_rate":       round(random.uniform(0.5, 1.0), 2),
        "dst_host_count":           random.randint(200, 255),
        "dst_host_srv_count":       random.randint(1, 30),
        "dst_host_same_srv_rate":   round(random.uniform(0.0, 0.1), 2),
        "dst_host_diff_srv_rate":   round(random.uniform(0.3, 0.5), 2),
        "dst_host_same_src_port_rate": round(random.uniform(0.0, 0.05), 2),
        "dst_host_srv_diff_host_rate": round(random.uniform(0.5, 1.0), 2),
        "dst_host_serror_rate":     0.0,
        "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate":     round(random.uniform(0.8, 1.0), 2),
        "dst_host_srv_rerror_rate": round(random.uniform(0.8, 1.0), 2),
    }


def gen_brute_force():
    """Simulate brute-force / R2L (guess_passwd style)."""
    return {
        "duration":                 random.randint(0, 10),
        "protocol_type":            "tcp",
        "service":                  "ssh",
        "flag":                     "SF",
        "src_bytes":                random.randint(50, 300),
        "dst_bytes":                random.randint(50, 300),
        "land":                     0,
        "wrong_fragment":           0,
        "urgent":                   0,
        "hot":                      random.randint(0, 5),
        "num_failed_logins":        random.randint(3, 10),
        "logged_in":                0,
        "num_compromised":          0,
        "root_shell":               0,
        "su_attempted":             0,
        "num_root":                 0,
        "num_file_creations":       0,
        "num_shells":               0,
        "num_access_files":         0,
        "num_outbound_cmds":        0,
        "is_host_login":            0,
        "is_guest_login":           0,
        "count":                    random.randint(10, 50),
        "srv_count":                random.randint(5, 30),
        "serror_rate":              0.0,
        "srv_serror_rate":          0.0,
        "rerror_rate":              round(random.uniform(0.0, 0.2), 2),
        "srv_rerror_rate":          round(random.uniform(0.0, 0.2), 2),
        "same_srv_rate":            round(random.uniform(0.7, 1.0), 2),
        "diff_srv_rate":            round(random.uniform(0.0, 0.1), 2),
        "srv_diff_host_rate":       round(random.uniform(0.0, 0.2), 2),
        "dst_host_count":           random.randint(50, 200),
        "dst_host_srv_count":       random.randint(50, 200),
        "dst_host_same_srv_rate":   round(random.uniform(0.7, 1.0), 2),
        "dst_host_diff_srv_rate":   round(random.uniform(0.0, 0.1), 2),
        "dst_host_same_src_port_rate": round(random.uniform(0.5, 1.0), 2),
        "dst_host_srv_diff_host_rate": round(random.uniform(0.0, 0.1), 2),
        "dst_host_serror_rate":     0.0,
        "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate":     round(random.uniform(0.0, 0.2), 2),
        "dst_host_srv_rerror_rate": round(random.uniform(0.0, 0.2), 2),
    }


TRAFFIC_GENERATORS = {
    "normal":      gen_normal,
    "dos":         gen_dos_neptune,
    "probe":       gen_probe_portscan,
    "brute_force": gen_brute_force,
}


def generate_log(traffic_type: str, n: int, output_file: str):
    generator = TRAFFIC_GENERATORS.get(traffic_type, gen_normal)
    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        for _ in range(n):
            row = generator()
            writer.writerow(row)
    print(f"[Simulator] Generated {n} {traffic_type} records → {output_file}")


def generate_mixed_log(n: int, output_file: str,
                       weights=None):
    """Generate mixed traffic: mostly normal with some attacks."""
    if weights is None:
        weights = {"normal": 0.6, "dos": 0.15, "probe": 0.15, "brute_force": 0.10}

    types = list(weights.keys())
    probs = list(weights.values())

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        for _ in range(n):
            chosen = random.choices(types, weights=probs, k=1)[0]
            row = TRAFFIC_GENERATORS[chosen]()
            writer.writerow(row)
    print(f"[Simulator] Generated {n} mixed records → {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XAI-IDS Traffic Simulator")
    parser.add_argument("--type", choices=["normal","dos","probe","brute_force","mixed","all"],
                        default="all")
    parser.add_argument("--n", type=int, default=200)
    args = parser.parse_args()

    if args.type == "all":
        generate_log("normal",      args.n, os.path.join(LOG_DIR, "normal_traffic.log"))
        generate_log("dos",         args.n, os.path.join(LOG_DIR, "attack_traffic.log"))
        generate_mixed_log(args.n,          os.path.join(LOG_DIR, "mixed_traffic.log"))
    elif args.type == "mixed":
        generate_mixed_log(args.n,          os.path.join(LOG_DIR, "mixed_traffic.log"))
    else:
        generate_log(args.type, args.n, os.path.join(LOG_DIR, f"{args.type}_traffic.log"))