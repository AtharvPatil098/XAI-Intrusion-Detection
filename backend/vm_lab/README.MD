# VM Lab — XAI Intrusion Detection System

Complete guide to integrating the IDS with a Kali Linux + Metasploitable VM lab.

---

## VM Setup

| VM             | Role       | OS              | Default IP      |
|----------------|------------|-----------------|-----------------|
| Kali Linux     | Attacker   | Kali Linux 2023+| 192.168.56.102  |
| Metasploitable | Victim     | Ubuntu (MSF2)   | 192.168.56.101  |

### VirtualBox Network Configuration
Both VMs must be on the same **Host-Only** adapter:
```
VM Settings → Network → Adapter 1 → Attached to: Host-only Adapter → vboxnet0
```

Verify IPs inside each VM:
```bash
ip addr show
```

---

## Host Machine Setup

The IDS backend runs on your **host machine** — not inside the VMs.

### 1. Install dependencies
```bash
cd backend
pip install -r requirements.txt
pip install scapy requests
```

### 2. Find the host-only interface name
```bash
ip link show | grep vbox     # Linux — usually vboxnet0
ifconfig | grep vbox         # Mac
```

### 3. Run preprocessing and training (one-time)
```bash
python preprocessing/preprocess_nslkdd.py
python model/train_rf.py --dataset nslkdd
python anomaly_detection/train_if.py --dataset nslkdd

# CICIDS — place 8 CSVs in data/raw/CICIDS/ first
python preprocessing/preprocess_cicids.py
python model/train_rf.py --dataset cicids
python anomaly_detection/train_if.py --dataset cicids
```

---

## Running the Full Stack

Open 3 terminals on your host:

### Terminal 1 — Backend API
```bash
cd backend
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

### Terminal 2 — Flow Extractor (requires sudo)
```bash
cd backend
sudo python vm_lab/flow_extractor.py --interface vboxnet0

# Options:
#   --interface   Network interface to sniff  (default: vboxnet0)
#   --api         Backend API URL             (default: http://localhost:8000)
#   --timeout     Flow idle timeout seconds   (default: 5)
#   --verbose     Show debug output
```

### Terminal 3 — Dashboard
```bash
open frontend/index.html        # Mac
xdg-open frontend/index.html   # Linux
```

---

## Running Attacks from Kali Linux

### Port Scan (Probe)
```bash
nmap -sS -T4 -p 1-1024 192.168.56.101
```
Expected: High/Critical, NSL-KDD classifies as "probe"

### DoS SYN Flood
```bash
sudo hping3 --syn --flood -p 80 --rand-source 192.168.56.101 &
sleep 15 && kill %1
```
Expected: Critical, serror_rate = 1.0, both RF models flag DoS

### Brute Force SSH
```bash
hydra -l msfadmin -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.101 -t 4
```
Expected: High, num_failed_logins elevated, service=ssh

### Run All Attack Scripts
```bash
chmod +x backend/vm_lab/attack_scripts/*.sh
TARGET=192.168.56.101
./backend/vm_lab/attack_scripts/port_scan.sh $TARGET
./backend/vm_lab/attack_scripts/dos_attack.sh $TARGET 10
./backend/vm_lab/attack_scripts/brute_force.sh $TARGET
```

---

## Traffic Simulation (No VMs Required)

```bash
python vm_lab/traffic_simulator.py --type all --n 500

# Test dual endpoint directly
curl -X POST http://localhost:8000/api/predict/dual \
  -H "Content-Type: application/json" \
  -d '{"features": {"duration":0,"protocol_type":"tcp","flag":"S0","count":511,"serror_rate":1.0,"SYN Flag Count":511,"Flow Duration":0}}'
```

---

## How the Flow Extractor Works

```
Kali → Metasploitable packets on vboxnet0
        ↓
scapy captures each packet
        ↓
FlowTracker groups packets into flows (5-tuple)
        ↓
Flow exported on FIN/RST or idle timeout (5s)
        ↓
flow_to_dual_features() computes both feature spaces:
  41 NSL-KDD features + 77 CICIDS features
        ↓
POST /api/predict/dual → all 4 models run
        ↓
Risk score + alert printed to terminal
Dashboard updates in real time
```

### Feature Coverage

| Feature group | Coverage | Notes |
|---|---|---|
| Bytes / packet counts | Full | Directly measured |
| TCP flags | Full | Read from TCP header |
| Flow duration + IATs | Full | From timestamps |
| Port / service mapping | Full | Port → NSL-KDD service lookup |
| NSL-KDD host stats | Partial | count approximated |
| CICIDS bulk metrics | Zero | Requires CICFlowMeter |
| Init TCP window size | Zero | Not extracted by scapy |

---

## Troubleshooting

**Permission denied**
```bash
sudo python vm_lab/flow_extractor.py --interface vboxnet0
```

**Cannot connect to API**
```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

**Interface not found**
```bash
ip link show    # find your vboxnet interface name
sudo python vm_lab/flow_extractor.py --interface vboxnet1
```

**No flows appearing**
- Ping Metasploitable from Kali: `ping 192.168.56.101`
- Confirm both VMs use Host-Only adapter
- Try `--interface any` (Linux only)

**CICIDS models MISSING**
System still works with only NSL-KDD models. CICIDS requires the 8 dataset CSVs.