# VM Lab — XAI Intrusion Detection System
# Windows Host + VirtualBox (Kali Linux + Metasploitable)

---

## Your Setup

```
Windows Host Machine
    │
    ├── FastAPI backend      (localhost:8000)
    ├── Dashboard            (browser)
    │
    └── VirtualBox
            ├── Kali Linux        192.168.232.129  (Attacker)
            └── Metasploitable    192.168.232.128  (Victim)
```

---

## Step 1 — Install Npcap (Windows only, required)

Scapy needs Npcap to capture packets on Windows. WinPcap will NOT work.

1. Download from: https://npcap.com/#download
2. Run the installer
3. Check **"Install Npcap in WinPcap API-compatible mode"**
4. Restart Windows after installation

---

## Step 2 — Find your VirtualBox interface name

On Windows, interfaces have long `\Device\NPF_{GUID}` names instead of `vboxnet0`.

Open **Command Prompt as Administrator** and run:

```cmd
python -c "
from scapy.all import get_if_list, get_if_addr
for iface in get_if_list():
    try:
        addr = get_if_addr(iface)
        print(f'{addr}  ->  {iface}')
    except:
        pass
"
```

Look for the line showing `192.168.232.x` — that is your VM network interface.
Copy the full `\Device\NPF_{...}` string — you will need it in Step 4.

Example output:
```
192.168.232.1   ->  \Device\NPF_{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
192.168.1.5     ->  \Device\NPF_{B2C3D4E5-...}   <- your WiFi, ignore this
```

---
atharv = \Device\NPF_{BCB66A33-2C7F-49EE-A091-11D81FED149C}
## Step 3 — Install dependencies

```cmd
cd backend
pip install -r requirements.txt
pip install scapy requests
```

---

## Step 4 — Run the full stack

Open **3 terminals**:

### Terminal 1 — Backend (regular cmd)
```cmd
cd backend
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

### Terminal 2 — Flow Extractor (Administrator cmd — required for packet capture)
```cmd
cd backend
python vm_lab/flow_extractor.py ^
  --interface "\Device\NPF_{BCB66A33-2C7F-49EE-A091-11D81FED149C}" ^
  --kali 192.168.232.129 ^
  --target 192.168.232.128
```
atharv = \Device\NPF_{BCB66A33-2C7F-49EE-A091-11D81FED149C}

Replace `{your-guid-here}` with the GUID you found in Step 2.

### Terminal 3 — Dashboard
Open in browser:
```
http://127.0.0.1:8000/dashboard
```

---

## Step 5 — Verify it's working

Once flow_extractor is running you should see:
```
[FlowExtractor] Sniffing on '\Device\NPF_{...}' → http://127.0.0.1:8000/api/predict/dual
[FlowExtractor] Flow idle timeout: 5s
[FlowExtractor] Press Ctrl+C to stop
```

From Kali, ping Metasploitable to generate traffic:
```bash
ping 192.168.232.128
```

You should immediately see alert lines in the flow_extractor terminal:
```
[08:42:11] 192.168.232.129:0 → 192.168.232.128:0 (ICMP) | [Low    ] Risk:  18.2
```

---

## Step 6 — Run attacks from Kali

### Port Scan (Probe detection)
```bash
nmap -sS -T4 -p 1-1024 192.168.232.128
```
Expected: High/Critical, SYN Flag Count elevated, NSL-KDD flags as probe

### DoS SYN Flood
```bash
sudo hping3 --syn --flood -p 80 192.168.232.128 &
sleep 10 && kill %1
```
Expected: Critical, serror_rate = 1.0, both RF models flag DoS

### Brute Force SSH
```bash
hydra -l msfadmin -P /usr/share/wordlists/rockyou.txt ssh://192.168.232.128 -t 4
```
Expected: High risk, service = ssh, num_failed_logins elevated

---

## Troubleshooting

### "No module named scapy"
```cmd
pip install scapy
```

### "Permission denied" / flow_extractor captures nothing
Must run cmd as Administrator. Right-click cmd → Run as administrator.

### Npcap not found error
Re-install Npcap from https://npcap.com and restart Windows.

### Interface not found
Run the Step 2 command again — use the exact string including `\Device\NPF_`.

### No flows appearing after running attacks
Your VMs may be on plain NAT (not NAT Network) — Windows can't sniff plain NAT traffic directly. Switch to NAT Network:

```
VirtualBox → File → Tools → Network Manager → NAT Networks → Create
  Name: IDS_Network
  CIDR: 192.168.232.0/24

Both VMs → Settings → Network → Adapter 1:
  Attached to: NAT Network
  Name: IDS_Network
```

Restart both VMs, find the interface name again (Step 2), then retry.

### Flow extractor running but dashboard not updating
The dashboard polls `/api/predict/dual` using random samples every 2 seconds independently of flow_extractor. Flow_extractor posts its own predictions to the same endpoint but the dashboard doesn't switch to showing those automatically.

To see flow_extractor results: watch the **Terminal 2 output** for real-time alerts. The dashboard shows the model's behaviour on random samples in parallel.

---

## How it works

```
Kali attack traffic on VM network
        ↓
Npcap captures packets (Windows driver)
        ↓
flow_extractor.py groups packets into flows (5-tuple)
        ↓
Flow exported on FIN/RST or 5s idle timeout
        ↓
flow_to_dual_features() computes:
  - 41 NSL-KDD features (flags, bytes, rates, duration)
  - 77 CICIDS features  (IATs, packet lengths, flow stats)
        ↓
POST /api/predict/dual → all 4 models run
        ↓
[LEVEL] Risk: score  NSL RF:x IF:x  CIC RF:x IF:x
```

---

## Traffic Simulation (No VMs needed)

If you just want to test the full pipeline without the VMs:

```cmd
cd backend
python vm_lab/traffic_simulator.py --type all --n 500
```

This generates `vm_lab/logs/normal_traffic.log`, `attack_traffic.log`, `mixed_traffic.log`.

Then run the detector against the log:
```python
from realtime_detection.realtime_detector import DualRealtimeDetector
detector = DualRealtimeDetector()
results  = detector.process_csv_file("vm_lab/logs/mixed_traffic.log", max_rows=200)
for r in results:
    print(r["risk_level"], r["risk_score"])
```