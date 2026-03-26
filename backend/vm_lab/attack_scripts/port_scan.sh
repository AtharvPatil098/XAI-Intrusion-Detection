#!/bin/bash
# vm_lab/attack_scripts/port_scan.sh
# Run from Kali Linux → target Metasploitable
# Usage: ./port_scan.sh <TARGET_IP>

TARGET=${1:-"192.168.232.128"}
echo "[*] Starting port scan on $TARGET"

# Quick SYN scan (nmap)
nmap -sS -T4 -p 1-1024 $TARGET -oN /tmp/portscan_results.txt

echo "[*] Port scan complete. Results in /tmp/portscan_results.txt"
