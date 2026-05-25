#!/bin/bash
# vm_lab/attack_scripts/port_scan.sh
# Run from Kali Linux → target Metasploitable
# Usage: ./port_scan.sh <TARGET_IP>

nmap -sS -p 1-2000 -T4 192.168.232.130
