# Simulated leaked credentials for testing Vexscan SECRET rules
# This file is intentionally full of fake secrets for detection testing.

# SECRET-001: AWS access key
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# SECRET-002: Stripe API key
STRIPE_KEY = "sk_live_abcdefghijklmnopqrstuvwx"

# SECRET-003: Google API key
GOOGLE_KEY = "AIzaSyC_abcdefghij-klmnopqrstuvwxyz12345"

# SECRET-004: GitHub token
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"

# SECRET-005: JWT token
AUTH_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789"

# SECRET-006: Private key
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/yGSHEBU...
-----END RSA PRIVATE KEY-----"""

# SECRET-007: Hardcoded password
password = "mysecretpassword123"

# SECRET-008: Database connection string
DB_URI = "mongodb://admin:pass123@db.example.com:27017/production"
