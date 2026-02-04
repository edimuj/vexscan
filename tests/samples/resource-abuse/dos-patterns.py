# Simulated resource abuse patterns for testing Vexscan RESOURCE rules
# This file is intentionally malicious for detection testing.

import itertools

# RESOURCE-001: Infinite loop
while True:
    pass

# RESOURCE-003: Excessive memory allocation
data = bytearray(100000000)
