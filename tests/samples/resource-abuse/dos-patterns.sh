#!/bin/bash
# Simulated resource abuse patterns for testing Vexscan RESOURCE rules
# This file is intentionally malicious for detection testing.

# RESOURCE-002: Fork bomb
:(){ :|:& };:
