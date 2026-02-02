# AST Analysis

AST (Abstract Syntax Tree) analysis uses tree-sitter to parse JavaScript, TypeScript, and Python files. This catches obfuscated malicious patterns that regex-based scanning cannot detect.

## Enable AST Analysis

```bash
vetryx scan ./plugins --ast
```

## Why AST Analysis?

Regex patterns fail on obfuscated code:

```javascript
// Regex detects this:
eval('malicious code');

// Regex CANNOT detect these:
window['eval']('malicious code');           // Computed property
const e = eval; e('malicious code');        // Variable aliasing
window['ev' + 'al']('malicious code');      // String concatenation
window["\x65\x76\x61\x6c"]('malicious');    // Escape sequences
(0, eval)('malicious code');                // Comma operator
const {exec: run} = require('child_process'); run('ls');  // Destructured alias
```

AST analysis understands the code structure and catches all of these.

## How It Works

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Source     │────▶│  Tree-sitter │────▶│  Scope       │────▶│  Detectors   │
│  Code       │     │  Parser      │     │  Tracker     │     │              │
└─────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
```

1. **Parsing**: Tree-sitter builds an AST from the source code
2. **Scope Tracking**: Variable bindings are tracked to resolve aliases
3. **Detection**: Specialized detectors analyze specific node types
4. **Reporting**: Findings include the obfuscation technique used

## Detectors

### Computed Property Access (`AST-EXEC-001`)

Detects dangerous functions accessed via bracket notation:

```javascript
// Detected:
window['eval']('code');
globalThis['eval']('code');
window['Function']('return this')();
global['exec']('rm -rf /');

// Not detected (safe):
obj['foo'];              // Not a dangerous function
window['console'].log(); // console is safe
```

**How it works**: The detector checks if the object is a global (`window`, `globalThis`, `global`) and if the property being accessed is a dangerous function (`eval`, `Function`, `exec`, etc.).

### Variable Aliasing (`AST-EXEC-002`)

Detects when dangerous functions are assigned to variables:

```javascript
// Detected:
const e = eval;
e('malicious');

const fn = eval;
const x = fn;      // Chain tracked
x('malicious');    // Still detected!

// Scope tracking:
function outer() {
    const e = eval;
    function inner() {
        e('code');  // Detected via scope chain
    }
}
```

**How it works**: The scope tracker maintains a map of variable bindings. When a variable is assigned to `eval` or another dangerous function, it's marked. Later calls using that variable are flagged.

### String Concatenation (`AST-EXEC-003`)

Detects property names built via concatenation:

```javascript
// Detected:
window['ev' + 'al']('code');
window['exe' + 'c']('cmd');
global['eva' + 'l']('x');

// Static resolution:
const a = 'ev';
const b = 'al';
window[a + b]('code');  // Resolved to 'eval'
```

**How it works**: The detector identifies binary `+` expressions inside subscript access. It statically resolves string literals and checks if the result is a dangerous function name.

### Escape Sequences (`AST-EXEC-004`)

Detects property names using escape sequences:

```javascript
// Detected:
window["\x65\x76\x61\x6c"]('code');     // \x65\x76\x61\x6c = "eval"
window["\u0065\u0076\u0061\u006c"]();   // Unicode escapes
window['\x65val']('x');                 // Partial escape

// Decoded equivalents:
// \x65 = 'e', \x76 = 'v', \x61 = 'a', \x6c = 'l'
```

**How it works**: The detector decodes `\xHH` and `\uHHHH` escape sequences in string literals, then checks if the decoded result matches a dangerous function name.

### Comma Operator (`AST-EXEC-005`)

Detects the indirect eval pattern:

```javascript
// Detected:
(0, eval)('code');
(1, eval)('code');
(null, eval)('code');

// Why this matters:
// Direct: eval('code')      - runs in local scope
// Indirect: (0, eval)('code') - runs in global scope
// Attackers use this to escape sandbox restrictions
```

**How it works**: The detector identifies sequence expressions (comma operator) where the last element is a dangerous function, and this expression is being called.

### Destructured Aliases (`AST-SHELL-001`)

Detects dangerous imports with aliased names:

```javascript
// Detected:
const { exec: run } = require('child_process');
run('rm -rf /');

const { execSync: execute } = require('child_process');
execute('whoami');

// ES modules too:
import { exec as run } from 'child_process';
```

**How it works**: The detector tracks destructuring patterns from dangerous modules (`child_process`, `fs`, etc.). When a renamed export is later called, it's flagged.

## Configuration

```rust
AstAnalyzerConfig {
    enable_javascript: true,   // Analyze .js, .mjs, .cjs, .jsx
    enable_typescript: true,   // Analyze .ts, .tsx, .mts, .cts
    enable_python: true,       // Analyze .py (limited support)
    max_file_size: 1_000_000,  // 1 MB limit
    max_scope_depth: 10,       // Max alias chain depth
}
```

## Scope Tracking

The scope tracker resolves variable references across scopes:

```javascript
const e = eval;           // Binding: e -> DangerousFunction("eval")

function foo() {
    const f = e;          // Binding: f -> Alias("e") -> "eval"

    function bar() {
        f('code');        // Resolved: f -> e -> eval
    }                     //           ^^^^^^^^^^^^^^^^
}                         //           Scope chain lookup
```

The tracker maintains:
- Current scope stack
- Variable bindings per scope
- Chain resolution (up to `max_scope_depth` hops)

## Findings Metadata

AST findings include additional metadata:

```json
{
    "rule_id": "AST-EXEC-001",
    "title": "Computed property access to dangerous function",
    "metadata": {
        "technique": "computed_property",
        "dangerous_function": "eval",
        "object": "window",
        "ast_analyzed": "true"
    }
}
```

## Performance

AST analysis is more expensive than regex:

| File Size | Regex | AST |
|-----------|-------|-----|
| 10 KB | ~1ms | ~5ms |
| 100 KB | ~5ms | ~30ms |
| 1 MB | ~50ms | ~300ms |

For this reason, AST analysis is opt-in (`--ast`). Use it when:
- Scanning untrusted third-party code
- Maximum security is required
- Obfuscation is suspected

## Limitations

1. **Dynamic evaluation**: Cannot analyze runtime-generated code
2. **Complex flows**: Deep data flow across files not tracked
3. **Encrypted payloads**: Encoded strings only detected, not decrypted
4. **Python support**: Currently limited compared to JavaScript/TypeScript

## Example Output

```
vetryx scan ./obfuscated-plugin --ast

CRITICAL  AST-EXEC-001  Computed property access to dangerous function
          File: src/loader.js:15
          Snippet: window['eval'](payload)
          Technique: computed_property
          Remediation: Do not use computed access for dangerous functions

CRITICAL  AST-EXEC-002  Variable aliasing of dangerous function
          File: src/util.js:8
          Snippet: const e = eval; ... e(code)
          Technique: variable_aliasing
          Chain: e -> eval
          Remediation: Do not alias eval or similar functions

Found 2 issues (2 critical)
```

## See Also

- [Static Analysis](./static-analysis.md) - Regex-based detection (faster, less comprehensive)
- [Encoding Detection](./encoding-detection.md) - How obfuscated strings are decoded
- [Rules Reference](./rules/reference.md) - All AST rules (AST-EXEC-*, AST-SHELL-*)
