# /vexscan:vet

Vet a plugin before installation - scan from GitHub URL or local path.

**Runs as a subagent to keep your main conversation clean.**

## Usage

```
/vexscan:vet <source>
```

## Examples

- `/vexscan:vet https://github.com/user/claude-plugin` - Vet from GitHub
- `/vexscan:vet ./downloaded-plugin` - Vet local directory

## Verdicts

- **SAFE** - No issues found, safe to install
- **CAUTION** - Minor issues found, review before installing
- **RISKY** - Serious issues, install only if you trust the author
- **DANGEROUS** - Critical issues found, do not install

## Instructions

**IMPORTANT: Always run this as a Task subagent to avoid polluting the main context.**

When the user wants to vet a plugin before installing:

1. Use the **Task tool** to spawn a subagent with the following configuration:
   - `subagent_type`: "general-purpose"
   - `description`: "Vet plugin security"
   - `prompt`: See below

2. The subagent will:
   - Clone the repo (if GitHub URL) or access the local path
   - Run a comprehensive security scan
   - Analyze each finding with AI reasoning
   - Provide a verdict with justification

3. Report the **verdict and key findings** to the user

### Task Prompt Template

```
Vet a plugin for security issues before installation.

**Source:** ${SOURCE}

**Step 1: Run the vet command**
\`\`\`bash
vexscan vet "${SOURCE}" --skip-deps -f json
\`\`\`

**Step 2: Deep analysis**
For each finding:
- Read the actual code/content that triggered the finding
- Determine if it's genuinely malicious or a false positive
- Consider the context (is eval() used safely? is the webhook legitimate?)

**Step 3: Provide verdict**

Return a structured response:

## Verdict: [SAFE|CAUTION|RISKY|DANGEROUS]

### Summary
- Files scanned: N
- Real threats: N (list severities)
- False positives filtered: N

### Key Findings (if any)
For each real threat:
- What: Brief description
- Where: File and line
- Risk: Why this is dangerous
- Evidence: The suspicious code snippet

### Recommendation
Clear guidance on whether to install this plugin.

**Be thorough but concise. The user needs actionable information.**
```

Replace `${SOURCE}` with the GitHub URL or local path provided by the user.
