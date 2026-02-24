---
description: Run pre-flight checks, bump version, commit, tag, push, and monitor CI
argument-hint: "[patch|minor|major]"
allowed-tools:
  - Read
  - Edit
  - Glob
  - Grep
  - Bash
---

# Release vexscan

You are releasing a new version of vexscan.

## Step 1: Pre-flight checks

Run these sequentially. If any fail, **stop immediately** and report the failure.

```bash
cargo fmt -- --check
```
```bash
cargo clippy -- -D warnings
```
```bash
cargo nextest run
```
```bash
cargo run -- rules test
```

Then verify the working tree is clean:
```bash
git status --porcelain
```
If there are uncommitted changes, stop and tell the user to commit or stash first.

## Step 2: Determine version bump

Read the current version from `Cargo.toml` (the `version = "X.Y.Z"` line).

**If `$ARGUMENTS` is `patch`, `minor`, or `major`:** use that directly. Skip analysis.

**If `$ARGUMENTS` is empty:** analyze the changes since the last git tag to determine the bump type.

```bash
git describe --tags --abbrev=0
```
```bash
git log <last-tag>..HEAD --oneline
```
```bash
git diff <last-tag>..HEAD --stat
```

Read the actual commit diffs if the summary isn't clear enough. Then classify:

- **patch** — bug fixes, formatting fixes, rule pattern tweaks, doc typos, dependency updates, CI fixes
- **minor** — new features, new commands, new detection rules, new output formats, new CLI flags, significant refactors that change behavior
- **major** — breaking CLI changes (removed/renamed flags, changed output format defaults), breaking config file format changes, removed commands

**If you determine `major`:** ask the user for confirmation before proceeding. Explain what breaking changes you found.

**If `patch` or `minor`:** tell the user your reasoning in one line and proceed. Example: "Minor bump — new `check` command and trust store feature since v0.11.0"

Apply the bump:
- `patch` → increment patch
- `minor` → increment minor, reset patch to 0
- `major` → increment major, reset minor and patch to 0

Tell the user: "Releasing **vX.Y.Z** (was A.B.C)"

## Step 3: Bump version

Edit `Cargo.toml` — update the `version = "..."` line to the new version.

Then rebuild to update Cargo.lock:
```bash
cargo build --release
```

## Step 4: Review docs

Read `README.md` and `SKILL.md`. Do a quick sanity check:
- Do they mention features that exist in the current codebase?
- Are there obviously stale sections referencing removed commands or old behavior?

If anything looks stale, tell the user what you found but **do not block the release**. Just note it as a follow-up.

## Step 5: Commit

```bash
git add Cargo.toml Cargo.lock
git commit -m "Bump version to X.Y.Z"
```

Replace X.Y.Z with the actual new version. Do NOT add Co-Authored-By — this is a mechanical version bump.

## Step 6: Tag and push

```bash
git tag vX.Y.Z
git push origin main --follow-tags
```

This triggers the Release workflow (builds binaries for macOS x86/ARM, Linux x86, Windows x86) and the CI workflow.

## Step 7: Monitor CI

Wait for the GitHub Actions runs triggered by this push. Use:
```bash
gh run list --limit 6 --json databaseId,name,status,conclusion,headBranch --jq '.[] | select(.headBranch=="main") | "\(.name): \(.status) \(.conclusion // "running")"'
```

Poll every 30 seconds until all runs complete (up to 10 minutes). Report the final status of each workflow:
- CI (fmt + clippy + test)
- Validate Rules
- Release (binary builds)

If any workflow fails, fetch the failure logs with `gh run view <id> --log-failed` and report the issue.

Finish with a summary: version released, tag pushed, CI status, and any doc staleness notes from step 4.
