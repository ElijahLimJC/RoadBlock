---
name: sync-specs
description: Update spec files (requirements.md, design.md, tasks.md) to match the current state of the code
license: MIT
compatibility: kiro
metadata:
  workflow: git
  audience: developers
---

## What I do

I review all code changes on the current branch and update the corresponding spec files in `.kiro/specs/` so they accurately reflect what the code actually does.

## When to use me

Activate phrases:
- "update the specs"
- "sync the specs"
- "refresh the specs"
- "specs are out of date"
- "bring specs up to date"
- "reconcile specs with code"

## How I work

### Step 1: Identify the spec directory

Use the spec directory path provided by team-lead, or search `.kiro/specs/` for the matching feature directory.

### Step 2: Read existing spec files

Read whichever of these files exist in the spec directory:
- `requirements.md`
- `design.md`
- `tasks.md`

### Step 3: Get the code changes

```bash
git diff main... -- ':!.kiro' ':!.hypothesis'
```

If the diff is very large, also get the file list:
```bash
git diff main... --name-only -- ':!.kiro' ':!.hypothesis'
```

### Step 4: Compare code to specs and update

For each spec file that exists:
1. Compare what the code actually does against what the spec describes
2. Identify discrepancies
3. Update the spec file to accurately describe the current code behavior

Changes include:
- Updating descriptions to match actual implementation details
- Adding new requirements/design sections for unspecced functionality
- Marking or removing items that were descoped
- Updating task completion status in `tasks.md`
- Correcting technical details (component names, file paths, etc.)

### Step 5: Present a summary

Brief summary of what changed in each spec file and why.

## Constraints

- Only modify files inside `.kiro/specs/` — never application code
- Preserve existing formatting conventions
- **NEVER run git commands that modify state** (read-only only)
