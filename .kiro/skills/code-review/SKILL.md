---
name: code-review
description: Comprehensive code review of changes between current branch and main
license: MIT
compatibility: kiro
metadata:
  workflow: git
  audience: developers
---

## What I do

I perform a comprehensive code review of changes between the current branch and a target branch (defaults to main). I analyze the full diff holistically for logic errors, style guide violations, and code quality issues.

## When to use me

Use this skill when you want to perform a code review before creating a pull request.

## How I work

### Step 1: Determine target branch

Default is `main`. If team-lead specifies a different branch, use that.

### Step 2: Get the git diff

```bash
git diff main... -- ':!.kiro' ':!.hypothesis'
```

### Step 3: Get changed file list

```bash
git diff main... --name-only -- ':!.kiro' ':!.hypothesis'
```

### Step 4: Review the full diff

Analyze the complete diff as one unit. Evaluate against:

**Style guide checks (Python/RoadBlock):**
- Type hints on all function signatures
- Pydantic v2 patterns (field_validator, ConfigDict)
- Google-style docstrings on public functions
- Max line length 100 (ruff)
- Snake_case functions/variables, PascalCase classes
- Exception isolation in parsers (try/except wrapping)
- No global mutable state outside st.session_state

**Quality checks:**
- Logic errors, bugs, potential runtime issues
- Missing error handling or edge cases
- Cross-file consistency (imports, shared types)
- Security issues (unsanitized scammer input reaching LLM)
- Missing property-based tests for new extraction logic
- Prompt injection vectors in persona engine changes

If the diff is too large, read individual files with `git show HEAD:<file-path>`.

### Step 5: Compile findings

Collect all findings into the structured report format.

### Step 6: Present results

```
## Code Review Report

**Branch**: [branch name]
**Compared Against**: main
**Files Reviewed**: [count]

### Findings

| # | File | Line | Severity | Description |
|---|------|------|----------|-------------|
| 1 | path/file.py | 45 | error | [what's wrong and how to fix] |

### Summary

**Errors**: [count] (must fix)
**Warnings**: [count] (should fix)
**Clean**: [yes/no]
```

## Severity Levels

- **error** — Must fix: logic bugs, security issues, broken functionality
- **warning** — Should fix: style violations, missing error handling, test gaps

## Constraints

- Default comparison branch is `main`
- Excludes .kiro/ and .hypothesis/ directories
- **NEVER run git commands that modify state**
- Git usage limited to read-only: diff, log, show, branch, rev-parse, status
- Review is holistic (full diff as one unit)
