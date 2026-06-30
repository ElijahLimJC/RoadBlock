---
inclusion: always
version: 1.0.0
---

# Branching & Commit Convention

## Branch Format
```
<type>/<short-slug>
```

### Types
- `feature` — new functionality
- `fix` — bug fixes
- `chore` — dependency updates, config, non-functional changes
- `test` — test additions/improvements
- `refactor` — code restructuring
- `docs` — documentation only

### Rules
- All lowercase
- Words separated by hyphens
- Max 5 words in slug
- No underscores, no extra suffixes

### Examples
```
feature/email-scam-ingestion
fix/crypto-wallet-validation
chore/update-dependencies
test/persona-property-tests
```

## Commit Message Format

Conventional Commits:
```
<type>: <short description>

[optional body]
```

### Types
- `feat:` — new feature
- `fix:` — bug fix
- `test:` — adding or updating tests
- `refactor:` — code change that neither fixes a bug nor adds a feature
- `docs:` — documentation only
- `chore:` — maintenance tasks

### Rules
- Subject line under 72 characters
- Imperative mood ("add feature" not "added feature")
- One logical change per commit
- Body optional for simple changes
