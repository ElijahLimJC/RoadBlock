---
name: documentation-template
description: Template for app_docs/ files; structure and style to match when creating or updating documentation.
version: 1.0.0
---

# Documentation Template

Template for `app_docs/` files. Match this structure and style when creating or updating documentation.

---

## Structure

```markdown
# [Component Name]

## Overview

[1-2 paragraphs: what this does, why it exists, key constraints. No fluff.]

---

## Files

[List of files involved, grouped by directory]

---

## [Core Concept / Architecture Section]

[Tables, code blocks, or diagrams explaining the main mechanism.
Use whatever format best communicates the design.]

---

## [Detail Sections as needed]

[Each major aspect gets its own section. Examples:
- Validation rules (table format)
- Configuration options (table with key/type/default/purpose)
- Error handling
- IoC types and patterns
- Extraction pipeline stages]

---

## Tests

[Test file paths and what they cover]

---

## Correctness Properties

[Property-based tests and what invariants they verify]
```

---

## Style Rules

- **Concise**: No filler. State what it does, not what it "aims to achieve"
- **Tables over prose**: Use tables for mappings, configs, enums, IoC types
- **Code blocks for structure**: Pipeline stages, regex patterns, file trees
- **One file per component**: `threat-parser.md`, `safety-filter.md`, `persona-engine.md`
- **Flat sections**: H2 for main sections, H3 only when grouping within a section
- **Horizontal rules**: Use `---` between major sections
- **No raw source code dumps**: Show signatures, patterns, and key snippets only

---

## Naming Convention

```
app_docs/<component-name>.md
```

Use kebab-case. Name matches the component/domain, not the ticket or task.

Examples: `threat-parser.md`, `safety-filter.md`, `persona-engine.md`, `soc-dashboard.md`
