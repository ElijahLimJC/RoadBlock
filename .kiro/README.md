# .kiro/ - AI Development Configuration

This directory contains all configuration for the Kiro AI-powered development environment used to build RoadBlock.

## Directory Structure

```
.kiro/
├── agents/       # Custom agent definitions (multi-agent ensemble)
├── hooks/        # Automated triggers that fire on IDE/agent events
├── settings/     # IDE-level configuration (MCP servers)
├── skills/       # Reusable skill definitions
├── specs/        # Feature specifications (requirements + design + tasks)
├── steering/     # Always-on rules injected into every agent session
└── templates/    # Reusable file templates
```

## Agents (`agents/`)

Multi-agent ensemble for structured development. Each agent has a dedicated role:

| Agent | File | Purpose |
|-------|------|---------|
| team-lead | `team-lead.json` | Orchestrates workflow, delegates to other agents, manages branches/commits |
| builder | `builder.json` | Implements code changes, runs one task at a time |
| validator | `validator.json` | Read-only verification against acceptance criteria and tests |
| reviewer | `reviewer.json` | Code review of diffs against main branch |
| documenter | `documenter.json` | Generates documentation for completed features |
| critic | `critic.md` | Evaluates implementations against formal spec requirements |
| design-system-architect | `design-system-architect.md` | Design tokens, theming, component architecture |

## Hooks (`hooks/`)

Agent hooks fire automatically on IDE events. Key hooks:

| Hook | Trigger | Purpose |
|------|---------|---------|
| auto-commit-changes | PostFileSave | Auto-commits meaningful file changes |
| commit-new-file | PostFileCreate | Commits newly created files |
| audit-prompts | PreToolUse | Reviews write operations for safety |
| threat-parser-regression | PostFileSave | Runs parser tests on threat_parser.py changes |
| hypothesis-property-runner | PostFileSave | Runs property-based tests on model changes |
| aws-schema-drift-validator | PostFileSave | Validates AWS model schema consistency |
| classifier-injection-tests | PostFileSave | Tests safety filter on changes |
| concurrency-leak-auditor | PostFileSave | Checks for async resource leaks |

## Steering (`steering/`)

Rules injected into every agent session. These define project norms:

| File | Content |
|------|---------|
| `product.md` | What RoadBlock is, core capabilities, design principles |
| `tech.md` | Tech stack, runtime, common commands, testing strategy |
| `structure.md` | Expected project layout and conventions |
| `conventions.md` | Code style, error handling, async patterns, git workflow |
| `branching-convention.md` | Branch naming and commit message format |
| `ears-reference.md` | EARS syntax for writing testable acceptance criteria |
| `response-preferences.md` | AI response style (concise, honest, no fluff) |
| `agentic-team.md` | Agent separation of concerns |

## Specs (`specs/`)

Feature specifications developed through the Kiro spec workflow:

| Spec | Status |
|------|--------|
| `tarpit-honeypot-pipeline/` | Core pipeline (safety filter, persona, parser, notifications) |
| `email-scam-ingestion/` | IMAP polling, scam classification, auto-reply |
| `fix-default-response-send/` | Bug fix for default response delivery |

## Settings (`settings/`)

- `mcp.json` - MCP (Model Context Protocol) server configurations for IDE-level tool access

## How It Works Together

1. **Steering** files set project-wide rules that every agent follows
2. **Specs** define what to build (requirements -> design -> tasks)
3. **Agents** execute the work (team-lead delegates, builder implements)
4. **Hooks** enforce quality gates automatically (tests, linting, commits)
5. **MCP servers** provide external tool access (TarPit adversary testing)
