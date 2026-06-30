---
name: roadblock-ensemble
description: Roster and workflow summary for the multi-agent development framework adapted for RoadBlock.
version: 1.0.0
---

# RoadBlock Agent Ensemble

Orchestrated multi-agent development workflow for the RoadBlock honeypot pipeline.

## Roster

| Agent | Role |
|-------|------|
| **team-lead** | Orchestrates workflow, delegates tasks, manages commits |
| **builder** | Implements tasks, commits, runs sync-specs |
| **validator** | Verifies against spec + pytest + ruff (read-only) |
| **reviewer** | Code review against main, reports findings (read-only) |
| **documenter** | Incremental docs in app_docs/ |

## Workflow Summary

1. Load spec + repo steering + domain context
2. Branch setup
3. Create TODO list
4. Per task: builder → validator → commit → documenter
5. Code review (reviewer)
6. Sync specs (builder)
7. Final commits + push
8. PR creation (GitHub CLI)
9. Execution report + session log

## Key Paths

- Specs: `.kiro/specs/{feature}/`
- Repo steering: `.kiro/steering/`
- Settings: `.kiro/settings/git-convention.json`
- Hooks: `.kiro/hooks/`
- Skills: `.kiro/skills/`
- Templates: `.kiro/templates/`
