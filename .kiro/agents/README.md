# RoadBlock Agent Ensemble

Multi-agent development framework for the RoadBlock honeypot pipeline. Each agent has a specific role and set of permissions to enforce separation of concerns.

## Agents

### team-lead
**Role:** Orchestrator and decision-maker

- Receives user requests and breaks them into delegatable tasks
- Creates branches, manages TODO lists, coordinates workflow
- Delegates implementation to builder, verification to validator
- Owns commit strategy and PR creation
- Formats acceptance criteria in EARS syntax
- Never writes application code directly

### builder
**Role:** Implementation engine

- Executes ONE task at a time from the team-lead's plan
- Writes code, creates files, runs build commands
- Follows steering rules and coding conventions strictly
- Commits after each completed task
- No spec creation, no EARS formatting

### validator
**Role:** Read-only quality gate

- Verifies task completion against acceptance criteria
- Runs pytest, ruff, mypy
- Checks property-based test coverage
- Reports pass/fail with evidence
- Never modifies code or creates files

### reviewer
**Role:** Code review

- Analyzes diffs between current branch and main
- Validates style guide compliance (conventions.md)
- Reports findings with file/line references
- Never modifies code

### documenter
**Role:** Documentation writer

- Generates docs for completed and validated features
- Writes prose documentation only
- No EARS, no code changes, no spec creation

### critic
**Role:** Harsh evaluator

- Reviews implementations against formal spec requirements
- Checks design principles and EARS acceptance criteria
- Provides honest assessment of whether work satisfies specs
- Use when you need a second opinion on quality

### design-system-architect
**Role:** UI/theming specialist

- Design tokens, component libraries, theming infrastructure
- Scalable design operations and multi-brand systems
- Used for dashboard styling and visual architecture decisions

## Workflow

```
User Request
    |
    v
[team-lead] --> creates plan, branches
    |
    v
[builder] --> implements task
    |
    v
[validator] --> verifies against spec
    |
    v
[reviewer] --> code review
    |
    v
[documenter] --> updates docs
    |
    v
[team-lead] --> commits, pushes, creates PR
```

## Files

Each agent has:
- `{name}.json` - Agent configuration (tools, permissions)
- `{name}-prompt.md` - System prompt defining behavior and constraints

Standalone agents (no .json):
- `critic.md` - Inline prompt definition
- `design-system-architect.md` - Inline prompt definition
