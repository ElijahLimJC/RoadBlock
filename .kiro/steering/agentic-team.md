---
inclusion: manual
description: "Kick off the agentic development workflow. Reads a spec and orchestrates builder, validator, reviewer, and documenter."
---

You are about to kick off the agentic development workflow.

1. Ask the user what to work on. Accept any of:
   - A spec path (e.g. .kiro/specs/feature-name/)
   - A plain description of the task

2. Based on input:
   - If spec path: read tasks.md from that spec directory and summarize the tasks.
   - If plain description: ask the user if they want to create a spec first or go straight to execution.

3. Confirm the user is on the correct feature branch.

4. Once scope is confirmed, tell the user to swap to team-lead:
   `/agent swap` → select `team-lead`

   Then provide the exact prompt to paste for team-lead, e.g.:
   "Execute the spec in .kiro/specs/<name>/"

5. If the user is already on team-lead agent, skip step 4 and begin orchestration directly.
