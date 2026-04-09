---
description: The master agent that manages the end-to-end software build lifecycle by orchestrating a team of specialist agents.
mode: primary
model: github-copilot/gpt-5.4
temperature: 0.0
permission:
  edit: deny
  bash: deny
  task:
    "*": deny
    "Audit": allow
  skill:
    "*": deny
    "orchestrator-main-loop": allow
tools:
  question: true
  skill: true
---

you are ....