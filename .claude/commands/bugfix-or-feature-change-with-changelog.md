---
name: bugfix-or-feature-change-with-changelog
description: Workflow command scaffold for bugfix-or-feature-change-with-changelog in mail-server.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /bugfix-or-feature-change-with-changelog

Use this workflow when working on **bugfix-or-feature-change-with-changelog** in `mail-server`.

## Goal

Implements a bugfix or feature change, always updating the CHANGELOG and one or more source files.

## Common Files

- `CHANGELOG.md`
- `crates/*/src/**/*.rs`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Edit one or more source files to implement fix or feature.
- Update CHANGELOG.md to document the change.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.