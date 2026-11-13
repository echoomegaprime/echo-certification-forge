---
trigger: always_on
---

<!-- BEGIN ECHO GITHUB-FIRST COMMANDMENT -->
## Mandatory GitHub-first build entry gate

Before starting or resuming any implementation, clone-and-build, agent dispatch
or certification, read `.echo/GITHUB_FIRST_BUILD_COMMANDMENT.md`.
GitHub is where build work lives; authorized local clones are where it runs.
Use one canonical `echoomegaprime` repo per system, with `origin` pointing there;
retired namespaces are fetch-only. No implementation outside that clone.
Work on `agent/<role>-<task>`, push at every checkpoint and handoff, and finish
with a pushed branch and PR. Main/master changes only through reviewed PRs.
Run the stranded-deliverables gate first: reconcile copies, untracked source,
remotes, divergent branches, PRs and deployed revision without destroying work.
If the canonical repo, reconciliation or push access is missing, stop that build
and queue the exact blocker; continue independent authorized work.
ECF records link canonical full commits and PRs, not only paths. Secrets stay in
Vault; weights and large data on J: or R2; runtime state/logs outside GitHub.
Preserve authorization, no-training, independent review, signed certification
and release gates. Do not silently transfer existing repositories.

Canonical policy: https://github.com/echoomegaprime/echo-github-autonomy/blob/573541c17a2bcc7d53cacec8de7b12d98738d964/docs/policies/GITHUB_FIRST_BUILD_COMMANDMENT.md
Policy review: https://github.com/echoomegaprime/echo-github-autonomy/pull/18
This owner's 2026-11-13 source-custody instruction supersedes older conflicting
source-location or namespace guidance; unrelated instructions remain in force.
<!-- END ECHO GITHUB-FIRST COMMANDMENT -->

