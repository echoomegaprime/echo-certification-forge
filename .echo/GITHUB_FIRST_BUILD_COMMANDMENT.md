# ECHO commandment: GitHub is where work lives

**GitHub is the only place build work is allowed to live, not necessarily the
only place it runs.** Local clones on FORGE, ANVIL, QUENCH and other authorized
nodes are execution workspaces. Every build starts from one canonical repository
in the `echoomegaprime` namespace and ends as a pushed branch and pull request.

1. One canonical repository per system. Every node's `origin` points to it.
   Retired owners and repositories are fetch-only; never silently re-home a
   system or create a competing canonical repository.
2. No implementation outside a clone. Locate and verify the canonical repository
   first. If it or push access is missing, stop the affected build, queue the
   exact blocker in GitHub, and continue independent authorized work.
3. Each agent owns an `agent/<role>-<task>` branch. Push at every meaningful
   checkpoint and handoff. Verify the remote commit before claiming preservation.
4. Change `main`/`master` only through reviewed PRs. Run the stranded-deliverables
   gate before clone-and-build, integration, certification, or deployment:
   inventory local copies, untracked source, remotes, divergent branches, existing
   PRs and deployed revision; compare them; link the reconciliation decision to
   commits/PRs; hold unresolved divergence. Never delete or overwrite stranded work.
5. Continuity Fabric records reference canonical repository, full commit SHA,
   branch and PR, with evidence digests. Local paths may describe execution but
   are never the sole record or source of truth.
6. Keep secrets in Vault. Keep model weights and large data on J: or R2. Keep
   runtime state, caches and logs outside versioned source. Record safe artifact
   references and digests. Generated deployment copies are traceable artifacts;
   they must never become an alternate authoring source.

Apply this before planning implementation, dispatching another AI, resuming work,
or certifying a build. Preserve existing permissions, independent reviews and
release gates. This commandment grants no new credentials or release authority.

The requested first migration is Finisher: reconcile the live Cloudflare line,
the QUENCH `lyra-finisher` clone and PR #1041 before choosing a release candidate.
The supplied divergence counts for Swarm brain, fleet roles and ticket #34269
are migration leads, not newly verified inventory.
