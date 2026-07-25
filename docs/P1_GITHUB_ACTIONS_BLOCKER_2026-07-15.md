# Hosted CI Startup Blocker - Resolved 2026-07-23

## Classification

`RESOLVED - NAMED WORKFLOW AND REAL JOBS PASSED`

This classification replaces earlier wording that attributed the failures to an external GitHub platform issue. That attribution was not proven.

## Confirmed facts

- GitHub Actions is enabled for the repository and the repository action policy reports `allowed_actions: all`.
- Push runs `29472066127` and `29472641620` both ended as `startup_failure`.
- Both runs created zero jobs and exposed an empty workflow name.
- Normalizing the workflow trigger layout did not change the failure.
- The locally reproduced P1 and P2 verification gates are independent of hosted CI and remain evidence-backed.

## Not yet ruled out

- workflow parser or schema annotation failure not exposed by the returned API payloads;
- repository, organization, or enterprise policy inherited outside repository-level settings;
- account, billing, quota, or hosted-runner restrictions;
- reusable-workflow or required-workflow interactions;
- environment or deployment-protection restrictions;
- GitHub API annotations not returned by the available run/job endpoints;
- permission interactions not represented by the repository Actions permission endpoint.

## Required resolution

The blocker is resolved only when a pushed commit creates a named workflow and at least one job, or when GitHub exposes a concrete diagnostic that identifies and corrects the root cause. Tests must not be removed or weakened to obtain a run.

## Resolution evidence

Commit `c27324e4b7e0b147c34cb7c1eea232982cb619e7` created two successful hosted runs of the named
`certification-forge-ci` workflow:

- push run `30045260673`: job `test` passed checkout, Python 3.13 setup, editable dependency install,
  compile, the full deterministic pytest suite with branch coverage, P1 verification, and evidence upload;
- pull-request run `30045263342`: the same real job and all required steps passed.

The retained artifacts are:

- push artifact `8578873146`, digest
  `sha256:3e8c11a0d61b1f7b4e46618b3de55b5766d1e7152b734095d42fb623bb43575e`;
- pull-request artifact `8578871983`, digest
  `sha256:d06747004c1b51cb3e294f91218da3a52e882a5d0eb1bd23c84c5e25948ebfa7`.

Machine-readable evidence is recorded in `artifacts/hosted_ci_resolution.json`. Hosted CI is no
longer a product blocker. This does not upgrade the whole-product verdict, which remains `NOT_READY`.
