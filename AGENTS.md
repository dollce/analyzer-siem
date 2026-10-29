# Project instructions

## Purpose and scope

This repository provides an on-demand Docker Compose Elastic Security analysis lab.
Keep the root `builder.py` entry point, matching pinned Elastic Stack versions,
explicit Basic/Trial licensing, file-based Logstash ingestion, and disposable lifecycle.
Stack upgrades must never happen automatically; notify the operator about new stable
versions and let them choose when to rebuild.

## Repository delivery authorization

The project owner authorizes autonomous commits, pushes, pull requests, merges,
and version tags for requested development work in
`https://github.com/dollce/analyzer-siem.git`. The canonical branch is `master`.
Use `dev/` feature branches and a pull request for implementation changes.
Do not ask again for routine repository-delivery approval.

When creating a development PR, invoke the `pr-delivery` skill and a NEW dedicated
`pr_delivery` reviewer with `fork_turns="none"` and no inherited conversation or
memories. Pass only PR identity, checkout, original requirements, and current human
authorization. Never include author rationale, previous findings, or test claims.
The author fixes actionable findings. Each changed head or base needs a fresh reviewer.
Merge after successful independent review and checks, without bypassing protections.
Observe checks on the merge commit. If the skill/role is unavailable, report the
specific limitation instead of substituting self-review.

Tag reviewed releases by the pinned Elastic version: `elastic-vX.Y.Z` for the first
release on a Stack version, then `elastic-vX.Y.Z-r2`, `-r3`, etc. for subsequent
project revisions using that version. Use annotated tags on merged `master` commits.
Never move an existing published tag or force-push shared history.

This repository is public. Commit reusable code, configuration examples, tests,
CI and user-facing documentation only. Exclude credentials, `.env`, source logs,
downloaded Labs content, generated certificates/state, local execution records,
and workstation/account details. Do not invent a license for the owner's code.

## Runtime boundary

Repository-delivery authorization does not authorize starting a SIEM, initializing
a lab, enabling/deploying detection rules, or ingesting runtime fixtures or logs.
Do not request a lab target to complete a code review or compensate for a no-op job.
Only a separate direct operational request authorizes those actions.
Never reset licensing state to bypass upstream Trial eligibility.

## Validation

Run `python3 builder.py check` for Compose and unit validation, and
`bash scripts/check_logstash.sh` when changing the Logstash pipeline. The latter
uses an isolated container with no network or input logs. CI is validation only.
Keep documentation clear about static/mocked checks versus actual SIEM runtime
validation, and preserve original logs on both stop and destroy operations.
