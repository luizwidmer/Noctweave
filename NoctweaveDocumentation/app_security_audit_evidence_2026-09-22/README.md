# Evidence index — 22 September 2026

This directory supports the [app security audit](../app_security_audit_2026-09-22.md).
It records eight confirmed findings and two separate hardening changes. It does
not claim exhaustive coverage or upstream hostile-source sandbox compliance.

## Repository records

| Git root | Findings | Repairs and limitations |
| --- | --- | --- |
| Noctweave root | [findings.json](noctweave/findings.json) — empty; shared TURN issue counted once below | [repairs.json](noctweave/repairs.json) |
| Native messaging client | [findings.json](native-client/findings.json) — one | [repairs.json](native-client/repairs.json) |
| Native relay | [findings.json](native-relay/findings.json) — one, including related Docker configuration | [repairs.json](native-relay/repairs.json) |
| NoctweaveJS | [findings.json](js-client/findings.json) — two | [repairs.json](js-client/repairs.json) |
| NoctCord | [findings.json](noctcord/findings.json) — one | [repairs.json](noctcord/repairs.json) |
| Noctweave Net | [findings.json](noctweave-net/findings.json) — three | [repairs.json](noctweave-net/repairs.json) |

[run.json](run.json) records starting commits, relative Git roots, workflow and
SHA-256 hashes of changed source, tests and related app documentation. Audit
report files are omitted from that source manifest to avoid recursive hashes.
At audit completion, application patches were uncommitted; these evidence records
preserve that pre-commit snapshot. The starting commit is not a repaired ref.
Consult each repository's Git history for the published repair commit.

Each findings array uses the unchanged Cloudflare `report-schema.json` and was
checked with its `validate-findings.cjs`. Repair status is deliberately recorded
separately. Trace line numbers refer to the recorded vulnerable commit. Evidence
entries distinguish newly added regression fixtures and local run output from
that original source. Schema validation establishes structure, not proof of
exploitability or completeness.

## Checks and retained evidence

- [validation.json](validation.json) summarizes the actual test and build outcomes,
  independent review, skipped checks and environment failures.
- [dependency-checks.json](dependency-checks.json) records the two Bun advisory
  checks and their coverage limit.
- [secret-scan-summary.json](secret-scan-summary.json) contains redacted triage
  metadata for all 84 matches. Its numeric path prefixes map to `noctweave` (0),
  `native-client` (1), `native-relay` (2), `noctweavejs` (3), `noctcord` (4) and
  `noctweave-net` (5).
- [local-evidence-manifest.json](local-evidence-manifest.json) records hashes of
  selected local logs. Those files remain in the named repository's ignored
  evidence directory; they are unavailable in a fresh clone of this report.
- [skill-fork.json](skill-fork.json) records the separately published and installed
  skill revision, upstream base, validation and independent workflow review.

The original NoctCord owner/self reproduction log was retained, but its test
function was replaced by the stronger two-member regression without saving an
exact source copy. This limits exact replay of that historical fixture. The
vulnerable coordinator remains available at the recorded Git ref; the current
two-member regression and its passing log are retained. No original cross-member
execution or media interception is claimed.

Reproduction commands in repair records assume the reviewed local toolchain and
dependencies. `<noctweave-workspace>` denotes the root checkout from `run.json`.
Use the repository's command wrapper and local caches. Do not run against real
credentials or production services. Baseline comparisons must use a disposable
copy of the recorded source rather than overwrite a user's current worktree.

No raw credentials, disposable signing keys, plaintext messages, full fixture
directories, private agent guides or generated build products are published here.
