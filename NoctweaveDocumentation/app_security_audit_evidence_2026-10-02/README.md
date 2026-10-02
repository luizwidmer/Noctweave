# App security audit evidence — 2 October 2026

This directory contains reviewable machine-readable findings for the eight Git
roots included in the 2 October audit. Each `findings.json` uses the unchanged
`security-audit/report-schema.json`; an empty array means no finding survived
the checks performed in that root, not that the root is vulnerability-free.
Repair state and test outcomes are recorded separately in `repairs.json` where
source was changed. The [owner report](../app_security_audit_2026-10-02.md)
records coverage, gaps, and the difference between source tests and shipped app
behavior.

| Evidence directory | Git root | Starting `main` commit |
| --- | --- | --- |
| `noctweave` | `PICCP Project` | `8dfb8a3021fba1fd35a0548ba1df754dbba69093` |
| `js-client` | `PICCP Project/NoctweaveJS` | `05178661059147bd58f7bc4f5088c69dd4fa497f` |
| `native-client` | `PICCP Project/Noctweave Messaging Client` | `66424fbf0a5726bba1f63dcc4735f4a36378a243` |
| `native-relay` | `PICCP Project/Noctweave Relay` | `b91be30ea1175ed730e3493ad9fdb2695188b20b` |
| `noctcord` | `NoctCord` | `d7afd9d13ba8fa52c4065a2d61f1ac551f298c73` |
| `noctgallery` | `NoctGallery` | `c74a86a2e302ae86386d7ef9dbd5893e647bee5c` |
| `noctboard` | `NoctBoard` | `e0058a50c98762f6884103ea523fc048e9ad1e9c` |
| `noctweave-net` | `noctweave-net` | `6e77f94d847a60e18e92545275b5cb49c6857f47` |

The nonempty records are the public-root [findings](noctweave/findings.json)
and [repairs](noctweave/repairs.json), plus Noctweb Lab's
[candidate](noctweave-net/findings.json) and
[repair](noctweave-net/repairs.json). Each other root has an explicit empty
`findings.json` for the reviewed snapshot.
The public-root record contains six confirmed findings and two
`needs_validation` candidates. The Lab record contains one
`needs_validation` candidate.

The repaired code and skill guidance were published on `main` as Noctweave
`edd7f90a71e2f55dff1055fea7b686475d9af02f`, noctweave-net
`29c8dffb5f92c1ae35a94bbabe23df04f9ec5b4d`, and security-audit-skill
`fce2e9baf571b6cdf8253cce13f0d779d1afadc8`. Remote refs matched these
commits after each push. This evidence status update follows those commits.

The local ignored `.runtime/security-audit-2026-10-02/` directory contains
disposable build output, bounded reproduction material, and run metadata. No
production endpoints, user credentials, or real message data were used.
