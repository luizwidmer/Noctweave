# NoctCord test performance follow-up — 2026-09-30

The full NoctCord gate fell from **661.331 to 331.952 seconds**, a **49.81%
reduction**, on the current M4 machine. The three-member exchange fell from
370.835 to 182.518 seconds. Both serial runs passed the same 94 case identities
with the same single opt-in skip. No slow test, integrity check, durable
readback or fresh fixture was removed. The rejected concurrency experiments
remain reverted.

The retained change optimizes NoctweaveCore's existing JSON implementation.
It preserves NCJ-1 canonical bytes and the existing strict decoding checks.
NoctCord's test assertions and scenario bodies are byte-identical to the
baseline apart from its logging helper, which now timestamps existing markers
at their source. No dependency pin, signing setting, app version, branch or
publication state changed in this pass. Changes remain uncommitted.

## Equivalent end-to-end measurements

Both runs used the same local public Core dependency override, normal Debug
configuration, explicit SwiftPM `swiftbuild` backend and strict cached
dependency resolution. Each ran the complete serial suite. Builds were warmed
before both measurements; their incremental builds took 0.29 and 0.31 seconds.
Other owned compilation/test workloads were not run concurrently with these
gate measurements. The fixture roots, relay ports, credentials, admissions and
transport state were freshly created by the unchanged scenarios.

| Gate or scenario | Before | After | Time saved |
| --- | ---: | ---: | ---: |
| Complete NoctCord gate, wall time | 661.331 s | 331.952 s | 329.379 s / 49.81% |
| Three-member state, attachment and realtime exchange | 370.835 s | 182.518 s | 188.317 s |
| Member leave and owner destruction with retained records | 117.254 s | 58.980 s | 58.274 s |
| Invitation admission through malicious member history | 101.108 s | 52.696 s | 48.412 s |
| Realtime admission with durable join refresh | 62.846 s | 31.993 s | 30.853 s |

These are single complete before/after comparisons, not a statistical
performance guarantee. They demonstrate a meaningful improvement for this
workload on the existing machine; they do not predict another Mac's speed or
the cost of unrelated application builds. A later sampled admission run also
passed; its profiling overhead is excluded from this comparison.

Reproduce the local gate from the NoctCord checkout with:

```sh
NOCTWEAVE_PACKAGE_PATH="/Users/luiz/Desktop/Projects/PICCP Project" \
  swift test --disable-automatic-resolution --build-system swiftbuild
```

NoctCord's default immutable remote revision remains unchanged. The measured
improvement uses the local optimized Core source through its existing explicit
override. A future publication and consumer pin update are separate work; no
automatic local-path fallback was introduced.

## Function evidence and implementation

Earlier stacks showed state persistence repeatedly encoding, preflighting and
decoding deep protocol state. A separate deterministic 1,011,215-byte fixture
isolated the expensive JSON stages without caching protocol validation or
reusing integration credentials. Five repetitions per stage, built with
`swiftc -Onone -DDEBUG`, produced these medians:

| JSON stage | Before | Retained candidate | Ratio |
| --- | ---: | ---: | ---: |
| Strict input preflight | 23.967 ms | 5.498 ms | 4.36× faster |
| Canonical tree output | 34.791 ms | 5.328 ms | 6.53× faster |
| Complete canonicalization | 59.984 ms | 11.747 ms | 5.11× faster |
| Sorted encoding, including transport encoding | 61.923 ms | 13.642 ms | 4.54× faster |
| Decode including strict preflight | 24.685 ms | 5.738 ms | 4.30× faster |

The canonical outputs have identical SHA-256 digests before and after. These
synthetic function ratios are distinct from the measured full-suite result.
Unchanged Foundation transport encoding and JSON tree conversion were also
measured; no speedup is claimed for them.

The implementation:

- Copies unescaped UTF-8 runs into canonical output instead of constructing a
  temporary Swift string for each Unicode scalar. NFC normalization, UTF-8 key
  ordering, control escaping and safe-integer rejection remain in place.
- Borrows input bytes synchronously inside `Data.withUnsafeBytes`, replacing
  the preflight parser's complete plaintext `[UInt8]` copy. The private parser
  and its pointers never escape that closure.
- Scans unescaped string runs without a per-byte captured-key append. Quotes,
  escapes, raw controls, malformed surrogates, duplicate keys and nesting depth
  are still checked. Literal bounds use subtraction before forming a range to
  avoid an unnecessary potentially overflowing addition.
- Reserves at most 64 KiB initially for canonical output, avoiding a reservation
  proportional to a large whitespace-heavy input.

An initial indexed `for` loop made canonical output slower. Its measurements
are preserved as `json-candidate-for-index-rejected.json`; that implementation
was rejected before applying the retained candidate. The bounded `while` loop
was measured and then validated in the real gate.

`ClientState.swift` and `ClientStateStore.swift` retain their baseline bytes.
There is no validation-result cache, shared signing authority, reused admission
fixture, crypto downgrade, altered transaction fence or removed state-file
decode. Encryption, rollback anchors, expected-state comparison and durable
readback retain their existing implementation.

## Correctness and memory safety

| Check | Result |
| --- | --- |
| Canonical vectors, strict preflight and new UTF-8/storage tests | 14 passed |
| Full Core suite | 557 cases, 2 existing opt-in skips, no failures; exit 0 |
| Full relay suite | 151 cases, no failures; exit 0 |
| Complete NoctCord suite | Same 94 identities and results as baseline; 1 existing opt-in skip; exit 0 |
| Address Sanitizer corpus | 2,332 inputs; no sanitizer failure; identical old/new canonical outputs and acceptance/rejection transcript |

The focused cases include all C0 controls, Unicode scalar boundaries, empty
strings, long base64-like strings, bridged strings, NFC normalization, every
truncated prefix of escaped JSON, nonzero-index Data slices, malformed UTF-8,
invalid escapes, surrogate pairs and duplicate keys. The sanitizer corpus also
includes deterministic random bytes and nesting-depth boundaries. Existing
signed state, restart, admission, message, duress, rollback and parser security
regressions ran in the complete suites.

The change removes one full plaintext preflight copy and many temporary scalar
strings. It does not establish complete memory zeroization or a measured
peak-memory reduction. A diagnostic process snapshot remains evidence of a
snapshot, not a memory benchmark.

## Remaining bottlenecks and timing discipline

SwiftPM buffers XCTest output. Collector receipt timestamps from the baseline
cannot measure individual phases and are explicitly marked unusable. Existing
NoctCord markers now include a monotonic timestamp captured in the test, so
their deltas remain valid even when received together later. Reliable serial
XCTest case durations and process wall time are used for before/after results.

After optimization, the three-member scenario still spends 55.207 seconds
publishing/synchronizing voice joins and 34.761 seconds synchronizing initial
space state. The invitation scenario spends 33.560 seconds between accepting
the admission response and finishing bootstrap synchronization. The subsequent
bootstrap stack sample still traverses `ClientStateStore.save`, expected-state
matching, `ClientState`/persona/group-runtime decoding and structural/credential
validation. Its leading active leaf functions are strict string scanning and
canonical UTF-8 output; Foundation JSON strings, metadata lookups and signing
verification also appear. This sample does not quantify each operation's share
of total gate time or establish key decoding as the dominant cost.

Further reductions should target those measured nested serialization and
validation paths while retaining their security checks. No speculative
validation memoization or fixture reuse was retained here. Electrobun app
signing/distribution remains a separate backlog and did not block this work.

## Evidence and scope

Commands, source snapshots, logs, timings, function results, the sanitizer
corpus, call stacks and comparisons are retained locally in
[`ReleaseArtifacts/TestPerformanceFollowup-2026-09-30/`](../ReleaseArtifacts/TestPerformanceFollowup-2026-09-30/).
That directory is ignored by Git. Key records are `cord-comparison.json`,
`cord-full-before.json`, `cord-full-after.json`, `core-full-after.json`,
`relay-full-after.json`, `json-before.json`, `json-candidate.json`,
`corpus-before.json`, `corpus-candidate-asan.json` and
`cord-bootstrap-profile-sample-1.txt`.

Final hashes and repository statuses record the exact retained scope and
preservation of unrelated prior audit/Electrobun changes. Existing selected
`main` branches and all eight repository HEADs remain unchanged. There was no
commit, push, dependency upgrade, security-setting change or publication.
