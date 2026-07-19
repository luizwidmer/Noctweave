# Noctweave Architecture Revision Report

- Date: July 18, 2026
- Branch: `architecture-revision`
- Target: clean Noctweave 1.0 protocol origin

## Executive outcome

The revision changes Noctweave from a profile/inbox-oriented messenger into a
pairwise-private event protocol built around fresh relationship and group
contexts.

The old pre-release architecture is not a migration source. Its identity
profiles, reusable contact offers, global inboxes, destructive mailboxes,
endpoint/device graphs, self-sync records, history-authority transfers, group
registry routes, and permissive relay envelope are removed rather than adapted.

The resulting invariant is:

> A persona is local organization only. Every relationship and group mints
> fresh unlinkable authority, and a relay receives only capability-authorized
> ciphertext routing state.

Definitive references for the resulting baseline:

- [normative architecture](noctweave_architecture_revision_v2.md);
- [identity philosophy](noctweave_identity_philosophy.md);
- [protocol specification](noctweave_protocol_spec_v1.md);
- [group protocol design](group_protocol_design.md);
- [post-revision roadmap](noctweave_roadmap.md).

## Philosophy gate

The revision now treats these as hard protocol constraints:

- no account or provider identity;
- no globally reusable user, persona, endpoint, device, or installation ID;
- no device authorization/revocation graph or primary-device recovery role;
- no persona public key, inbox, relay address, or recovery authority;
- no shared live ratchet or live-key history import;
- no reusable public contact package;
- no server-readable relationship or event metadata beyond opaque routing;
- no silent protocol downgrade or decoder fallback.

Continuity remains possible only as an explicit, locally consented control in
one existing relationship. A local burn creates an unrelated empty persona and
publishes nothing.

## What was replaced

| Removed model | 1.0 replacement | How it works now |
| --- | --- | --- |
| `IdentityProfile` as protocol identity | `PersonaProfileV1` local container | Holds a local label plus relationships/groups; has no key or address. |
| Reusable contact offer/share | `ContactPairingInvitationV2` | Short-lived, one-use rendezvous material only; relationship data is exchanged inside the encrypted session. |
| Global identity generation and endpoint set | `LocalPairwiseIdentityV2` plus one `RelationshipEndpointBindingV4` | Each relationship mints a fresh authority and singular endpoint with a renewable signed prekey. |
| Reusable identity fingerprint | `RelationshipSafetyNumberV2` | A comparison value is derived only from the two disposable relationship-authority signing keys; it cannot correlate either participant elsewhere. |
| Inbox registration and destructive fetch/ack | Opaque route create/append/sync/commit | Separate send/read/renew/teardown capabilities; ordered non-destructive sync with a route-local cursor. |
| Identity-addressed delivery | `OpaqueRoutePacketV2` | Fixed-policy encrypted packets reveal only the opaque route needed by the relay. |
| One envelope ID for every concern | transaction, event, direct-envelope, route-copy, and route-sequence IDs | Local echo, ratchet ciphertext, retries, receipts, and relay ordering have independent meanings. |
| Closed message/control enum | `ConversationEvent`, `EncodedContent`, and `AuthenticatedRelationshipControlV2` | Application content is namespaced/versioned; controls are separately signed and fail closed. |
| Ad-hoc pending send state | `ProtocolIntentV2` plus exact pending packets | The event, intent, and exact ciphertext are durable before publication; retries do not re-encrypt. |
| Public relay location on identity | encrypted `PairwiseRouteSetV2` | A signed route snapshot supports testing, overlap, promotion, draining, and revocation without changing relationship trust. |
| Global continuity/burn archive | local continuity policy and destructive persona replacement | Continuity is peer-selective; burn retains no old live authority or archive record. |
| Self-sync/history authority | none in the live protocol | Local history remains local; a future archive may contain history only and grants no participation authority. |
| Device/client group membership | group-scoped member plus one active credential | Credential replacement is an old-key authorization plus new-key possession proof in one epoch. |
| Monolithic relay request object | exact modular request/response envelope | Request ID, module, version, method, and typed body are correlated and strictly decoded. |

## Pairwise relationship operation

1. An offerer creates a one-use contact rendezvous. Each production participant
   advances its own state machine and exchanges only opaque encrypted frames;
   no helper receives both parties' private pairing state. The JavaScript
   browser flow persists exact outbox frames and resumes independently after a
   restart.
2. Both participants independently create a relationship authority, singular
   endpoint, renewable prekey, pseudonym, and opaque receive route.
3. Introductions are exchanged only inside the PQ-authenticated rendezvous.
4. Both derive the same relationship ID from the transcript and store only
   their local projection. A non-serializable process-local persona-scope token
   minted before asynchronous construction must still match at insertion;
   burn or restart invalidates it without creating a wire identity.
5. A zero-I/O prepare creates one immutable logical event, advances and saves
   its relationship ratchet, encrypts one direct envelope, packetizes it for
   the current peer route set, and atomically persists exact retry bytes,
   delivery projections, and one intent per destination route. The returned
   event is the durable local echo.
6. Each receiver route synchronizes independently. Its cursor advances only
   after every packet is either durably processed or terminally quarantined.
   Verified incomplete fragments and their next cursor are saved atomically so
   reassembly continues across pages and restart. The next local cursor is
   saved before relay commit can authorize garbage collection.

The peer receives append authority and the route payload key needed to send.
Read, renewal, and teardown authority remain local to the route owner.

Endpoint manifests negotiate exact protocol modules, cipher suites, limits, and
content-type major versions. Unsupported outbound content is rejected before
ratchet mutation. Endpoint prekeys renew through an authenticated
relationship-only control and never create persona-wide key material.

Direct-v4 performs one relationship-bound ML-KEM signed-prekey bootstrap and
then advances independent symmetric chains. It does not periodically refresh
the root with PQ key agreement and makes no in-session post-compromise-healing
claim. Reset or a terminal counter gap requires a fresh bootstrap into a new
session.

Live signature, prekey, endpoint, route-set, and control verification uses
throwing PQ APIs. Invalid peer material stays distinct from local algorithm or
runtime unavailability; the latter remains retryable and cannot authorize
cursor advancement.

Client transaction IDs are unique per author relationship handle within the
bounded retained event log. While its event/outbox record remains retained, a
restart can resume the original durable send by transaction or event ID without
creating another event or re-encrypting. Direct sessions and chain state are
persisted per relationship. Publication is counter-ordered per route/session;
N+1 waits while N is unresolved. Retryable failures carry a durable next-attempt
time, while terminal failures remain visible until explicit discard. Discarding
a terminal ratchet gap fails dependent later artifacts and makes the next send
bootstrap a fresh session.

All mutations for one relationship are serialized. A process-wide local
encrypted-state save gate merges independent relationship work against the
latest aggregate,
preventing a later save from clobbering another relationship's newer state.
The store also compares the caller's exact expected prior aggregate before
replacement. A stale client sharing the same store therefore cannot resurrect
a persona or relationship after another client burns it. The independently
anchored generation/ciphertext digest and permanent identity-free erased
tombstone make file rollback, deletion, or unanchored reinitialization fail
closed without becoming protocol identity.

Consent, message-request state, mute, receipt preferences, and block state are
local policy on one relationship. Blocking succeeds locally first, clears
pending sends and live sessions, ignores future inbound application events,
and then attempts route teardown without publishing a global block identity.

## Delivery semantics

Noctweave now distinguishes:

- `locallyPersisted`: durable local event and outbox state;
- `relayAccepted`: the relay accepted the encrypted packets;
- `peerStored`: a peer voluntarily reported durable processing;
- `peerRead`: a peer voluntarily reported a read action.

A socket write, HTTP response, or cursor commit is not a read receipt.

Receive failures have three outcomes: route-chain/cursor/retention or persisted
corruption is route-fatal without page advancement; deterministic peer input is
durably quarantined and advances; storage, network, local-state, or PQ-runtime
unavailability is retryable without advancement. Reassembly pressure evicts and
tombstones the oldest incomplete bundle deterministically and records loss; it
does not synthesize `peerStored` or guarantee reconstruction.

The relay cursor commit and generated receipts, route probes, and route-set
updates are best-effort only after the local page commit. One failed receive
route cannot starve a later healthy route in the same pass; the aggregate sync
fails only when no route succeeds. Receiver-observed time controls freshness;
peer-authored time remains authenticated display/audit metadata.

Pending counts include only retained nonterminal route work. Terminal delivery
artifacts have their own failed count and cannot disappear through retry. A
validly signed envelope from a boundedly retired session is authenticated and
quarantined rather than allowed to wedge ordered route sync; reset sessions are
not silently healed.

## Group operation

Group identity is independent from pairwise relationships. Signed group state
contains group-scoped members, one active credential per member, roles,
permission policy, protocol selection, epoch, transcript, and accepted commit.

The runtime provides:

- signed member admission and removal;
- explicit two-proof credential replacement;
- role hierarchy and last-owner protection;
- complete signed commit/next-state/provider-byte transitions and
  destination-specific welcomes;
- prepared/committed/finalized local crash recovery and atomic peer-epoch
  convergence;
- explicit group-only join anchors rather than self-authorizing welcomes;
- typed immutable group application events with exact content capabilities;
- durable exact-ciphertext application outbox and idempotent retry receipts;
- exact decoding, replay rejection, counter-gap detection, and digest-only
  fork evidence;
- atomic local credential and epoch transition, terminal local removal, and a
  32 MiB aggregate runtime bound;
- exact terminal deletion outbox/inbound persistence, atomic clearing of
  sendable work, conflict/resurrection rejection, and throwing PQ error
  propagation.

Group opaque-route transport is now a durable runtime workflow. Every active
credential announces its own signed group-scoped route set. Exact replay is
idempotent; an immediately following revision must prove the predecessor
digest; after missed revisions, a strictly
newer credential-signed route set may act as a monotonic checkpoint only when
its issue time does not move backwards. Same/older revisions and invalid
direct successors fail closed.

Before relay I/O, the runtime persists recipient authorization snapshots,
fixed-size packets, and per-route attempt state for applications, route
announcements, transitions, Welcomes, and deletion. Every receive route keeps
its own digest-chain cursor, partial reassembly, processed effects, and bounded
quarantine before relay cursor commit. High-level Headless and CLI operations
cover creation, send, sync, maintenance, admission/add/join, exact-operation
resume, and deletion. Admission artifacts remain caller-transported over an
independently authenticated encrypted channel and create no contact, account,
device, or cross-group authority.

The implemented `nw.pq-group.experimental-2` provider is Noctweave-specific,
O(n), bounded to 128 active credentials, and not RFC 9420 MLS.

The persisted aggregate enforces freshness rather than trusting constructors:
relationship IDs, authorities, endpoints, handles, and routes cannot be reused;
group IDs, member/credential handles, admission digests, and signing/agreement
keys cannot overlap another group or any relationship, including across local
personas. Failed upserts leave the prior valid state untouched.

## Tool and app integration

`NoctweaveCLI` exposes the clean protocol directly: one-use pairing, durable
direct send/sync and route maintenance, relationship-local policy and
continuity, explicit persona burn, and the complete experimental group
workflow. Group creation requires an operator-chosen UUID so interrupted work
keeps a stable target for status, maintenance, and exact-operation resume.
Group deletion and full database erasure require
confirmation tokens bound to the lowercase group UUID plus the first 16 hex
characters of SHA-256 over the canonical current signed-group-state encoding,
or to the same short hash over the canonical absolute state path.
Incomplete group publication still emits its structured result but exits
nonzero, distinguishing retry, authorization recovery, relay rejection, and an
invalid relay response for automation. Command-specific option allowlists run
before side effects. State now defaults to the user's Application Support
directory. Bounded descriptor-based private input and no-clobber,
directory-synchronized mode-`0600` output eliminate check-then-open handling
for CLI artifacts.

The browser integration shell now performs durable direct text messaging,
receipt/control processing, ordered synchronization, block/burn, and
make-before-break route maintenance. Its durable state coordinator requires an
independently protected atomic last-value anchor. Static browser storage cannot
provide that authority and fails closed. The authoritative encrypted persona
aggregate is committed through a fixed local application-state slot, while each
relationship retains its own anchor. The slot never enters protocol state and
cannot be selected by a URL or profile alias. Burn advances it through
`active -> burning -> burned`, refuses ordinary unlock during recovery, makes
every relationship terminal, erases aggregate ciphertext, and only then permits
best-effort relay cleanup. The high-level browser service deliberately
rejects attachment publication until attachments have the same exact
prepare/publish/retry journal; integrations may use the lower-level encrypted
blob protocol only when they supply that durability themselves.

On macOS, the Electrobun host supplies scope locks, crash-recoverable encrypted
journals, Keychain-bound committed generations and ciphertext digests, and
permanent erased tombstones for both the aggregate and relationship records.
Plaintext protocol state, message content, and vault keys remain in the
WebView, while opaque local scope metadata is host-visible; this boundary is
rollback protection, not local-host anonymity. The Keychain item detects
rollback or deletion of companion files; it is not a hardware monotonic counter
and does not protect against rollback of the whole Keychain or host. Non-Apple
desktop hosts remain fail-closed until they provide an equivalent independent
last-value authority.

The native reference app integrates group creation, text send/sync,
maintenance, and admission/add/join flows and resumes sync and maintenance on
unlock, foreground entry, and a bounded periodic cadence. It is a reference
product surface, not part of the public integration API; external applications
depend on `NoctweaveCore`, the relay wire, or `NoctweaveJS`.

## Relay and transport operation

The in-process and Linux relays implement the same exact provisional candidate
modules:

- provisional `nw.core@2`;
- provisional `nw.opaque-route@2`;
- provisional `nw.rendezvous-transport@2`;
- provisional `nw.blobs@1`;
- provisional `nw.federation@1`;
- experimental `nw.open-discovery@1`, only when open discovery is enabled.

The exact `nw.opaque-route@2` limit registry is identical in both relays:
68-byte cursors, 256-packet pages, 65,536-byte packets, 1,024 packets per route,
604,800-second retention, and 100,000 routes. Relay info separately reports the
operator's blob default/maximum TTL; the store ceiling is 2,592,000 seconds
(30 days), not six hours.

HTTP, WebSocket, raw TCP, and federation all carry the same strict envelope.
Responses must correlate the complete operation tuple. Linux persists opaque
route lifecycle and ordered packet state in SQLite. The relay does not expose
a plaintext group registry, account endpoint, or GET compatibility health API.
Federation discovers and coordinates relay operators; direct delivery never
forwards a user's message from relay to relay. A sender submits ciphertext
directly to the endpoint in the peer's relationship-encrypted route set.

The pairing transport uses two unlabeled encrypted directional lanes with
separate publish, read, and delete capabilities. The relay persists capability
digests rather than bearer secrets, enforces fixed ciphertext buckets and
ordered sequence rules, and keeps terminal tombstones. The module is disabled
by default and requires TLS or an explicit loopback development endpoint. Every
nested request, response, and persisted object rejects unknown, missing,
malformed, and unbounded fields. Optional fields are present explicitly as
either a value or `null`. This includes opaque-route lifecycle state, encrypted
attachment payloads, federation directories, local message projections, relay
restart snapshots, and their nested cryptographic-context objects. Restored
relay state also re-enforces lifetime/cardinality limits, canonical dictionary
keys, unique attachment indexes, and exact ML-DSA coordinator pins before it is
applied.
Raw JSON is BOM-free UTF-8; a preflight rejects duplicate semantic object
fields (including escaped and canonically equivalent spellings), unpaired
Unicode surrogates, numeric magnitudes that cannot remain finite, and nesting
beyond 128 containers before native decoding.

Opaque-route recovery closes both destructive crash windows. The client saves
verified inbound state and its next cursor before relay commit; if it crashes,
the relay still retains the older prefix. After terminal teardown, a fresh
request authenticated by the last valid teardown authority returns the existing
tombstone, while create, renew, append, and sync remain rejected.

Route rollover is journaled from exact replacement-route creation through
testing advertisement, targeted probe, promotion, overlap, drain, and teardown.
Restart resumes one unfinished rollover, including reconciliation when a probe
was accepted before local promotion. Terminal rollover state requires explicit
discard.

Encrypted blob upload likewise persists an exact request and intent before I/O.
Every chunk uses a 32-byte idempotency key and canonical request digest. An
exact retry for a retained `(attachmentId, chunkIndex)` returns the original
result without extending expiry or rewriting SQLite/IPFS state; any key, body,
or requested-expiry drift is a non-retryable conflict.

Experimental optional wake/prefetch is route-scoped. It contains only opaque
packet records, route-local jitter material, encrypted staging, and deferred
cursor commit. Pull synchronization remains complete without wake
infrastructure.

## Lessons adopted from public protocols

| Source | Adopted | Rejected by the philosophy gate |
| --- | --- | --- |
| XMTP | ordered cursors, durable intents, typed application content, separation of protocol controls | inbox accounts, installation authorization, self-sync authority, managed history assumptions |
| Signal/Sesame | independent cryptographic endpoint/session discipline and no shared ratchet mutation | phone/account graph, primary-device and linked-device model |
| Matrix | local echo, transaction IDs, immutable event relations, retry reconciliation | global user IDs, room state-resolution complexity, server-readable relations |
| XMPP | distinct transport/delivery/read acknowledgements and resumable ordered processing | server-trusted identity/device copying |
| SimpleX | pairwise opaque capabilities, unlinkable routes, make-before-break route change | destructive single-consumer queues as synchronization |
| Waku | versioned protocol modules and capability discovery | GossipSub/content topics as private-message routing |
| Nostr/XMPP extensions | small candidate core, namespaced extensions, lifecycle and conformance evidence | global public keys, broadcast publication, public relay lists |
| MLS | commits, welcomes, epochs, transcript binding, provider boundary | pretending the custom PQ profile is MLS or importing multi-device membership |
| AT Protocol | trust/location separation and staged cutover semantics | global DID and public repository/account migration model |
| Briar | transport-independent event state and optional opaque helper/wake role | mandatory mesh routing or wider contact discovery |

## Removed source surfaces

The revision deletes the old contact/share/trust types; identity profile and
reset/mutation records; inbox and mailbox state; pending direct-delivery type;
global route-set model; relay actor proof; self-sync convergence/transport;
history transfer; endpoint-set/device lifecycle tests; fingerprint mailbox and
legacy group relay tests; and the old direct binding vector.

It also removes the pre-1.0 liboqs 0.15-to-0.16 identity/key migration check
from release verification. Version 1.0 starts at the reviewed 0.16 pin.

## Clean implementation history

The branch keeps the revision as reviewable slices rather than one flattened
change. The prior baseline and current closure are recorded in:

- `cdf4806` — clean Swift relationship, group, route, event, and policy model;
- `a4e488b` — exact Linux/in-process relay and rendezvous transport;
- `d460de8` — JavaScript pairwise 1.0 and browser-service parity;
- `b6a12d5` — compile, credential-validation, retry, and semantic cursor-test
  closure found by the full verification run;
- `b4b7ec4` — relay rendezvous status language aligned with the then-current v2
  manifest;
- `bd46c09` — obsolete generation/identity-service source filenames removed;
- `7218290` — relay module maturity aligned across both manifests before the
  current evidence-based provisional correction;
- `5a040fa` — ambiguous JSON rejected consistently in Swift, Linux relay, and
  JavaScript protocol inputs;
- `2366b63` — Unicode scalar validity and canonically equivalent JSON member
  semantics aligned across implementations;
- `1ece417` — strict JSON checks extended to operator configuration, persisted
  operator policy, and IPFS response boundaries;
- `3f2ea5c` — the last stale private identity-coding helper renamed to
  relationship-authority terminology;
- `401b2b3` — pre-1.0 CLI aliases removed from the definitive command surface;
- `40d75ed` — experimental open discovery separated from candidate federation;
- `9cec9c1` — discovery gateways restricted to one exact response schema;
- `b7d1a94` — JavaScript pairing split into independently resumable participant
  state machines;
- `4034655` — the browser persists only a validated pending pairing offer;
- `bda7be7` — protocol domains and local service names established under the
  Noctweave origin;
- `9de6d83` — operator privacy controls labeled as experimental metadata with
  no implied anonymity claim;
- `db275ef` — the browser surface described honestly as an integration shell;
- `192fda5` — the obsolete pre-1.0 liboqs cross-version compatibility probe
  removed from the release gate;
- `b5f7fe4` — aggregate freshness enforced across relationship, group, and
  persona boundaries;
- `ccc40b2` — message, conversation, and attachment projections made exact and
  structurally bounded;
- `afaf775` — encrypted payload schemas bounded and exact across Swift, relay,
  and JavaScript;
- `cd12964` — focused architecture verification aligned with the clean
  relationship/group philosophy and its aggregate invariants;
- `78e150f` — downstream agent and operator integration guidance rewritten for
  the pairwise baseline;
- `7f2dbc5` — JavaScript relay success objects validated recursively rather
  than only at the outer envelope;
- `deb8db5` — Core relay metadata, capabilities, federation directories, and
  attachment success values made exact and bounded;
- `2bb6e2f` — Core opaque-route wire, cursor, receipt, packet, and replay state
  made recursively exact;
- `5366be6` — group-scoped member and credential handles reject malformed or
  ambiguous persisted forms;
- `ba685f2` — Linux opaque-route runtime and persisted replay state made
  recursively exact;
- `c354870` — JavaScript relay metadata aligned with mandatory explicit-null
  fields;
- `bd5e732` — Linux relay response and capability objects made exact;
- `bbc50c6` — relay snapshots and attachment persistence made exact at every
  nested field boundary;
- `77dba35` — the unused pre-1.0 group `MessageBody` wire discriminator
  removed;
- `4e322f7` — the OpenAPI contract aligned with the exact candidate schema and
  explicit-null rules;
- `b99d179` — JavaScript opaque-route, rendezvous, blob, and federation client
  parity closed, including generic recursive response validation;
- `34646a2` — Core/Linux request DTOs, endpoint values, authentication
  tokens, and federation response sets made structurally exact;
- `3fe9e88` — Linux hidden-retrieval and attachment model bounds aligned with
  Core and JavaScript;
- `a422099` — restored relay state bounded by canonical map keys, active and
  lifetime limits, and exact coordinator pin material;
- `6b392a1` — the focused architecture gate expanded to retain every recursive
  protocol-boundary regression;
- `247823b` — the final JavaScript packet-index and cross-runtime capability-
  limit-key bounds aligned, closing that candidate-wire audit;
- `7a7b041` — pairwise and group protocol state made crash-durable, ordered,
  replay-safe, terminal where required, and strict about local PQ-runtime
  failures;
- `a7cf8d7` — relay, JavaScript, and OpenAPI wire semantics aligned around the
  exact provisional module surface and shared limits;
- `086655d` — architecture, protocol, security, public API, and roadmap
  documentation reconciled with the philosophy-filtered implementation;
- `f7daa82` — explicit throwing group-credential validation and stale-runtime
  error classification corrected after the final compiler gate exposed them;
- `f682bf8` — JavaScript opaque-route receive state made crash-durable;
- `a75c3c7` — the browser rendezvous integration completed;
- `ea48df1` — relay operator controls aligned with the clean protocol;
- `169f7dc` — relationship route maintenance automated;
- `8ecc17d` — the definitive clean-architecture CLI workflows exposed;
- `2d637c4` — group opaque-route fanout made crash-durable;
- `7c95cb5` — read-only route-sync authority exposed without broadening route
  capabilities;
- `f7e53d8` — NCJ-1 made the canonical authenticated JSON profile;
- `15bb358` — production PQ authority/key generation made throwing;
- `26b8acf` — the private ignored research workspace reserved;
- `fd3e025` — durable group transport and admission orchestration completed;
- `849ee02` — exact rollback compare-and-replace, permanent erased anchors,
  group route checkpoints, throwing PQ propagation, and epoch-overflow closure;
- `8a06831` — the direct-v4 root/session derivation frozen as a shared canonical
  Swift/JavaScript vector;
- `ec32c7e` — strict CLI option allowlists, bounded private file I/O,
  target-bound confirmations, and durable group outcomes completed;
- `650a2ed` — durable browser messaging, aggregate and relationship rollback
  anchors, terminal local burn, Electrobun host storage, and application
  integration completed;
- this documentation commit — README, public integration skill, normative
  specifications, security requirements, and this evidence record reconciled.

The separate native Noctyra reference-app repository retains its own clean
companion history: `734ce44` adopts the clean architecture, `583de08` completes
group workflows, `be8cabb` automates protocol maintenance, and `3c1962a`
removes the remaining pre-1.0 identity surfaces.

Earlier commits retain the incremental route, strict-wire, group-runtime, and
pairing work that led to this clean baseline. Obsolete intermediate concepts
remain visible in history but are absent from the 1.0 source and schemas.

## Final verification record

The completed revision passed the following final matrix on 2026-07-18:

- `swift build --package-path NoctweaveCore` — passed;
- `swift test --package-path NoctweaveCore` — 402 tests, zero failures, one
  intentionally opt-in live-TLS test skipped;
- `swift build --package-path NoctweaveRelayServer` — passed;
- `swift test --package-path NoctweaveRelayServer` — 72 tests, zero failures;
- `scripts/run-tests.sh` — passed the 402-test Core suite, 72-test relay suite,
  178-test JavaScript suite, CLI smoke checks, and desktop TypeScript check;
- `scripts/verify-whitepaper-alignment.sh` — passed the focused clean-
  architecture suites and public-boundary checks;
- `scripts/verify-release.sh` — passed package-pin, vendored-liboqs, SBOM,
  dependency-graph, 72-test relay, and Dockerfile checks; Trivy was not
  installed, so its optional vulnerability scan did not run;
- `npm run desktop:build` in `NoctweaveJS` — produced the stable Electrobun
  artifacts using the host disk-image service;
- native Noctyra macOS and generic iOS builds — passed, as did the attachment-
  sanitizer smoke test; the iOS build retains the existing extension/app
  `CFBundleVersion` 6-versus-7 warning;
- the public `noctweave-messaging-relay` AgentSkill validator — passed;
- `git diff --check` — passed after final documentation reconciliation.

Focused coverage includes exact state compare-and-replace after burn,
permanent erased tombstones, zero-I/O prepare/reopen, transaction replay,
per-route/session ordering, retry and explicit discard, local-first cursor
recovery, effect-idempotent teardown, rollover resumption, exact blob
idempotency, group route checkpoints, group convergence, terminal deletion,
epoch-overflow rejection, stale-runtime rejection, throwing PQ-error
propagation, and the shared direct-v4 root/session transcript.

## Remaining engineering and assurance work

The 1.0 architecture semantics and primary protocol/tool workflows are
implemented, but every direct/relay candidate module remains provisional and
the group cryptographic profile remains experimental. Remaining work before
promotion or any production-security claim is finite assurance and product
closure, not another account/device architecture revision:

1. retain the same green matrix as macOS and Linux CI evidence from clean
   checkouts;
2. expand NCJ-1 and the existing shared protocol fixtures into a larger golden-
   vector corpus plus differential/fuzz testing for every signed, hashed,
   encrypted, and strict-decoder boundary;
3. conduct independent direct/group cryptographic, side-channel, zeroization,
   downgrade, forward-secrecy, and post-compromise review; retain the explicit
   direct-v4 healing limits and experimental group label;
4. complete process-termination and injected storage-fault labs for local
   save/anchor replacement, route rollover, cursor commit, group transition,
   admission, deletion, and exact retry;
5. add an independently secured rollback-anchor backend for non-Apple desktop
   hosts; continue to fail closed rather than trusting rollbackable local files;
6. add attachment prepare/publish/retry to the high-level durable browser
   messaging service; keep its current attachment operation fail-closed until
   that journal exists;
7. finish accessible typed-relation, optional-receipt, local moderation, and
   advanced group administration projections across reference clients;
8. run live cross-client interoperability for CLI, Swift, browser/desktop, and
   native reference surfaces, including restart-time group admission recovery;
9. publish reproducible SBOM, dependency, container, checksum, and release
   artifacts with the final exact test evidence.

Optional hidden retrieval, onion, mixnet, mesh, and open-discovery work remains
separate research. None is a prerequisite for the direct protocol, and none is
currently a production anonymity claim.

## Final architectural position

Noctweave 1.0 is not “XMTP with post-quantum keys” and not a private account
system. It is a pairwise-private, post-quantum event system with fresh
unlinkable and disposable relationship contexts, group-scoped credentials,
opaque replaceable routes, strict relay modules, and explicit failure/retry
semantics. The useful state-machine lessons were retained; the stable-account
assumptions were removed.
