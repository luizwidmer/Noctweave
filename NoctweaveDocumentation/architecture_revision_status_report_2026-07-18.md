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
| One envelope ID for every concern | transaction, event, envelope/packet, and route sequence IDs | Local echo, retries, receipts, and relay ordering have independent meanings. |
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
   their local projection.
5. A send creates one immutable logical event, encrypts one direct envelope,
   packetizes it for the current peer route set, and persists exact retry bytes.
6. Each receiver route synchronizes independently. Its cursor advances only
   after packet verification, reassembly, direct decryption, event validation,
   replay recording, and durable state persistence.

The peer receives append authority and the route payload key needed to send.
Read, renewal, and teardown authority remain local to the route owner.

Endpoint manifests negotiate exact protocol modules, cipher suites, limits, and
content-type major versions. Unsupported outbound content is rejected before
ratchet mutation. Endpoint prekeys renew through an authenticated
relationship-only control and never create persona-wide key material.

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

## Group operation

Group identity is independent from pairwise relationships. Signed group state
contains group-scoped members, one active credential per member, roles,
permission policy, protocol selection, epoch, transcript, and accepted commit.

The runtime provides:

- signed member admission and removal;
- explicit two-proof credential replacement;
- role hierarchy and last-owner protection;
- authenticated welcomes and epoch-secret distribution;
- prepared/committed/finalized crash recovery;
- typed immutable group application events with exact content capabilities;
- durable exact-ciphertext application outbox and idempotent retry receipts;
- opaque-route fanout without a plaintext relay group registry;
- exact decoding, replay rejection, counter-gap detection, and fork quarantine;
- atomic local credential and epoch transition.

The implemented `nw.pq-group.experimental-2` provider is Noctweave-specific,
O(n), bounded to 128 active credentials, and not RFC 9420 MLS.

The persisted aggregate enforces freshness rather than trusting constructors:
relationship IDs, authorities, endpoints, handles, and routes cannot be reused;
group IDs, member/credential handles, admission digests, and signing/agreement
keys cannot overlap another group or any relationship, including across local
personas. Failed upserts leave the prior valid state untouched.

## Relay and transport operation

The in-process and Linux relays implement the same exact modules:

- `nw.core@2`;
- `nw.opaque-route@2`;
- `nw.rendezvous-transport@2`;
- `nw.blobs@1`;
- `nw.federation@1`;
- experimental `nw.open-discovery@1`, only when open discovery is enabled.

HTTP, WebSocket, raw TCP, and federation all carry the same strict envelope.
Responses must correlate the complete operation tuple. Linux persists opaque
route lifecycle and ordered packet state in SQLite. The relay does not expose
a plaintext group registry, account endpoint, or GET compatibility health API.
Federation discovers and coordinates relay operators; stable delivery never
forwards a user's message from relay to relay. A sender submits ciphertext
directly to the endpoint in the peer's relationship-encrypted route set.

The pairing transport uses two unlabeled encrypted directional lanes with
separate publish, read, and delete capabilities. The relay persists capability
digests rather than bearer secrets, enforces fixed ciphertext buckets and
ordered sequence rules, and keeps terminal tombstones. The module is disabled
by default and requires TLS or an explicit loopback development endpoint. Every
nested stable request, response, and persisted object rejects unknown, missing,
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
| Nostr/XMPP extensions | small stable core, namespaced extensions, lifecycle and conformance evidence | global public keys, broadcast publication, public relay lists |
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
change. The final architecture closure is recorded in:

- `cdf4806` — clean Swift relationship, group, route, event, and policy model;
- `a4e488b` — exact Linux/in-process relay and rendezvous transport;
- `d460de8` — JavaScript pairwise 1.0 and browser-service parity;
- `b6a12d5` — compile, credential-validation, retry, and semantic cursor-test
  closure found by the full verification run;
- `b4b7ec4` — relay rendezvous status language aligned with the stable v2
  manifest;
- `bd46c09` — obsolete generation/identity-service source filenames removed;
- `7218290` — stable relay module maturity aligned across both manifests;
- `5a040fa` — ambiguous JSON rejected consistently in Swift, Linux relay, and
  JavaScript protocol inputs;
- `2366b63` — Unicode scalar validity and canonically equivalent JSON member
  semantics aligned across implementations;
- `1ece417` — strict JSON checks extended to operator configuration, persisted
  operator policy, and IPFS response boundaries;
- `3f2ea5c` — the last stale private identity-coding helper renamed to
  relationship-authority terminology;
- `401b2b3` — pre-1.0 CLI aliases removed from the definitive command surface;
- `40d75ed` — experimental open discovery separated from stable federation;
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
- `bd5e732` — Linux stable relay response and capability objects made exact;
- `bbc50c6` — relay snapshots and attachment persistence made exact at every
  nested field boundary;
- `77dba35` — the unused pre-1.0 group `MessageBody` wire discriminator
  removed;
- `4e322f7` — the OpenAPI contract aligned with the exact stable schema and
  explicit-null rules;
- `b99d179` — JavaScript opaque-route, rendezvous, blob, and federation client
  parity closed, including generic recursive response validation;
- `34646a2` — stable Core/Linux request DTOs, endpoint values, authentication
  tokens, and federation response sets made structurally exact;
- `3fe9e88` — Linux hidden-retrieval and attachment model bounds aligned with
  Core and JavaScript;
- `a422099` — restored relay state bounded by canonical map keys, active and
  lifetime limits, and exact coordinator pin material;
- `6b392a1` — the focused architecture gate expanded to retain every recursive
  protocol-boundary regression;
- `247823b` — the final JavaScript packet-index and cross-runtime capability-
  limit-key bounds aligned, closing the stable-wire audit.

Earlier commits retain the incremental route, strict-wire, group-runtime, and
pairing work that led to this clean baseline. Obsolete intermediate concepts
remain visible in history but are absent from the 1.0 source and schemas.

## Verification evidence

Final evidence recorded on July 18, 2026:

- `swift build --package-path NoctweaveCore`: passed;
- `swift test --package-path NoctweaveCore`: 295 tests executed, one intentional
  skip, zero failures;
- `swift build --package-path NoctweaveRelayServer`: passed;
- `swift test --package-path NoctweaveRelayServer`: 65/65 passed;
- `scripts/run-tests.sh`: passed the Core, relay, JavaScript, and desktop
  TypeScript gates together;
- packaged `NoctweaveCLI` help plus live loopback `health` and `info` against
  the Linux relay's `/relay` endpoint: passed;
- `npm test --prefix NoctweaveJS`: 114/114 passed;
- `npm run typecheck:desktop --prefix NoctweaveJS`: passed;
- `scripts/verify-whitepaper-alignment.sh`: passed the focused architecture,
  public-boundary, and release-scope checks;
- `scripts/verify-release.sh`: passed dependency pins, reproducible SBOMs,
  relay tests, and Dockerfile syntax validation; Trivy was not installed and
  was explicitly skipped;
- OpenAPI YAML: 87 schemas and 164 local references parsed and resolved;
- all relative Markdown documentation links resolve and the three revised SVG
  architecture assets pass XML validation;
- all edited Swift source/test files passed syntax parsing and the full diff
  passed whitespace/error checks.

A final read-only cross-runtime audit found no remaining recursive exactness,
bound, or explicit-null divergence in the stable relay wire or restored relay
state.

The macOS relay build emits a deployment-target warning because the locally
installed Homebrew SQLite library targets a newer macOS version. It does not
change the successful build/test result, but release artifacts must use the
documented Linux/Docker toolchain rather than this local linkage.

## Remaining engineering and assurance work

The architecture is closed; the remaining work is product surface and assurance
before a production-security claim:

1. retain the complete green suite as macOS and Linux CI evidence from a clean
   checkout;
2. expose the implemented pairing, relationship-policy, message-request,
   safety-number, receipt, route-rollover, and teardown flows consistently in
   the CLI and end-user reference clients;
3. complete automatic route drain/teardown cleanup after the implemented
   create, advertise-as-testing, targeted-probe, promote, and overlap flow;
4. replace sorted-JSON signing inputs with an explicitly specified
   cross-language canonical representation, or prove every signing byte in an
   independent implementation;
5. add shared Swift/JavaScript golden vectors and differential/fuzz testing for
   every strict decoder;
6. conduct independent direct/group cryptographic, side-channel, zeroization,
   downgrade, forward-secrecy, and post-compromise review;
7. complete process-termination, storage-fault, route rollover, and group epoch
   recovery labs;
8. publish reproducible SBOM, dependency, container, and release artifacts;
9. complete accessible UI projections for typed relations, optional receipts,
   group governance, and local moderation state.

Optional hidden retrieval, onion, mixnet, mesh, and open-discovery work remains
separate research. None is a prerequisite for the direct protocol, and none is
currently a production anonymity claim.

## Final architectural position

Noctweave 1.0 is not “XMTP with post-quantum keys” and not a private account
system. It is a pairwise-private, post-quantum event system with fresh
relationship contexts, group-scoped credentials, opaque replaceable routes,
strict relay modules, and explicit failure/retry semantics. The useful state
machine lessons were retained; the stable-account assumptions were removed.
