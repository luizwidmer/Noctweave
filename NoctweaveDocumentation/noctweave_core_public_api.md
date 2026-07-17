# NoctweaveCore Public API Notes

`NoctweaveCore` is the shared Swift package for protocol implementers and Noctyra tooling. The package is not yet source-stability frozen, but public APIs should now be treated as candidate library surface rather than app-private implementation detail. Stability rules are defined in `noctweave_core_stability_policy.md`.

Noctweave 1.0 is a clean protocol origin. Pre-1.0 persisted and wire formats
are rejected; the production API does not carry decoders, upgrade paths, or
runtime fallbacks for research-era state.

The current pre-1.0 direction is documented in
[`noctweave_architecture_revision_v2.md`](noctweave_architecture_revision_v2.md).
Architecture v2 is being integrated in layers; public type availability alone
does not imply that a model is active on the relay wire.

## Package Products

- `NoctweaveCore`: protocol models, cryptographic wrappers, relay client/server primitives, messaging state, groups, federation, and metadata-reduction helpers.
- `NoctweaveCLI`: command-line diagnostics and headless messaging client.
- `NoctweaveCoreTestHarness`: local protocol harness for development verification.
- `NoctweaveJS`: JavaScript ESM protocol library, working browser direct-message client, relay request helpers, and encrypted web/database storage adapters.

## Client-Facing APIs

- `HeadlessMessagingClient`: persistent headless identity, contact, send,
  receive, register, contact-share, attachment, and voice-message
  workflows. Direct `receive(...)` uses an endpoint-owned mailbox consumer,
  ordered sync, and a cursor commit persisted after message state. The
  `acknowledge` argument controls whether that durable cursor is committed.
- `retryPendingDirectDeliveries(maxCount:)`: retries the original sealed direct
  envelope from the ciphertext outbox and returns the number accepted during
  this call. It preserves the signed envelope ID and uses the durable intent
  record; it does not re-encrypt under an already advanced ratchet. The bounded
  outbox applies backpressure at capacity and never truncates pending
  ciphertext or its live intent. A permanent relay rejection or exhausted
  attempt budget reports `directDeliveryRequiresAction` instead of spinning or
  silently abandoning the ciphertext.
- `rearmPendingDirectDelivery(envelopeId:)`: explicitly rearms the durable
  intent for an action-required direct delivery while preserving its intent ID,
  idempotency key, payload digest, and original sealed envelope. It does not
  authorize re-encryption or a new ratchet step.
- `HeadlessIdentityChangeResult`: structured result for same-generation
  authority rotation and full identity-burn operations.
- `HeadlessContinuityAudit` and `HeadlessContinuityAuditPurgeResult`: structured inspection and purge results for active-identity continuity events.
- `HeadlessMessagingClient.rotateIdentity(preservingContinuityWith:)`: requires
  an explicit, bounded set of contact UUIDs; `[]` explicitly discloses the
  old-key-authenticated rotation statement to nobody. Only selected contacts
  receive continuity, unknown IDs fail closed, and a resumed durable rotation
  must use the exact same set. Rotation remains an in-generation authority
  change; use burn, not an empty rotation selection, when unlinkability and
  route teardown are required.
- `HeadlessSentAttachment` and `HeadlessFetchedAttachment`: headless direct/group attachment and voice-message transfer results.
- `ClientState` and `ClientStateStore`: codable local state and optional platform encryption wrapper.
- `Identity`, `IdentityProfile`, `Contact`, `Conversation`, and `Message`: core client state models. Production identity and key creation should use the throwing `generate(...)` APIs so unavailable PQ algorithms or entropy failures can be handled without terminating a process.
- `MessageEngine`: direct-message session creation, encryption, decryption, root ratchet, and message appending.
- `RendezvousOfferV2`, `PendingRendezvousOfferV2`, and `RendezvousSessionV2`:
  one-use, expiring, purpose-bound PQ pairing foundations. Client pairing
  integration remains unfinished.

## Architecture-v2 Swift APIs

The following v2 foundations are active in persisted state or direct mailbox
delivery. Multi-endpoint admission itself is deliberately not a public API yet:

- `NoctweaveArchitectureV2`, `LocalEndpointState`, `EndpointRecord`, and
  `EndpointSetManifest`: source types for a generation-scoped local endpoint
  and signed endpoint set. They do not model
  an account, durable device, or cross-generation registry. Admission and
  removal state machines are internal conformance models. Removal rekeys the
  local self-sync state and persists every unfinished route, mailbox, peer, and
  group cleanup obligation in `EndpointRemovalJournalV2`; manifest mutation
  alone is never called completed removal. A new `ClientStateStore` profile
  starts with one independently keyed local endpoint, one
  `RelationshipStateV2` shell per contact, and local generation-scoped
  `SelfSyncLocalStateV2`.
- `EndpointSetCheckpointV4`, `CertifiedGenerationEndpoint`,
  `EndpointSignedPrekeyPackageV4`, `PairwiseEndpointBindingV4`, and
  `DirectEndpointSessionIdentity`: these source types authenticate one preferred local endpoint
  under a compact generation-authority-signed manifest checkpoint and endpoint
  possession signature. Pairwise relationship IDs are derived from both
  identity generations; relay-visible sender identifiers and certificate
  references are relationship-scoped hashes. The full certificate, public
  keys, prekey bundle, global endpoint UUID, identity fingerprint, and endpoint
  set are not carried in the relay-visible direct context. Sessions are keyed
  by contact, local endpoint, peer endpoint, both handles, certificate
  references, and manifest epochs. Uncertified contacts are rejected; there is
  no identity-key direct-message wire or implicit upgrade path.
- Fresh direct messages, attachments, identity-rotation notices, and burn/reset
  notices are signed by the local endpoint key and use the preferred peer
  endpoint's signed prekey. Rotation keeps the pinned endpoint session;
  burn durably stages the exact reset ciphertext under the old endpoint
  session, registers the fresh local inbox/consumer before cutover, does not
  wait for any contact relay to accept the reset, and blocks new sends to each
  retained contact until that contact's reset is accepted.
  `EndpointRemovalProofV4`
  is an identity-signed endpoint-key rejection record for
  an encrypted control update. Applying it blocks that peer endpoint but is not
  complete local endpoint removal; route, self-sync, group, and delivery
  cleanup must also finish. Its endpoint certificate remains pinned to the
  issuing authority, while the rejection record follows the contact's current
  verified continuity key after same-generation authority rotation.
- The active cutover intentionally selects one certified peer endpoint.
  Multi-endpoint publication, per-recipient fan-out, encrypted manifest
  update distribution, and delivery aggregation remain follow-up work; the
  presence of a multi-record local manifest does not imply those flows exist.
- `LocalEndpointState.renewSignedPrekeyIfNeeded(at:)` rotates only the
  preferred endpoint's short-lived bootstrap key during its two-day renewal
  window. `CertifiedGenerationEndpoint.refreshingPrekeyPackage(using:at:)`
  publishes the replacement under the existing stable endpoint authorization.
  Prior private signed-prekey records are bounded to four and usable only until
  their authenticated expiry; established sessions are not rekeyed or reset.
  Neither operation creates another endpoint or invokes recovery/account or
  inbox authority.
- `MailboxConsumerId`, `MailboxCursor`, `SequencedEnvelope`,
  `MailboxSyncBatch`, `MailboxConsumerRegistration`, and
  `PendingMailboxCursorCommit`: independent ordered mailbox state.
  `MailboxRouteCredentialV2` persists one fresh consumer ID and ML-DSA key per
  relay/inbox route; the endpoint signing key is not reused as a fresh
  relay credential. The two
  raw-value identifiers use canonical single JSON strings on the Swift,
  JavaScript, OpenAPI, and signature-transcript surfaces; `{ "rawValue": ... }`
  is not a valid wire encoding.
- `RegisterMailboxConsumerRequest`, `SyncMailboxRequest`,
  `CommitMailboxCursorRequest`, and `RevokeMailboxConsumerRequest`: authenticated
  relay operations implemented by the in-process and Linux relay paths.
  First-consumer registration requires inbox-authority authorization and
  route-key possession. Later fresh consumers additionally require an
  active consumer's sponsorship. Sync and commit use only the bound
  route key, while consumer removal remains authority-controlled.
- `MailboxRouteSponsorshipContext`,
  `HeadlessMessagingClient.mailboxRouteSponsorshipContext()`, and
  `sponsorMailboxRouteCredential(_:)`: let one already admitted endpoint
  sponsor a fresh relay/inbox-route credential after that route key supplies
  its own possession proof. This never substitutes for endpoint admission, and
  the context carries no inbox authority or endpoint private key.
- `ProtocolIntentV2`: bounded durable mutation journal. The headless direct
  send/retry path uses it; the other declared intent kinds remain model surface
  until their workflows adopt the journal.
- `DeliveryStateRecord` and `QuarantinedControlEvent`: bounded persisted v2
  state. They do not replace the current direct-message projection by
  themselves.
- `InboundEnvelopeReceiptV2`: bounded persisted direct-receive receipt binding
  one logical event ID to its delivery-envelope ID and canonical signed-envelope
  digest. Exact refetches can be skipped only when all three values match;
  conflicting reuse fails before cursor advancement. Receipt compaction does
  not make old IDs trusted—an older replay must pass the normal signature and
  ratchet path again.
- `QuarantinedTransportEnvelopeV2`: bounded dead-letter receipt for a
  permanently invalid sequenced envelope. It stores only route/envelope
  digests, sequence, envelope ID, reason, and time. The client persists it
  before cursor commit so hostile ciphertext cannot block later events; local
  storage/runtime failures remain retryable and do not advance the cursor.
- `RelayCapabilityManifestV2` and `RelayModuleCapabilityV2`: bounded
  relay-terminated module advertisement carried by `RelayInfo`. The advertised
  modules follow actual relay configuration; this is discovery, not
  endpoint-to-endpoint transcript negotiation.
- `RelationshipStateV2`, `RelationshipEventCheckpointV2`, and
  `SelfSyncLocalStateV2`: persisted per-contact relationship shells, bounded
  domain-separated event-history checkpoints, and local self-sync
  secret/progress state. The checkpoint commits the canonical removed prefix
  and cumulative count while retaining a recent event window, so capacity does
  not silently drop history or permanently block append. A relationship shell
  does not by itself create a route capability or self-sync transport.
- `ReadOnlyHistoryProjectionV2`, `SealedHistoryArchiveTransportV2`,
  `HistoryArchiveImportTrustV2`, and `HistoryArchiveImportLedgerV2`: the active
  local history-export/import boundary. `HistoryTransferV2.exportArchive(...)`
  returns the only package intended for transport: an outer recipient-KEM seal
  whose clear JSON contains only version, KEM ciphertext, nonce, fixed-bucket
  ciphertext, and tag. `importArchive(...)` removes that seal before applying
  the existing sender authorization, signature, expiry, recipient, digest,
  projection, and replay checks. The `exportInnerArchive(...)`,
  `importInnerArchive(...)`, and `encodedForOuterSeal()` APIs are explicitly
  low-level and their metadata-bearing bytes must not leave the process.
  Callers must import with a ledger copy and atomically persist the returned
  inert projection plus the updated ledger before publishing success.

`ProtocolModuleCapability` and `ProtocolCapabilityManifest` are active on the
certified direct-v4 endpoint path. The default advertised manifest contains
only `nw.core:2`, `nw.endpoints:2`, `nw.events:2`, and `nw.prekeys:2`, with a
truthful single-peer-endpoint ceiling. The complete known-module catalog is
descriptive, not enabled by default. Direct-v4 negotiates only its four required
modules under fixed ceilings and binds the canonical result into the signed and
encrypted message transcript; optional modules require explicit opt-in and do
not alter that digest.

The following architecture-revision models have structural validation and focused tests but
remain additive foundations rather than end-to-end active protocol paths:
- `RelationshipRouteV2` and `RelationshipRouteSetV2`: signed,
  make-before-break relationship route state that can be retained in a
  `RelationshipStateV2` after verification. Contact import and headless relay
  rotation do not yet exchange route sets.
- `InboxRouteCapabilityV2`, `InboxRegistrationReceiptV3`,
  `CreateInboxRouteCapabilityRequest`, and
  `RevokeInboxRouteCapabilityRequest`: experimental relay-side opaque
  delivery-route storage and wire primitives. They are disabled by default and
  omitted from relay capability advertisements. Capability-only
  `DeliverRequest` omits inbox and routing identifiers, and both reference
  relays resolve only a live domain-separated digest before allocation. New
  owner-side bearer values use `InboxRouteCapabilityV2.generate()` and the OS
  CSPRNG; direct raw construction is not public. Authenticated import and wire
  decoding necessarily accept peer-provided structurally valid bearers, so a
  relay cannot prove their entropy. Registration returns a relay-local
  inbox-generation scope and next mutation sequence. Mutation v3 binds those values and commits its
  logical digest atomically, so applied retries converge and stale,
  conflicting, skipped, or cross-relay mutation requests fail closed. The
  final relay can still correlate every capability mapped to one inbox, and the
  current 16-entry bound is not relationship-scale. Issuance remains blocked
  until confidential transport, relationship-scoped inboxes or equivalent
  unlinkability, expiring rotation, realistic limits, abuse controls, and
  padding policy exist. Do not treat this foundation as a reusable public
  address.
- `SignedSelfSyncRecordV2`, `SealedSelfSyncRecordV2`,
  `SelfSyncEpochWelcomeV2`, and `SelfSyncLocalStateV2`: endpoint-signed,
  source-ordered hidden synchronization inside one disposable identity
  generation. Shared encryption-key possession is not source authority. The
  local state persists only the current epoch key, source chain progress, and
  exact ordering evidence; endpoint removal rotates the epoch.
- `RendezvousOfferV2`, `PendingRendezvousOfferV2`, and
  `RendezvousSessionV2`: one-use, expiring, purpose-bound post-quantum contact
  rendezvous. Public offers disclose no generation, endpoint, inbox, account,
  provider, or recovery identifier. Only contact pairing is enabled; endpoint
  admission, route rotation, group invitation, and history purposes fail
  closed until each has its own complete state machine.
- `GroupUser`, `GroupClientLeaf`, `GroupPermissionPolicy`,
  `GroupMembershipState`, and `GroupCryptoProvider`: endpoint-aware group
  state and crypto boundary. Relay-backed group delivery is not part of the
  current 1.0 surface; the Noctweave PQ group provider remains explicitly
  experimental.

The Swift certified direct-v4 path actively uses these typed APIs:

- `WirePayloadV2` separates `.application(ConversationEvent)` from
  `AuthenticatedControlPayloadV2`. Its authenticated-context discriminator is
  `NoctweaveWirePayloadV2.directV4Format` (`nw.wire-payload.v2`).
- `ContentTypeId`, `EncodedContent`, `ConversationEvent`, and `EventRelation`
  form the encrypted application event. Text and attachment are supported
  projections; unknown visible types retain their original event and expose a
  bounded fallback/placeholder, while silent unknown types and receipts retain
  the event without a UI message.
- `AuthenticatedControlKindV2` is the closed set of controls an implementation
  may apply. Unknown control identifiers produce a bounded
  `QuarantinedControlEvent`; malformed known controls fail before ratchet state
  is committed.
- `MessageEngine.encryptDirectV4(wirePayload:...)` and
  `decryptDirectV4Payload(...)` are the typed direct entry points. The older
  `decryptDirectV4(...)` returns the existing `MessageBody` UI/control
  projection only when one exists.

`MessageBody` remains a public local UI/control projection and the closed
payload projection used by the separately framed experimental group path. It
is not a direct-message wire format. Direct-v4 binds the
negotiated `nw.events` module version and resource limits into the messaging
transcript. Unknown application types remain safely retainable through their
authenticated fallback/disposition; security controls remain a closed,
separate namespace.

NoctweaveJS mirrors this boundary with
`encryptNativeApplicationEnvelope(...)` and
`decryptNativeApplicationEnvelope(...)`. Its text-oriented projection
returns the fallback for an unknown visible event and `null` for an unknown
silent event, so older text-oriented callers do not invent an unsupported chat
bubble.

## Relay APIs

- `RelayEndpoint` and `RelayEndpointParser`: normalized TCP, HTTP, HTTPS, WebSocket, WSS, and TLS relay endpoints.
- `RelayClient`: transport-aware relay request client with a deployment-specific `RelayClientPolicy` for request size, response size, and timeout budgets. Policy values are validated against fixed safety ceilings; cryptographic dimensions and wire-validation limits are not deployment overrides. `sendObservingTLS(...)` returns the system-trusted TLS leaf-certificate SHA-256 fingerprint only after a complete relay request succeeds, allowing clients to implement explicit or trust-on-first-use pinning.
- `RelayCertificatePinRecord`: bounded persisted relay trust record. Automatic first-use pins and manual pins are distinguished so a client can explain its trust decision.
- `RelayRequest` and `RelayResponse`: canonical relay protocol request/response envelopes.
- `RelayServer` and `RelayStore`: in-process relay implementation used by tests
  and local tools, with ordered per-consumer mailbox cursors, rendezvous,
  opaque-route capabilities, attachments, and federation. Relay-backed group
  operations are not part of the 1.0 public surface.
- `NoctweaveJS/NoctweaveRelayClient`: browser/Node HTTP and WebSocket relay access for applications that need relay diagnostics, inbox polling, or custom protocol integration.

## JavaScript Web Integration

`NoctweaveJS` provides relay transport, bounded raw storage adapters,
`EncryptedNoctweaveStore`, a narrow liboqs WASM adapter, the native
Noctweave direct-message wire profile, and bounded architecture-v2 helpers for
capability manifests, relationship-scoped endpoint handles, typed content
and events, mailbox cursors, and delivery-state progression. Fresh JavaScript
identities publish a certified direct-v4 contact offer containing a compact
manifest checkpoint and one preferred generation-scoped endpoint. The browser,
Node, and packaged reference clients establish endpoint-keyed sessions, use
endpoint signing keys and signed prekeys, authenticate pairwise opaque
handles and relationship-blinded certificate references, and carry generic
`WirePayloadV2` application events in an NPAD-v2 frame. Text and attachment
projections are strict; unknown visible/silent application types retain their
authenticated event and fallback/disposition. Pre-v4 contacts and NPAD-v1
direct frames are rejected; there is no format probing or downgrade. This is intentionally bounded to one preferred
endpoint and does not yet implement multi-endpoint fan-out.

The JavaScript client also includes encrypted local-first identity setup,
verified contacts, durable direct conversations, inbox synchronization, and
read-only history projection. Live profile portability is intentionally absent
because it would duplicate active private state. It is still pre-1.0 and
unaudited. Raw
`localStorage`, IndexedDB, and database adapters do not encrypt by themselves;
applications must wrap sensitive state and manage the wrapping key separately.
`NoctweaveRelayClient` accepts a bounded `policy` object for production timeout,
default raw-TCP port, request-size, and response-size configuration. Explicit
HTTP(S)/WebSocket URLs retain their standard or specified port.

## Operator And Federation APIs

- `RelayConfiguration` and `RelayInfo`: operator-controlled relay capabilities
  and advertised metadata. Only implemented 1.0 modules are advertised.
- `FederationDescriptor`, coordinator records, signed directory snapshots, and open-federation DHT records.
- Hidden retrieval, onion transport, mixnet transport, decentralized wake, and metadata-minimization helpers.

## Stability Rules Before 1.0

Public types may still change before the first stable release. Changes should be intentional, documented in the roadmap or protocol docs, and covered by tests when they affect wire format, state format, relay behavior, CLI behavior, or headless client behavior. See `noctweave_core_stability_policy.md` for the full pre-1.0 and post-1.0 rules.
