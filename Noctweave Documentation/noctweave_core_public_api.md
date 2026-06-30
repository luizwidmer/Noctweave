# NoctweaveCore Public API Notes

`NoctweaveCore` is the shared Swift package for protocol implementers and Noctyra tooling. The package is not yet source-stability frozen, but public APIs should now be treated as candidate library surface rather than app-private implementation detail. Compatibility expectations are defined in `noctweave_core_stability_policy.md`.

## Package Products

- `NoctweaveCore`: protocol models, cryptographic wrappers, relay client/server primitives, messaging state, groups, federation, and metadata-reduction helpers.
- `NoctyraCLI`: command-line diagnostics and headless messaging client.
- `NoctweaveCoreTestHarness`: local protocol harness for development verification.
- `NoctweaveJS`: JavaScript ESM relay client, relay request helpers, and web/database storage adapters for simple web integrations.

## Client-Facing APIs

- `HeadlessMessagingClient`: persistent headless identity, contact, send, receive, register, contact-share, attachment, voice-message, and group workflows.
- `HeadlessIdentityChangeResult`: structured result for identity rotation and burn operations.
- `HeadlessContinuityAudit` and `HeadlessContinuityAuditPurgeResult`: structured inspection and purge results for active-identity continuity events.
- `HeadlessGroupSummary`, `HeadlessSentGroupMessage`, and `HeadlessReceivedGroupMessage`: sanitized headless group messaging results that do not expose serialized ratchet keys.
- `HeadlessSentAttachment` and `HeadlessFetchedAttachment`: headless direct/group attachment and voice-message transfer results.
- `ClientState` and `ClientStateStore`: codable local state and optional platform encryption wrapper.
- `Identity`, `IdentityProfile`, `Contact`, `Conversation`, and `Message`: core client state models.
- `MessageEngine`: direct-message session creation, encryption, decryption, root ratchet, and message appending.
- `ContactOffer`, `ContactOfferCode`, and `ContactShare`: signed contact offers and password-protected contact packages.

## Relay APIs

- `RelayEndpoint` and `RelayEndpointParser`: normalized TCP, HTTP, HTTPS, WebSocket, WSS, and TLS relay endpoints.
- `RelayClient`: transport-aware relay request client with timeout and response-size bounds.
- `RelayRequest` and `RelayResponse`: canonical relay protocol request/response envelopes.
- `RelayServer` and `RelayStore`: in-process relay implementation used by tests and local tools.
- `NoctweaveJS/NoctweaveRelayClient`: browser/Node HTTP and WebSocket relay access for applications that need relay diagnostics, inbox polling, or custom protocol integration.

## JavaScript Web Integration

`NoctweaveJS` is intentionally scoped to relay transport and persistence. It provides `MemoryNoctweaveStore`, `BrowserLocalStorageStore`, `IndexedDBNoctweaveStore`, `DatabaseNoctweaveStore`, and `NoctweaveStateRepository` so simple web applications can store state in browser storage or in an application database. It does not claim to replace the Swift/liboqs post-quantum message engine; encrypted messaging from JavaScript must use a compatible audited crypto/WASM adapter.

## Operator And Federation APIs

- `RelayConfiguration` and `RelayInfo`: operator-controlled relay capabilities and advertised metadata.
- `FederationDescriptor`, coordinator records, signed directory snapshots, and open-federation DHT records.
- Hidden retrieval, onion transport, mixnet transport, decentralized wake, and metadata-minimization helpers.

## Stability Rules Before 1.0

Public types may still change before the first stable release. Changes should be intentional, documented in the roadmap or protocol docs, and covered by tests when they affect wire format, state format, relay compatibility, CLI behavior, or headless client behavior. See `noctweave_core_stability_policy.md` for the full pre-1.0 and post-1.0 rules.
