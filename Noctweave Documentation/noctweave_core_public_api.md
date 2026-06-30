# NoctweaveCore Public API Notes

`NoctweaveCore` is the shared Swift package for protocol implementers and Noctyra tooling. The package is not yet source-stability frozen, but public APIs should now be treated as candidate library surface rather than app-private implementation detail.

## Package Products

- `NoctweaveCore`: protocol models, cryptographic wrappers, relay client/server primitives, messaging state, groups, federation, and metadata-reduction helpers.
- `NoctyraCLI`: command-line diagnostics and headless direct messaging client.
- `NoctweaveCoreTestHarness`: local protocol harness for development verification.

## Client-Facing APIs

- `HeadlessMessagingClient`: persistent headless identity, contact, send, receive, register, and contact-share workflows.
- `HeadlessIdentityChangeResult`: structured result for identity rotation and burn operations.
- `HeadlessContinuityAudit` and `HeadlessContinuityAuditPurgeResult`: structured inspection and purge results for active-identity continuity events.
- `ClientState` and `ClientStateStore`: codable local state and optional platform encryption wrapper.
- `Identity`, `IdentityProfile`, `Contact`, `Conversation`, and `Message`: core client state models.
- `MessageEngine`: direct-message session creation, encryption, decryption, root ratchet, and message appending.
- `ContactOffer`, `ContactOfferCode`, and `ContactShare`: signed contact offers and password-protected contact packages.

## Relay APIs

- `RelayEndpoint` and `RelayEndpointParser`: normalized TCP, HTTP, HTTPS, WebSocket, WSS, and TLS relay endpoints.
- `RelayClient`: transport-aware relay request client with timeout and response-size bounds.
- `RelayRequest` and `RelayResponse`: canonical relay protocol request/response envelopes.
- `RelayServer` and `RelayStore`: in-process relay implementation used by tests and local tools.

## Operator And Federation APIs

- `RelayConfiguration` and `RelayInfo`: operator-controlled relay capabilities and advertised metadata.
- `FederationDescriptor`, coordinator records, signed directory snapshots, and open-federation DHT records.
- Hidden retrieval, onion transport, mixnet transport, decentralized wake, and metadata-minimization helpers.

## Stability Rules Before 1.0

Public types may still change before the first stable release. Changes should be intentional, documented in the roadmap, and covered by tests when they affect wire format, state format, relay compatibility, or headless client behavior.
