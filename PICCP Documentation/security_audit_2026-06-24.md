# Noctyra Security Re-Audit and DHT Feasibility Notes

**Date:** June 24, 2026  
**Scope:** Noctyra client, `PICCPCore`, macOS relay, Linux relay, federation discovery, relay forwarding, and relay discovery research.

## Executive Summary

The current implementation has materially strong application-layer controls for message confidentiality, authenticated inbox access, relay forwarding gates, signed group operations, bounded storage, and relay password isolation. The highest-value remaining risk area is not message encryption; it is network metadata, relay discovery trust, and coordinator/DHT poisoning.

This pass found one concrete SSRF-style hardening gap in public open-federation endpoint validation. The relay rejected private IPv4, loopback, link-local, and IPv4-mapped IPv6 addresses, but did not explicitly handle IPv6 transition addresses that can encode private IPv4 destinations. This has been patched in both `PICCPCore` and the Linux relay package.

The DHT/torrent research supports a cautious path: use DHT-style discovery only for open-federation relay bootstrap hints, never as authority. Public torrent infrastructure can help find candidate relays, but every result must be signed, short-lived, TLS-reachable, bounded, and independently probed before it enters a routing set. The signed-record primitive for this path now exists in core as `OpenFederationDHTRecord`, and the feature-gated candidate acceptance layer exists as `OpenFederationDHTCandidateCache`; the network DHT client/publisher remains deliberately unimplemented.

## Threat Scenarios Reviewed

### Malicious relay
- Can observe source IPs, timing, chosen relay, mailbox polling cadence, and ciphertext sizes.
- Cannot decrypt message payloads or attachments without endpoint keys.
- Mitigations present: ML-KEM/ML-DSA session setup, AEAD payloads, authenticated inbox fetch/ack, temporal buckets, attachment TTL, relay password support, TLS/WSS support.
- Residual risk: no PIR, mixnet, onion routing, or cover traffic.

### Malicious coordinator
- Can bias directory membership, omit relays, or advertise stale topology.
- Mitigations present: signed freshness-limited directory snapshots, pinned coordinator signing keys, quorum support for curated mode, freshness filtering.
- Residual risk: coordinator directory signatures are still Ed25519 rather than ML-DSA. This is the main post-quantum gap in federation metadata.

### Open-federation poisoning
- Attacker floods a coordinator or DHT namespace with bogus relays.
- Mitigations present: coordinator registration throttling, live relay-info reachability checks, TLS/public-routability requirements, federation mode/name matching, peer hint caps.
- Patched in this pass: public endpoint policy now handles Teredo, 6to4, and NAT64 IPv4-embedded private destinations.
- Residual risk: no autonomous DHT publish/query transport yet; when added, poisoning simulations must be extended to the live transport path.

### Cross-network federation confusion
- Open nodes and curated nodes must not form one mixed trust domain.
- Mitigations present: explicit mode checks before forwarding, open mode rejects allow lists, curated mode requires allow-list/coordinator policy.
- Residual risk: operator misconfiguration can still create confusing UX; relay UI should keep warning language explicit.

### Client compromise and local capture
- Malware or the OS can observe plaintext at use time.
- Mitigations present: app lock, secure typing, screenshot/screen-capture hiding, encrypted-at-rest storage, scoped attachment decryption.
- Residual risk: Swift memory erasure is best effort and cannot prove all framework copies are scrubbed.

### Group authorization abuse
- Unauthorized member tries to mutate group membership or stale actor proof is replayed.
- Mitigations present: actor proofs, signing-key matching, nonce replay cache, timestamp limits.
- Residual risk: groups are relay-backed application protocol, not MLS.

## DHT and Torrent Infrastructure Assessment

### What is useful
- BitTorrent DHT’s Kademlia-style lookup and token-protected announce model is useful as a relay-discovery pattern.
- BitTorrent PEX is useful as a model for low-rate relay peer exchange after initial bootstrap.
- IPFS/libp2p shows why discovery should be layered: local discovery, rendezvous/coordinator points, and Kademlia DHT have different trust and reachability properties.
- Tor’s signed directory consensus supports the current coordinator-first approach: signed snapshots with freshness windows are operationally clearer than trusting raw peer gossip.

### What is unsafe
- Public torrent DHT results are not authenticated Noctyra relay records.
- Public DHT crawling makes relay membership and federation interest observable.
- DHT namespaces are susceptible to poisoning and Sybil pressure.
- Mobile clients querying public DHT directly would leak metadata and add UDP reachability problems.

### Recommended path
1. Keep coordinator snapshots as the default discovery authority.
2. Keep relay peer exchange capped and fed only by recently healthy open-federation relays.
3. Add an optional open-only DHT prototype later, relay-operator controlled, with ML-DSA-signed short-lived records.
4. Clients should consume signed coordinator or trusted-relay directories first; direct public-DHT lookup should remain off by default.
5. Curated federation may use DHT only as a non-authoritative hint to find candidate coordinator endpoints, never to accept relay membership.

## Patched in This Pass

- `PICCPCore/Sources/PICCPCore/PublicRelayEndpointPolicy.swift`
  - Rejects Teredo (`2001::/32`).
  - Validates 6to4 (`2002::/16`) embedded IPv4 addresses against the same public-routability policy.
  - Validates NAT64 well-known prefix (`64:ff9b::/96`) embedded IPv4 addresses against the same public-routability policy.

- `PICCP Relay Server/Sources/PICCPRelayServer/PublicRelayEndpointPolicy.swift`
  - Same parity fix for Linux relay.

- Regression tests:
  - `PICCPCoreTests.testPublicRelayEndpointPolicyRejectsIPv6TransitionPrivateTargets`
  - `RelayTCPIntegrationTests.testPublicRelayEndpointPolicyRejectsIPv6TransitionPrivateTargets`

- `PICCPCore/Sources/PICCPCore/OpenFederationDHTRecord.swift`
  - Defines an ML-DSA-signed, short-lived open-federation relay advertisement record.
  - Validates namespace, relay identity digest, expiry/lifetime, signature, TLS transport, and optional public-routability policy.

- Regression tests:
  - `PICCPCoreTests.testOpenFederationDHTRecordValidatesSignedRelayAdvertisement`
  - `PICCPCoreTests.testOpenFederationDHTRecordRejectsTamperedEndpoint`
  - `PICCPCoreTests.testOpenFederationDHTRecordRejectsNamespaceMismatch`
  - `PICCPCoreTests.testOpenFederationDHTRecordRejectsExpiredAndOverlongRecords`
  - `PICCPCoreTests.testOpenFederationDHTRecordRequiresSecureHttpOrWebSocketEndpoint`

- `PICCPCore/Sources/PICCPCore/OpenFederationDHTDiscovery.swift`
  - Adds a disabled-by-default DHT candidate cache for relay operators.
  - Accepts only records that pass the signed-record validator.
  - Deduplicates by relay identity, prefers newer records, caps total records, caps per-host concentration, and evicts expired entries.
  - Emits normal `FederationNodeRecord` values so later relay integration can reuse existing federation directory handling.

- Regression/simulation tests:
  - `PICCPCoreTests.testOpenFederationDHTDiscoveryIsFeatureGated`
  - `PICCPCoreTests.testOpenFederationDHTDiscoveryAcceptsValidatedSignedRecords`
  - `PICCPCoreTests.testOpenFederationDHTDiscoveryRejectsPoisonedRecords`
  - `PICCPCoreTests.testOpenFederationDHTDiscoveryCapsHostFloods`
  - `PICCPCoreTests.testOpenFederationDHTDiscoveryCapsTotalRecords`
  - `PICCPCoreTests.testOpenFederationDHTDiscoveryHandlesChurnAndStaleRecords`

## Remaining Findings

### High
1. **Coordinator directory signatures are not post-quantum**
   - Current: Ed25519.
   - Required: versioned ML-DSA directory signature profile.
   - Risk: long-lived federation directory authenticity is not PQ.

### Medium
1. **No DHT publish/query transport exists**
   - Current: coordinator-assisted discovery plus peer hints; signed DHT records and a feature-gated candidate cache exist in core.
   - Required before release exposure: relay-only network transport, live reachability probe integration, transport-level churn/poisoning simulation, and operator UI warnings.

2. **Network anonymity remains out of scope**
   - Current: metadata reduction only.
   - Required for stronger claims: PIR, mixnet, onion routing, or cover traffic.

3. **Relay persistence still has operational hardening work**
   - Current docs indicate SQLite-backed snapshot-style persistence remains to be normalized.
   - Required: transactional normalized tables, corruption recovery tests, and migration policy.

### Low
1. **Release engineering remains incomplete**
   - Required: SBOM, dependency audit automation, signed release artifacts, and external audit.

2. **Swift 6 readiness warnings remain tracked**
   - Required before Swift 6 migration: NIO/sendability cleanup.

## Verification Plan

- Run `swift test` in `PICCPCore`.
- Run `swift test` in `PICCP Relay Server`.
- Build macOS client and server if UI/config changes are made.
- For DHT prototype work, add simulation tests covering:
  - poisoned record flood (core cache covered)
  - stale record eviction (core cache covered)
  - federation-name mismatch (core cache covered)
  - TLS/public-routing rejection (record validation covered)
  - signature mismatch (record validation covered)
  - Sybil concentration limits (host and total caps covered; network-level Sybil simulation still required)

## References

- BitTorrent BEP 5: DHT Protocol, token-protected announce and Kademlia-style lookup. https://www.bittorrent.org/beps/bep_0005.html
- BitTorrent BEP 11: Peer Exchange, peer gossip constraints. https://www.bittorrent.org/beps/bep_0011.html
- Tor directory consensus: signed consensus and freshness windows. https://spec.torproject.org/dir-spec/computing-consensus.html
- IPFS DHT concepts: provider/peer routing and DHT behavior. https://docs.ipfs.tech/concepts/dht/
- libp2p mDNS discovery: local discovery scope as a separate discovery plane. https://docs.libp2p.io/concepts/discovery-routing/mdns/
