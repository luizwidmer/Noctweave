# Open Federation Discovery Research (Tor/IPFS/BitTorrent)

Last updated: June 24, 2026

## Goal
Design a practical way for open-federation relays to discover each other quickly, maintain healthy node lists, and avoid unsafe trust assumptions.

## What Existing Networks Do

### Tor: signed directory consensus + fallback bootstrap
- Tor uses a small set of semi-trusted directory authorities that vote and publish a signed consensus document.
- Clients and caches consume the consensus on a timeline (`valid-after`, `fresh-until`, `valid-until`) to avoid stale topology.
- Tor also ships fallback directory lists to bootstrap when direct authority access is unavailable.
- Operational insight for us: signed coordinator outputs and explicit freshness windows improve reliability and split-brain behavior.

References:
- https://spec.torproject.org/dir-spec/outline.html
- https://spec.torproject.org/dir-spec/computing-consensus.html
- https://spec.torproject.org/dir-list-spec.html

### BitTorrent: DHT + peer exchange (PEX)
- BitTorrent DHT (BEP 5) uses Kademlia-like routing with iterative lookup and token checks to limit abusive announces.
- PEX (BEP 11) shares currently connected peers, with rate limits and liveness constraints; this makes swarm discovery faster after initial bootstrap.
- Operational insight for us: combine a baseline discovery network with low-rate peer exchange to accelerate convergence.

References:
- https://www.bittorrent.org/beps/bep_0005.html
- https://www.bittorrent.org/beps/bep_0011.html

### IPFS/libp2p: layered discovery
- libp2p supports multiple discovery paths: mDNS (LAN), Rendezvous (federated points), and Kad-DHT (decentralized).
- IPFS uses WAN/LAN DHT separation and reachability-aware participation (client/server mode) to reduce routing noise from unreachable nodes.
- Operational insight for us: separate local and public discovery scopes, and gate “router-grade” participation on observed reachability.

References:
- https://docs.libp2p.io/concepts/discovery-routing/mdns/
- https://libp2p.io/docs/rendezvous/
- https://libp2p.io/docs/kademlia-dht/
- https://docs.ipfs.tech/concepts/dht/

## Feasibility: Reusing Torrent Infrastructure

Public BitTorrent DHT infrastructure is attractive because it already provides a large UDP Kademlia network, bootstrapping conventions, and peer-location semantics. It is not suitable as a direct trust substrate for Noctyra relays.

Main issues:
- **DHT records are discovery hints, not authority.** BEP 5 token checks limit spoofed announces by source IP, but they do not authenticate that an announced endpoint is a valid Noctyra relay.
- **Metadata is public by design.** Relays advertising into a public torrent-style DHT expose endpoints, timing, and federation interest to observers crawling that namespace.
- **Poisoning and Sybil resistance are weak.** A popular namespace can be flooded with bogus endpoints unless every discovered record is independently signed, freshness-limited, and reachability-probed.
- **Curated federation cannot use it as authority.** Curated universes require operator-selected trust roots, signed directories, and quorum rules. A public DHT can only be a bootstrap hint, not an allow-list replacement.

Feasible uses:
1. **Open federation bootstrap hints:** derive an infohash-like namespace from `noctyra-open-v1 || federationName`, query peers, then accept only ML-DSA-signed Noctyra relay records after HTTPS/WSS reachability checks.
2. **Operator-only discovery:** relays may query DHT; ordinary clients should prefer signed coordinator snapshots or trusted relay-provided directories to reduce client-side metadata exposure.
3. **PEX-style acceleration:** once a relay is connected to known healthy open peers, it can exchange a capped list of live peers, using BitTorrent PEX constraints as a model.

Not recommended:
- Publishing contact/user information into any public DHT.
- Treating public DHT results as trusted membership.
- Mixing curated and open federation records.
- Making mobile clients depend on UDP DHT reachability.

## Recommended Noctyra Open-Federation Design

## Final Discovery Stance

Noctyra should ship open-federation discovery as a layered relay-operator system, not as client-side public-DHT participation.

The selected release stance is:

1. **Default authority:** signed coordinator snapshots with freshness windows.
2. **Acceleration path:** bounded relay-protocol peer exchange through `knownOpenPeers`.
3. **Experimental operator bridge:** HTTP gateway/sidecar integration for operators who want to connect BEP5, libp2p, or another discovery process.
4. **Not release scope:** built-in autonomous BEP5/libp2p participation inside the relay binary.

Autonomous public-DHT participation is deferred because the operational cost and metadata exposure are high relative to the benefit. A public BEP5/libp2p adapter would expose relay membership timing to crawlers, require UDP/NAT traversal and routing-table maintenance, introduce additional Sybil/churn surfaces, and need a dedicated live-network simulation suite. The current gateway boundary gives operators a way to experiment with torrent/libp2p infrastructure without letting raw public-network results bypass Noctyra's signed-record validator, endpoint policy, host caps, total caps, and TTL checks.

This means open federation can still benefit from torrent-style ideas: Kademlia informs lookup design, BEP 11 informs bounded peer exchange, and libp2p informs layered discovery. Those ideas are applied through coordinator snapshots, relay peer exchange, and the sidecar seam rather than embedding a public-DHT router in the release relay.

### Phase 1 (near-term): coordinator-first, signed directory snapshots
1. Keep coordinator nodes as primary discovery roots.
2. Coordinator publishes signed relay snapshots with:
   - relay endpoint
   - relay kind + federation mode/name
   - TLS capability
   - heartbeat freshness (`observedAt`, `expiresAt`)
3. Relays and clients cache snapshots with explicit TTL and fail over to stale-cache mode if coordinators are unreachable.

### Phase 2: relay peer exchange (R-PEX)
1. Add a low-rate “known peers” field to relay info/list responses.
2. Share only recently healthy open-federation peers.
3. Enforce limits:
   - max peers per response
   - minimum re-advertise interval
   - no blind forwarding without successful health probe
4. Benefit: new relays bootstrap from one endpoint and quickly expand their view.

### Phase 3: optional decentralized overlay
1. Introduce a lightweight federation DHT namespace for open federation only.
2. Store signed endpoint records keyed by federation namespace + relay identity digest.
3. Require each record to include:
   - relay endpoint and advertised transport
   - relay identity digest
   - federation mode/name
   - issued/expiry timestamps
   - supported protocol version
   - ML-DSA signature over the canonical record
4. Accept a DHT result only after:
   - record signature verification
   - endpoint public-routability policy
   - TLS or WSS requirement
   - live `/info` or equivalent relay-info probe
   - federation mode/name match
5. Keep coordinator mode available as a fallback and abuse-control anchor.
6. Do not mix curated and open entries in any path.

## DHT Record Sketch

Status: the signed-record primitive is implemented as `OpenFederationDHTRecord` in `PICCPCore` and the Linux relay package. A feature-gated `OpenFederationDHTCandidateCache` models the relay-operator acceptance layer: it ingests only validated short-lived records, deduplicates by relay identity, caps records per host and overall, evicts stale entries, and exposes normal federation node records for relay integration. Host caps also apply when a newer relay-identity record moves to a different host, so replacement churn cannot bypass per-host flood limits. `OpenFederationDHTTransport` and `OpenFederationDHTDiscoveryEngine` define the publish/query seam and testable refresh cycle. `OpenFederationDHTHTTPGatewayTransport` provides a concrete HTTP gateway/sidecar adapter so an operator can connect Noctyra to a separately managed BEP5/libp2p/custom discovery process without letting raw network results bypass Noctyra validation. The Linux relay also exposes native relay-protocol DHT publish/list routes and `OpenFederationDHTNativeOverlayTransport`, which walks bounded `knownOpenPeers` hints in a PEX-style overlay without a gateway sidecar. The gateway and native-overlay paths are covered by tests that push poisoned and host-flooded records through the adapter before cache acceptance. The project still does not ship autonomous BEP5/libp2p public-DHT participation. This is intentional: the signed record schema, candidate cache, gateway boundary, and native relay-protocol overlay exist first so any later public-network adapter has a hard acceptance boundary.

```json
{
  "version": 1,
  "namespace": "noctyra-open-v1:<federation-name-hash>",
  "relayIdentity": "<ml-dsa-public-key-hash>",
  "endpoint": "wss://relay.example.org",
  "federationMode": "open",
  "federationName": "example-open-net",
  "issuedAt": "2026-06-24T00:00:00Z",
  "expiresAt": "2026-06-24T00:10:00Z",
  "signatureAlgorithm": "ML-DSA-65",
  "signature": "<base64>"
}
```

The record is deliberately small and short-lived. Relays republish periodically; stale records are ignored. Discovery should be probabilistic and opportunistic, not a hard dependency for message delivery.

## Safety Controls (required before enabling open mode in UI)
- Signed relay advertisements (ML-DSA identity signing).
- Endpoint proof-of-reachability before accepting registration.
- Rate-limited register/list APIs with per-source quotas.
- Health-score decay and eviction of stale/failed nodes.
- Public endpoint policy that rejects private, local, documentation, multicast, and IPv6-transition addresses that embed private IPv4 destinations.
- Strict federation-mode isolation:
  - curated nodes never consume open node records
  - open nodes never import curated allowlists as authority

## Suggested Implementation Order
1. Signed coordinator snapshots + freshness semantics.
2. Client/relay cache policy with stale-read fallback.
3. R-PEX with strict caps and health validation.
4. Open-mode UI re-enable behind a feature flag.
5. Use the HTTP gateway adapter for operator-run discovery sidecars.
6. Use the native relay-protocol overlay for controlled open-relay PEX experiments.
7. Keep autonomous BEP5/libp2p participation out of the release relay unless a later release reopens the decision with a concrete operator demand, maintenance owner, and live-network abuse test plan.
8. If a later public-network adapter is approved, extend load/poisoning simulation from the core candidate cache, HTTP gateway transport, and native relay-protocol overlay before exposing it in release builds.

## Why this fits current codebase
The relay already has coordinator registration and node listing APIs. This plan extends existing coordinator logic first, then adds peer-exchange acceleration, and defers full DHT complexity until operational telemetry justifies it.

## Source Notes
- BitTorrent BEP 5 defines a UDP Kademlia-like DHT and token-protected announces, which is useful as a discovery pattern but insufficient as Noctyra relay authority.
- BitTorrent BEP 11 constrains PEX to verified live peers, one update per minute, and capped update sizes. Noctyra R-PEX should follow those principles.
- Tor directory consensus demonstrates the operational value of signed directory documents, freshness windows, and multiple authorities.
- IPFS/libp2p DHT design demonstrates separating peer records/provider records and tuning Kademlia parameters for churn.
