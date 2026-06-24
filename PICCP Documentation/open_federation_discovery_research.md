# Open Federation Discovery Research (Tor/IPFS/BitTorrent)

Last updated: March 6, 2026

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

## Recommended Noctyra Open-Federation Design

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
3. Keep coordinator mode available as a fallback and abuse-control anchor.
4. Do not mix curated and open entries in any path.

## Safety Controls (required before enabling open mode in UI)
- Signed relay advertisements (ML-DSA identity signing).
- Endpoint proof-of-reachability before accepting registration.
- Rate-limited register/list APIs with per-source quotas.
- Health-score decay and eviction of stale/failed nodes.
- Strict federation-mode isolation:
  - curated nodes never consume open node records
  - open nodes never import curated allowlists as authority

## Suggested Implementation Order
1. Signed coordinator snapshots + freshness semantics.
2. Client/relay cache policy with stale-read fallback.
3. R-PEX with strict caps and health validation.
4. Open-mode UI re-enable behind a feature flag.
5. Optional DHT research spike (only after 1-4 are stable).

## Why this fits current codebase
The relay already has coordinator registration and node listing APIs. This plan extends existing coordinator logic first, then adds peer-exchange acceleration, and defers full DHT complexity until operational telemetry justifies it.
