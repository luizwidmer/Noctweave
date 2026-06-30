# Security Audit (Internal) - 2026-03-16

## Scope
- `NoctweaveCore` relay/client protocol paths
- Linux relay (`Noctweave Relay Server`) TCP + HTTP/WebSocket bridge
- Federation forwarding, coordinator directory validation, actor-proof mutation paths

## Method
- Manual code review of authentication, forwarding, federation, and group mutation routes
- Differential parity review between mac/core relay and Linux relay paths
- Regression + integration test execution (`swift test` for both packages)

## Findings and Status

### Critical
- None identified in reviewed scope.

### High
1. **Actor-proof signature verification gap on Linux relay**
   - Risk: group mutation integrity depended on fallback mode when verifier unavailable.
   - Status: **Patched**.
   - Fix: runtime `liboqs` verifier added (`ML-DSA-65`) with fail-closed behavior when unavailable, plus Docker runtime now includes `liboqs`.

2. **Unbounded relay-to-relay forwarding wait (stall exhaustion)**
   - Risk: malicious/unresponsive peers could hold forwarding operations indefinitely.
   - Status: **Patched**.
   - Fix: bounded forwarding timeout applied to TCP/HTTP federation forwarding and bridge forwarder.

### Medium
1. **Metadata parity mismatch (transport advertisement)**
   - Risk: client relay capability interpretation drifted between mac/core and Linux relay.
   - Status: **Patched**.
   - Fix: Linux relay now advertises `transport` in relay info and supports explicit transport flag.

2. **Replay risk for actor-proof mutations**
   - Risk: repeated signed mutation payload reuse.
   - Status: **Patched**.
   - Fix: nonce replay cache enforcement retained and covered by tests.

### Low
1. **Swift 6 sendability warnings (NIO ecosystem)**
   - Risk: currently non-fatal; future toolchain strictness can promote to errors.
   - Status: **Open (low)**.
   - Notes: mostly `ByteToMessageHandler` unavailable `Sendable` warnings from dependency surface.

## Residual Risk
- External third-party audit is still pending.
- Open-federation redesign remains deferred by product decision.

## Verification Evidence
- `swift test` passed in `Noctweave Relay Server` (integration + parity tests).
- `swift test` passed in `NoctweaveCore`.

## Recommended Next Steps
1. Execute external audit on protocol + relay forwarding implementation.
2. Add CI policy for dependency audit/SBOM.
3. Resolve remaining Swift 6 sendability warnings before strict-mode migration.
