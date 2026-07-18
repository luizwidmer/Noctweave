#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$ROOT_DIR/scripts/liboqs-runtime.sh"

echo "Verifying clean 1.0 relationship, opaque-route, event, group, wake, and relay alignment..."
swift test \
  --package-path "$ROOT_DIR/NoctweaveCore" \
  --filter '(CodingPreflightTests|ContactPairingV2Tests|PersonaScopeFreshnessTests|MessageProjectionStrictTests|PairwiseOpaqueRouteV2Tests|OpaqueRoutePacketV2Tests|OpaqueRouteRelayStoreV2Tests|HeadlessCurrentArchitectureTests|ConversationEventStrictTests|WirePayloadV2Tests|NoctweavePQGroupRuntimeV2Tests|GroupPolicyTests|DecentralizedWakeRouteTests|RelayWireExactEnvelopeTests|StrictCryptographicStateTests)'

echo "Verifying Linux relay modular-wire and opaque-route parity coverage..."
swift test \
  --package-path "$ROOT_DIR/NoctweaveRelayServer" \
  --filter '(OpaqueRouteRuntimeV2Tests|OpaqueRouteRelayIntegrationTests|RelayWireExactEnvelopeTests|RendezvousRelayTransportTests|RelayCapabilitiesV2Tests|RelayStoreCurrentTests)'

echo "Verifying public repository boundary..."
if git -C "$ROOT_DIR" ls-files | grep -E '^(Noctyra Messaging Client|Noctyra Relay|Noctweave\.xcworkspace)/'; then
  echo "Private Apple app workspaces or sources must not be tracked in the public repository." >&2
  exit 1
fi

echo "Verifying release sources do not ship autonomous public-DHT adapters..."
if grep -R -E "BEP5|libp2p|Kademlia|PublicDHT|AutonomousPublicDHT" \
  "$ROOT_DIR/NoctweaveCore/Sources" \
  "$ROOT_DIR/NoctweaveRelayServer/Sources"; then
  echo "Autonomous public-DHT adapters are out of release scope; use coordinator snapshots, bounded relay peer exchange, or the bounded relay native-overlay DHT path." >&2
  exit 1
fi

echo "Whitepaper alignment verification complete."
