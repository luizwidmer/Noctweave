#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$ROOT_DIR/scripts/liboqs-runtime.sh"

echo "Verifying core metadata, hidden retrieval, onion/mixnet transport, group-state, wake, and open-federation alignment..."
swift test \
  --package-path "$ROOT_DIR/NoctweaveCore" \
  --filter '(NoctweaveCoreTests/test(MetadataMinimizer|MessageEngineBuckets|MessageEnginePads|MLSGroupEpochHistoryValidator|GroupRatchet|OfflineGroupMemberRefreshesEpoch|OfflineGroupMemberReplaysMultipleEpochDistributions|MultipleOfflineGroupMembersReplayRetainedEpochs|OfflineGroupMemberFailsClosedWhenRetainedEpochWindowExpires|ClientStateGroupRatchetRecovery|RootRatchetRoundTrip|RelayStoreBucketsVisiblePair|RelayStoreRejectsOversizedEnvelopePayloads|RelayStoreAttachmentRoundTrip|RelayStoreCanOffloadAttachmentChunksToExternalBlobStore|RelayStoreRejectsCorruptExternalAttachmentBlob|RelayStoreRejectsRatchetSecretDistribution|RelayStoreRejectsStructurallyInvalidRatchetSecretDistribution|HiddenRetrievalPlanner|HiddenRetrievalSupport|HiddenRetrievalReplicaSetValidator|HiddenRetrievalPIROperationalValidator|HiddenRetrievalPIRPromotion|RelayInfoSuppressesWeakReplicatedPIRAdvertisement|OnionTransport|RelayInfoSuppressesUnusableOnionTransportSupport|MixnetScheduler|MixnetPacketPadder|MixnetInterRelayCoverCoordinator|MixnetRouteSelector|MixnetRoutePolicyValidator|RelayInfoAdvertisesOptionalOnionTransportSupport|RelayInfoAdvertisesOptionalMixnetTransportSupport|RelayInfoSuppressesMisleadingMixnetAdvertisement|DecentralizedWakePlanner|DecentralizedPrefetch|CoordinatorRegistersAndListsFederationNodes|CuratedRelayForwardsUsingCoordinatorDirectory|RelayCanServeOpenFederationDHTRecordsWhenEnabled|RelayRejectsOpenFederationDHTRoutesWhenDisabled|OpenFederationDHTDiscoveryEngine(FallsBack|DropsExpired)|OpenFederationDHTHTTPGatewayRefresh)|GroupProtocolModelCheckerTests)'

echo "Verifying Linux relay open-federation parity coverage..."
swift test \
  --package-path "$ROOT_DIR/NoctweaveRelayServer" \
  --filter 'RelayStoreParityTests/test(GroupDescriptorCarriesMLSEpochState|RelayStoreBucketsVisiblePair|RelayStoreRejectsOversizedEnvelopePayloads|StoreCanOffloadAttachmentChunksToExternalBlobStore|ExternalAttachmentBlobDigestMismatchIsRejected|RelayStoreRejectsStructurallyInvalidRatchetSecretDistribution|HiddenRetrievalSupport|RelayInfoSuppressesWeakReplicatedPIRAdvertisement|RelayInfoCarriesOptionalOnionTransportSupport|RelayInfoSuppressesUnusableOnionTransportSupport|RelayInfoCarriesOptionalMixnetTransportSupport|RelayInfoSuppressesMisleadingMixnetAdvertisement|MixnetRoutePolicyValidator|RelayInfoAdvertisesOpenFederationDHTAndPEXSupport|OpenFederationDHTHTTPGatewayRefresh|OpenFederationDHTNativeOverlay)'

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
