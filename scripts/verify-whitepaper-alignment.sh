#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$ROOT_DIR/scripts/liboqs-runtime.sh"

echo "Verifying core metadata, hidden retrieval, onion/mixnet transport, group-state, wake, and open-federation alignment..."
swift test \
  --package-path "$ROOT_DIR/PICCPCore" \
  --filter '(PICCPCoreTests/test(MetadataMinimizer|MessageEngineBuckets|MessageEnginePads|MLSGroupEpochHistoryValidator|GroupRatchet|OfflineGroupMemberRefreshesEpoch|OfflineGroupMemberReplaysMultipleEpochDistributions|MultipleOfflineGroupMembersReplayRetainedEpochs|OfflineGroupMemberFailsClosedWhenRetainedEpochWindowExpires|ClientStateGroupRatchetRecovery|RootRatchetRoundTrip|RelayStoreBucketsVisiblePair|RelayStoreRejectsOversizedEnvelopePayloads|RelayStoreAttachmentRoundTrip|RelayStoreCanOffloadAttachmentChunksToExternalBlobStore|RelayStoreRejectsCorruptExternalAttachmentBlob|RelayStoreRejectsRatchetSecretDistribution|RelayStoreRejectsStructurallyInvalidRatchetSecretDistribution|HiddenRetrievalPlanner|HiddenRetrievalSupport|HiddenRetrievalReplicaSetValidator|RelayInfoSuppressesWeakReplicatedPIRAdvertisement|OnionTransport|RelayInfoSuppressesUnusableOnionTransportSupport|MixnetScheduler|MixnetPacketPadder|MixnetInterRelayCoverCoordinator|MixnetRouteSelector|MixnetRoutePolicyValidator|RelayInfoAdvertisesOptionalOnionTransportSupport|RelayInfoAdvertisesOptionalMixnetTransportSupport|RelayInfoSuppressesMisleadingMixnetAdvertisement|DecentralizedWakePlanner|DecentralizedPrefetch|OpenFederationDHTDiscoveryEngineFallsBack|OpenFederationDHTHTTPGatewayRefresh)|GroupProtocolModelCheckerTests)'

echo "Verifying Linux relay open-federation parity coverage..."
swift test \
  --package-path "$ROOT_DIR/PICCP Relay Server" \
  --filter 'RelayStoreParityTests/test(GroupDescriptorCarriesMLSEpochState|RelayStoreBucketsVisiblePair|RelayStoreRejectsOversizedEnvelopePayloads|StoreCanOffloadAttachmentChunksToExternalBlobStore|ExternalAttachmentBlobDigestMismatchIsRejected|RelayStoreRejectsStructurallyInvalidRatchetSecretDistribution|HiddenRetrievalSupport|RelayInfoSuppressesWeakReplicatedPIRAdvertisement|RelayInfoCarriesOptionalOnionTransportSupport|RelayInfoSuppressesUnusableOnionTransportSupport|RelayInfoCarriesOptionalMixnetTransportSupport|RelayInfoSuppressesMisleadingMixnetAdvertisement|MixnetRoutePolicyValidator|OpenFederationDHTHTTPGatewayRefresh|OpenFederationDHTNativeOverlay)'

echo "Verifying Apple helper prefetch does not publish identity signing keys..."
if grep -R "identitySigningKey" \
  "$ROOT_DIR/PICCP Messaging Client/PICCP Messaging Client/CiphertextPrefetchStore.swift" \
  "$ROOT_DIR/PICCP Messaging Client/PICCP Messaging Client/CiphertextPrefetchRunner.swift"; then
  echo "Closed-app helper prefetch must not carry the long-term identity signing key." >&2
  exit 1
fi

echo "Verifying Apple helper prefetch does not publish group routing metadata..."
if grep -R "NoctyraPrefetchGroup\|FetchGroupMessagesRequest\|fetchGroupMessages" \
  "$ROOT_DIR/PICCP Messaging Client/PICCP Messaging Client/CiphertextPrefetchStore.swift" \
  "$ROOT_DIR/PICCP Messaging Client/PICCP Messaging Client/CiphertextPrefetchRunner.swift"; then
  echo "Closed-app helper group fetch needs a delegated group credential before group routing metadata is published." >&2
  exit 1
fi

echo "Whitepaper alignment verification complete."
