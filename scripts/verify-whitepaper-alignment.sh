#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$ROOT_DIR/scripts/liboqs-runtime.sh"

echo "Verifying core metadata, hidden retrieval, onion/mixnet transport, group-state, wake, and open-federation alignment..."
swift test \
  --package-path "$ROOT_DIR/PICCPCore" \
  --filter '(PICCPCoreTests/test(MetadataMinimizer|MessageEngineBuckets|MessageEnginePads|GroupRatchet|OfflineGroupMemberRefreshesEpoch|OfflineGroupMemberReplaysMultipleEpochDistributions|MultipleOfflineGroupMembersReplayRetainedEpochs|OfflineGroupMemberFailsClosedWhenRetainedEpochWindowExpires|ClientStateGroupRatchetRecovery|RootRatchetRoundTrip|RelayStoreBucketsVisiblePair|RelayStoreRejectsOversizedEnvelopePayloads|RelayStoreAttachmentRoundTrip|RelayStoreCanOffloadAttachmentChunksToExternalBlobStore|RelayStoreRejectsCorruptExternalAttachmentBlob|RelayStoreRejectsRatchetSecretDistribution|RelayStoreRejectsStructurallyInvalidRatchetSecretDistribution|HiddenRetrievalPlanner|HiddenRetrievalSupport|HiddenRetrievalReplicaSetValidator|OnionTransport|MixnetScheduler|MixnetRoutePolicyValidator|RelayInfoAdvertisesOptionalOnionTransportSupport|RelayInfoAdvertisesOptionalMixnetTransportSupport|DecentralizedWakePlanner|OpenFederationDHTDiscoveryEngineFallsBack|OpenFederationDHTHTTPGatewayRefresh)|GroupProtocolModelCheckerTests)'

echo "Verifying Linux relay open-federation parity coverage..."
swift test \
  --package-path "$ROOT_DIR/PICCP Relay Server" \
  --filter 'RelayStoreParityTests/test(RelayStoreBucketsVisiblePair|RelayStoreRejectsOversizedEnvelopePayloads|StoreCanOffloadAttachmentChunksToExternalBlobStore|ExternalAttachmentBlobDigestMismatchIsRejected|RelayStoreRejectsStructurallyInvalidRatchetSecretDistribution|HiddenRetrievalSupport|RelayInfoCarriesOptionalOnionTransportSupport|RelayInfoCarriesOptionalMixnetTransportSupport|MixnetRoutePolicyValidator|OpenFederationDHTHTTPGatewayRefresh|OpenFederationDHTNativeOverlay)'

echo "Validating release provenance generation..."
"$ROOT_DIR/scripts/generate-release-provenance.py" >/dev/null

echo "Whitepaper alignment verification complete."
