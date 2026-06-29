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
if grep -R "identityFingerprint\|displayName" \
  "$ROOT_DIR/PICCP Messaging Client/PICCP Messaging Client/CiphertextPrefetchRunner.swift"; then
  echo "Closed-app helper runner must not depend on identity names or fingerprints." >&2
  exit 1
fi
if grep -R "var identityFingerprint\|var displayName" \
  "$ROOT_DIR/PICCP Messaging Client/PICCP Messaging Client/CiphertextPrefetchStore.swift"; then
  echo "Closed-app helper profile config must not publish identity names or fingerprints." >&2
  exit 1
fi

echo "Verifying Apple helper prefetch does not publish group routing metadata..."
if grep -R "NoctyraPrefetchGroup\|FetchGroupMessagesRequest\|fetchGroupMessages" \
  "$ROOT_DIR/PICCP Messaging Client/PICCP Messaging Client/CiphertextPrefetchStore.swift" \
  "$ROOT_DIR/PICCP Messaging Client/PICCP Messaging Client/CiphertextPrefetchRunner.swift"; then
  echo "Closed-app helper group fetch needs a delegated group credential before group routing metadata is published." >&2
  exit 1
fi

echo "Verifying Apple helper prefetch sanitizes stale helper config fields..."
if ! grep -q "prefetchConfigPayloadNeedsSanitization" \
  "$ROOT_DIR/PICCP Messaging Client/PICCP Messaging Client/CiphertextPrefetchStore.swift"; then
  echo "Closed-app helper config must scrub stale sensitive fields after successful decode." >&2
  exit 1
fi

echo "Verifying Apple helper prefetch has bounded local work queues..."
if ! grep -q "maxPrefetchProfiles" \
  "$ROOT_DIR/PICCP Messaging Client/PICCP Messaging Client/CiphertextPrefetchStore.swift"; then
  echo "Closed-app helper prefetch must cap profile count before helper execution." >&2
  exit 1
fi
if ! grep -q "maxPrefetchedRecords" \
  "$ROOT_DIR/PICCP Messaging Client/PICCP Messaging Client/CiphertextPrefetchStore.swift"; then
  echo "Closed-app helper prefetch must cap staged ciphertext records." >&2
  exit 1
fi
if ! grep -q "maximumEnvelopeCountPerProfile" \
  "$ROOT_DIR/PICCP Messaging Client/PICCP Messaging Client/CiphertextPrefetchRunner.swift"; then
  echo "Closed-app helper prefetch must clamp per-profile fetch response counts locally." >&2
  exit 1
fi

echo "Whitepaper alignment verification complete."
