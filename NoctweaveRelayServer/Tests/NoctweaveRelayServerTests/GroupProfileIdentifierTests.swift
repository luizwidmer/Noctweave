import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class GroupProfileIdentifierTests: XCTestCase {
    func testRelayUsesTheSameExplicitExperimentalNoctweaveGroupProfile() {
        XCTAssertEqual(MLSGroupEpochState.currentProtocolVersion, "noctweave-pq-group-experimental-2")
        XCTAssertEqual(
            MLSGroupEpochState.currentCipherSuite,
            "Noctweave-PQ-Group-Experimental-ML-KEM-768-ML-DSA-65-AES-256-GCM-SHA384-2"
        )
        XCTAssertFalse(MLSGroupEpochState.currentProtocolVersion.lowercased().contains("mls"))
    }

    func testRelayEpochValidatorRejectsSupersededGroupProfile() {
        let transcript = Data(repeating: 0x31, count: 32)
        let commit = MLSGroupCommitSummary(
            operation: .create,
            actorFingerprint: "actor",
            epoch: 0,
            committedAt: Date(timeIntervalSince1970: 1_800_000_000),
            memberFingerprints: [],
            previousTranscriptHash: nil,
            transcriptHash: transcript,
            ratchetSecretDistribution: nil
        )
        let state = MLSGroupEpochState(
            protocolVersion: "noctweave-pq-group-experimental-1",
            cipherSuite: MLSGroupEpochState.currentCipherSuite,
            groupId: UUID(),
            epoch: 0,
            treeHash: Data(repeating: 0x32, count: 32),
            confirmedTranscriptHash: transcript,
            lastCommit: commit
        )

        XCTAssertTrue(
            MLSGroupEpochHistoryValidator.issues(currentState: state, history: [commit])
                .contains(.unsupportedProtocolVersion)
        )
    }
}
