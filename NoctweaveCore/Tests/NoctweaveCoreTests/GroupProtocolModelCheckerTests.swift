import Foundation
import XCTest
@testable import NoctweaveCore

final class GroupProtocolModelCheckerTests: XCTestCase {
    func testGroupProtocolModelCheckerExploresCommitStateSpace() {
        let report = GroupProtocolModelChecker.verifySmallModel(
            candidateMemberCount: 4,
            maxDepth: 3
        )

        XCTAssertTrue(report.violations.isEmpty, report.violations.joined(separator: "\n"))
        XCTAssertGreaterThan(report.exploredStates, 8)
        XCTAssertGreaterThan(report.acceptedTransitions, 16)
        XCTAssertGreaterThan(report.rejectedTransitions, report.acceptedTransitions)
    }

    func testGroupProtocolModelRejectsReplayStaleAndForkedCommits() throws {
        let initial = GroupProtocolModelState(
            createdByFingerprint: "member-0",
            memberFingerprints: ["member-0", "member-1"]
        )
        let valid = SignedGroupCommit(
            operation: .update,
            groupId: initial.groupId,
            actorFingerprint: "member-0",
            baseEpoch: initial.epoch,
            previousTranscriptHash: initial.confirmedTranscriptHash,
            title: "Model Group 1"
        )

        let updated: GroupProtocolModelState
        switch initial.applying(valid) {
        case .accepted(let next):
            updated = next
        case .rejected(let reason):
            XCTFail("Expected valid update commit to be accepted: \(reason)")
            return
        }

        switch updated.applying(valid) {
        case .accepted:
            XCTFail("Expected replayed commit to be rejected.")
        case .rejected(let reason):
            XCTAssertEqual(reason, .staleEpoch)
        }

        let forked = SignedGroupCommit(
            operation: .update,
            groupId: updated.groupId,
            actorFingerprint: "member-0",
            baseEpoch: updated.epoch,
            previousTranscriptHash: initial.confirmedTranscriptHash,
            title: "Forked"
        )
        switch updated.applying(forked) {
        case .accepted:
            XCTFail("Expected forked transcript commit to be rejected.")
        case .rejected(let reason):
            XCTAssertEqual(reason, .transcriptMismatch)
        }
    }

    func testGroupProtocolModelPreservesEpochAndTranscriptInvariants() throws {
        let initial = GroupProtocolModelState(
            createdByFingerprint: "member-0",
            memberFingerprints: ["member-0", "member-1"]
        )
        let join = SignedGroupCommit(
            operation: .joinApprove,
            groupId: initial.groupId,
            actorFingerprint: "member-0",
            baseEpoch: initial.epoch,
            previousTranscriptHash: initial.confirmedTranscriptHash,
            addMemberFingerprints: ["member-2"]
        )

        let joined: GroupProtocolModelState
        switch initial.applying(join) {
        case .accepted(let next):
            joined = next
        case .rejected(let reason):
            XCTFail("Expected join approval to be accepted: \(reason)")
            return
        }

        XCTAssertEqual(joined.epoch, initial.epoch + 1)
        XCTAssertEqual(joined.epochState.lastCommit.previousTranscriptHash, initial.confirmedTranscriptHash)
        XCTAssertNotEqual(joined.confirmedTranscriptHash, initial.confirmedTranscriptHash)
        XCTAssertEqual(joined.memberFingerprints, ["member-0", "member-1", "member-2"])
        XCTAssertEqual(joined.epochState.lastCommit.memberFingerprints, joined.memberFingerprints)

        let duplicateJoin = SignedGroupCommit(
            operation: .joinApprove,
            groupId: joined.groupId,
            actorFingerprint: "member-0",
            baseEpoch: joined.epoch,
            previousTranscriptHash: joined.confirmedTranscriptHash,
            addMemberFingerprints: ["member-2"]
        )
        switch joined.applying(duplicateJoin) {
        case .accepted:
            XCTFail("Expected duplicate member add to be rejected.")
        case .rejected(let reason):
            XCTAssertEqual(reason, .invalidMemberMutation)
        }

        let noOp = SignedGroupCommit(
            operation: .update,
            groupId: joined.groupId,
            actorFingerprint: "member-0",
            baseEpoch: joined.epoch,
            previousTranscriptHash: joined.confirmedTranscriptHash
        )
        switch joined.applying(noOp) {
        case .accepted:
            XCTFail("Expected no-op group commit to be rejected.")
        case .rejected(let reason):
            XCTAssertEqual(reason, .noStateChange)
        }
    }
}
