import Foundation

public enum GroupProtocolModelCommitRejection: String, Codable, Equatable {
    case invalidGroupId
    case invalidActor
    case unauthorizedActor
    case staleEpoch
    case transcriptMismatch
    case createCommitAfterInitialization
    case invalidOperation
    case unauthorizedMemberMutation
    case invalidMemberMutation
    case notEnoughMembers
    case noStateChange
}

public enum GroupProtocolModelApplyResult: Equatable {
    case accepted(GroupProtocolModelState)
    case rejected(GroupProtocolModelCommitRejection)
}

public struct GroupProtocolModelState: Equatable {
    public let groupId: UUID
    public let title: String
    public let inboxId: String
    public let createdByFingerprint: String
    public let epochState: MLSGroupEpochState
    public let memberFingerprints: [String]

    public var epoch: UInt64 {
        epochState.epoch
    }

    public var confirmedTranscriptHash: Data {
        epochState.confirmedTranscriptHash
    }

    public init(
        groupId: UUID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
        title: String = "Model Group",
        inboxId: String = "model-group-inbox",
        createdByFingerprint: String,
        memberFingerprints: [String],
        createdAt: Date = Date(timeIntervalSince1970: 0)
    ) {
        let normalizedMembers = GroupProtocolModelState.normalized(memberFingerprints + [createdByFingerprint])
        let members = normalizedMembers.map { RelayGroupMember(fingerprint: $0, joinedAt: createdAt) }
        let epochState = MLSGroupEpochState.initial(
            groupId: groupId,
            title: title,
            inboxId: inboxId,
            createdByFingerprint: createdByFingerprint,
            members: members,
            createdAt: createdAt
        )
        self.init(
            groupId: groupId,
            title: title,
            inboxId: inboxId,
            createdByFingerprint: createdByFingerprint,
            epochState: epochState,
            memberFingerprints: normalizedMembers
        )
    }

    private init(
        groupId: UUID,
        title: String,
        inboxId: String,
        createdByFingerprint: String,
        epochState: MLSGroupEpochState,
        memberFingerprints: [String]
    ) {
        self.groupId = groupId
        self.title = title
        self.inboxId = inboxId
        self.createdByFingerprint = createdByFingerprint
        self.epochState = epochState
        self.memberFingerprints = GroupProtocolModelState.normalized(memberFingerprints)
    }

    public func applying(_ commit: SignedGroupCommit) -> GroupProtocolModelApplyResult {
        guard commit.groupId == groupId else {
            return .rejected(.invalidGroupId)
        }
        let actor = commit.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !actor.isEmpty else {
            return .rejected(.invalidActor)
        }
        guard memberFingerprints.contains(actor) || actor == createdByFingerprint else {
            return .rejected(.unauthorizedActor)
        }
        guard commit.baseEpoch == epoch else {
            return .rejected(.staleEpoch)
        }
        guard commit.previousTranscriptHash == confirmedTranscriptHash else {
            return .rejected(.transcriptMismatch)
        }
        guard commit.operation != .create else {
            return .rejected(.createCommitAfterInitialization)
        }

        let normalizedTitle = commit.title?.trimmingCharacters(in: .whitespacesAndNewlines)
        let titleChange = normalizedTitle.flatMap { $0.isEmpty ? nil : $0 }
        let addMembers = GroupProtocolModelState.normalized(
            commit.addMemberFingerprints + (commit.addMemberProfiles ?? []).map(\.fingerprint)
        )
        let removeMembers = GroupProtocolModelState.normalized(commit.removeMemberFingerprints)
        let isCreator = actor == createdByFingerprint

        guard commit.operation == expectedOperation(
            actor: actor,
            isCreator: isCreator,
            titleChange: titleChange,
            addMembers: addMembers,
            removeMembers: removeMembers
        ) else {
            return .rejected(.invalidOperation)
        }

        if !isCreator {
            guard titleChange == nil,
                  addMembers.isEmpty,
                  !removeMembers.isEmpty,
                  Set(removeMembers).isSubset(of: [actor]) else {
                return .rejected(.unauthorizedMemberMutation)
            }
        }

        if removeMembers.contains(createdByFingerprint) {
            return .rejected(.invalidMemberMutation)
        }

        var nextTitle = title
        var nextMembers = Set(memberFingerprints)
        var changed = false

        if let titleChange, titleChange != title {
            nextTitle = titleChange
            changed = true
        }

        for member in addMembers {
            guard !nextMembers.contains(member) else {
                return .rejected(.invalidMemberMutation)
            }
            nextMembers.insert(member)
            changed = true
        }

        for member in removeMembers {
            guard nextMembers.contains(member) else {
                return .rejected(.invalidMemberMutation)
            }
            nextMembers.remove(member)
            changed = true
        }

        guard nextMembers.count >= 2 || commit.operation == .selfLeave else {
            return .rejected(.notEnoughMembers)
        }
        guard changed else {
            return .rejected(.noStateChange)
        }

        let nextMemberFingerprints = nextMembers.sorted()
        let nextMembersForHash = nextMemberFingerprints.map {
            RelayGroupMember(fingerprint: $0, joinedAt: Date(timeIntervalSince1970: 0))
        }
        let nextEpochState = epochState.advancing(
            title: nextTitle,
            inboxId: inboxId,
            actorFingerprint: actor,
            members: nextMembersForHash,
            operation: commit.operation,
            committedAt: Date(timeIntervalSince1970: TimeInterval(epoch + 1)),
            ratchetSecretDistribution: nil
        )

        return .accepted(
            GroupProtocolModelState(
                groupId: groupId,
                title: nextTitle,
                inboxId: inboxId,
                createdByFingerprint: createdByFingerprint,
                epochState: nextEpochState,
                memberFingerprints: nextMemberFingerprints
            )
        )
    }

    fileprivate var stateKey: String {
        [
            String(epoch),
            title,
            confirmedTranscriptHash.base64EncodedString(),
            memberFingerprints.joined(separator: ",")
        ].joined(separator: "|")
    }

    fileprivate static func normalized(_ fingerprints: [String]) -> [String] {
        Array(
            Set(
                fingerprints.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .filter { !$0.isEmpty }
            )
        ).sorted()
    }

    private func expectedOperation(
        actor: String,
        isCreator: Bool,
        titleChange: String?,
        addMembers: [String],
        removeMembers: [String]
    ) -> MLSGroupCommitOperation {
        if isCreator,
           titleChange == nil,
           !addMembers.isEmpty,
           removeMembers.isEmpty {
            return .joinApprove
        }
        if !isCreator,
           titleChange == nil,
           addMembers.isEmpty,
           !removeMembers.isEmpty,
           Set(removeMembers).isSubset(of: [actor]) {
            return .selfLeave
        }
        if !addMembers.isEmpty {
            return removeMembers.isEmpty && titleChange == nil ? .addMembers : .update
        }
        if !removeMembers.isEmpty {
            return titleChange == nil ? .removeMembers : .update
        }
        return .update
    }
}

public struct GroupProtocolModelCheckReport: Equatable {
    public let exploredStates: Int
    public let acceptedTransitions: Int
    public let rejectedTransitions: Int
    public let maxDepth: Int
    public let violations: [String]
}

public enum GroupProtocolModelChecker {
    public static func verifySmallModel(
        candidateMemberCount: Int = 4,
        maxDepth: Int = 3
    ) -> GroupProtocolModelCheckReport {
        let candidates = (0..<max(2, candidateMemberCount)).map { "member-\($0)" }
        let initial = GroupProtocolModelState(
            createdByFingerprint: candidates[0],
            memberFingerprints: Array(candidates.prefix(2))
        )

        var explored = 0
        var accepted = 0
        var rejected = 0
        var violations: [String] = []
        var frontier: [(GroupProtocolModelState, Int)] = [(initial, 0)]
        var visited = Set<String>()

        while let (state, depth) = frontier.popLast() {
            guard visited.insert(state.stateKey).inserted else {
                continue
            }
            explored += 1
            guard depth < maxDepth else {
                continue
            }

            for commit in validCommits(from: state, candidates: candidates) {
                let result = state.applying(commit)
                switch result {
                case .accepted(let next):
                    accepted += 1
                    violations.append(contentsOf: invariantViolations(before: state, commit: commit, after: next))
                    frontier.append((next, depth + 1))
                    for invalid in invalidMutations(of: commit, from: state) {
                        switch state.applying(invalid) {
                        case .accepted:
                            violations.append("Invalid commit accepted at epoch \(state.epoch): \(invalid.operation)")
                        case .rejected:
                            rejected += 1
                        }
                    }
                case .rejected(let reason):
                    violations.append("Valid commit rejected at epoch \(state.epoch): \(commit.operation) \(reason.rawValue)")
                }
            }

            for invalid in standaloneInvalidCommits(from: state, candidates: candidates) {
                switch state.applying(invalid) {
                case .accepted:
                    violations.append("Standalone invalid commit accepted at epoch \(state.epoch): \(invalid.operation)")
                case .rejected:
                    rejected += 1
                }
            }
        }

        return GroupProtocolModelCheckReport(
            exploredStates: explored,
            acceptedTransitions: accepted,
            rejectedTransitions: rejected,
            maxDepth: maxDepth,
            violations: violations
        )
    }

    private static func validCommits(
        from state: GroupProtocolModelState,
        candidates: [String]
    ) -> [SignedGroupCommit] {
        var commits: [SignedGroupCommit] = []
        let creator = state.createdByFingerprint
        let outsiders = candidates.filter { !state.memberFingerprints.contains($0) }
        let removableMembers = state.memberFingerprints.filter { $0 != creator }

        if state.memberFingerprints.count >= 2 {
            commits.append(
                SignedGroupCommit(
                    operation: .update,
                    groupId: state.groupId,
                    actorFingerprint: creator,
                    baseEpoch: state.epoch,
                    previousTranscriptHash: state.confirmedTranscriptHash,
                    title: "Model Group \(state.epoch + 1)-\(state.confirmedTranscriptHash.prefix(2).base64EncodedString())"
                )
            )
        }

        for outsider in outsiders {
            commits.append(
                SignedGroupCommit(
                    operation: .joinApprove,
                    groupId: state.groupId,
                    actorFingerprint: creator,
                    baseEpoch: state.epoch,
                    previousTranscriptHash: state.confirmedTranscriptHash,
                    addMemberFingerprints: [outsider]
                )
            )
        }

        for member in removableMembers where state.memberFingerprints.count > 2 {
            commits.append(
                SignedGroupCommit(
                    operation: .removeMembers,
                    groupId: state.groupId,
                    actorFingerprint: creator,
                    baseEpoch: state.epoch,
                    previousTranscriptHash: state.confirmedTranscriptHash,
                    removeMemberFingerprints: [member]
                )
            )
        }

        for member in removableMembers {
            commits.append(
                SignedGroupCommit(
                    operation: .selfLeave,
                    groupId: state.groupId,
                    actorFingerprint: member,
                    baseEpoch: state.epoch,
                    previousTranscriptHash: state.confirmedTranscriptHash,
                    removeMemberFingerprints: [member]
                )
            )
        }

        return commits
    }

    private static func invalidMutations(
        of commit: SignedGroupCommit,
        from state: GroupProtocolModelState
    ) -> [SignedGroupCommit] {
        [
            SignedGroupCommit(
                operation: commit.operation,
                groupId: commit.groupId,
                actorFingerprint: commit.actorFingerprint,
                baseEpoch: state.epoch + 1,
                previousTranscriptHash: commit.previousTranscriptHash,
                title: commit.title,
                addMemberFingerprints: commit.addMemberFingerprints,
                addMemberProfiles: commit.addMemberProfiles,
                removeMemberFingerprints: commit.removeMemberFingerprints
            ),
            SignedGroupCommit(
                operation: commit.operation,
                groupId: commit.groupId,
                actorFingerprint: commit.actorFingerprint,
                baseEpoch: commit.baseEpoch,
                previousTranscriptHash: Data("wrong-transcript".utf8),
                title: commit.title,
                addMemberFingerprints: commit.addMemberFingerprints,
                addMemberProfiles: commit.addMemberProfiles,
                removeMemberFingerprints: commit.removeMemberFingerprints
            ),
            SignedGroupCommit(
                operation: .create,
                groupId: commit.groupId,
                actorFingerprint: commit.actorFingerprint,
                baseEpoch: commit.baseEpoch,
                previousTranscriptHash: commit.previousTranscriptHash,
                title: commit.title,
                addMemberFingerprints: commit.addMemberFingerprints,
                addMemberProfiles: commit.addMemberProfiles,
                removeMemberFingerprints: commit.removeMemberFingerprints
            ),
            SignedGroupCommit(
                operation: commit.operation,
                groupId: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
                actorFingerprint: commit.actorFingerprint,
                baseEpoch: commit.baseEpoch,
                previousTranscriptHash: commit.previousTranscriptHash,
                title: commit.title,
                addMemberFingerprints: commit.addMemberFingerprints,
                addMemberProfiles: commit.addMemberProfiles,
                removeMemberFingerprints: commit.removeMemberFingerprints
            )
        ]
    }

    private static func standaloneInvalidCommits(
        from state: GroupProtocolModelState,
        candidates: [String]
    ) -> [SignedGroupCommit] {
        let outsider = candidates.first { !state.memberFingerprints.contains($0) } ?? "outsider"
        let creator = state.createdByFingerprint
        return [
            SignedGroupCommit(
                operation: .update,
                groupId: state.groupId,
                actorFingerprint: outsider,
                baseEpoch: state.epoch,
                previousTranscriptHash: state.confirmedTranscriptHash,
                title: "Unauthorized"
            ),
            SignedGroupCommit(
                operation: .removeMembers,
                groupId: state.groupId,
                actorFingerprint: creator,
                baseEpoch: state.epoch,
                previousTranscriptHash: state.confirmedTranscriptHash,
                removeMemberFingerprints: [creator]
            ),
            SignedGroupCommit(
                operation: .joinApprove,
                groupId: state.groupId,
                actorFingerprint: creator,
                baseEpoch: state.epoch,
                previousTranscriptHash: state.confirmedTranscriptHash,
                addMemberFingerprints: [state.memberFingerprints[0]]
            ),
            SignedGroupCommit(
                operation: .update,
                groupId: state.groupId,
                actorFingerprint: creator,
                baseEpoch: state.epoch,
                previousTranscriptHash: state.confirmedTranscriptHash
            )
        ]
    }

    private static func invariantViolations(
        before: GroupProtocolModelState,
        commit: SignedGroupCommit,
        after: GroupProtocolModelState
    ) -> [String] {
        var violations: [String] = []
        if after.epoch != before.epoch + 1 {
            violations.append("Accepted commit did not advance epoch by one.")
        }
        if after.epochState.lastCommit.previousTranscriptHash != before.confirmedTranscriptHash {
            violations.append("Accepted commit did not bind previous transcript.")
        }
        if after.confirmedTranscriptHash == before.confirmedTranscriptHash {
            violations.append("Accepted commit did not change transcript.")
        }
        if after.epochState.lastCommit.operation != commit.operation {
            violations.append("Accepted commit summary operation mismatch.")
        }
        if after.epochState.lastCommit.memberFingerprints != after.memberFingerprints {
            violations.append("Accepted commit summary member set mismatch.")
        }
        if !after.memberFingerprints.contains(after.createdByFingerprint) {
            violations.append("Creator disappeared from live member set.")
        }
        return violations
    }
}
