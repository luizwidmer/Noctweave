import CryptoKit
import Foundation

private struct StrictPQGroupCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

private func requireExactPQGroupKeys<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _ keyType: Key.Type
) throws where Key.AllCases: Collection {
    let strict = try decoder.container(keyedBy: StrictPQGroupCodingKey.self)
    guard Set(strict.allKeys.map(\.stringValue))
            == Set(keyType.allCases.map(\.stringValue)) else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "Group credential fields must match the current schema exactly"
            )
        )
    }
}

private func requirePQGroupCredentialAlgorithms(
    signingPublicKey: Data,
    agreementPublicKey: Data
) throws {
    try GroupCryptographicRuntimeProbeV2.requireAlgorithms(
        signingPublicKey: signingPublicKey,
        agreementPublicKey: agreementPublicKey
    )
}

private func requirePQGroupCredentialAlgorithms(
    _ credentials: [GroupProviderCredentialV2]
) throws {
    try GroupCryptographicRuntimeProbeV2.requireAlgorithms(
        signingPublicKey: credentials.first?.signingPublicKey ?? Data(),
        agreementPublicKey: credentials.first?.agreementPublicKey ?? Data()
    )
}

public enum NoctweavePQGroupExperimentalErrorV2: Error, Equatable {
    case invalidCredential
    case invalidMembership
    case invalidState
    case inactiveState
    case invalidCommit
    case invalidEpochPackage
    case wrongDestination
    case staleEpoch
    case localCredentialRemoved
    case invalidApplicationEnvelope
    case replay
    case outOfOrder
    case authenticationFailed
    case counterExhausted
}

/// Private material for the single active credential of one group-scoped member.
public struct LocalGroupCredentialV2: Codable, Equatable {
    public let groupId: UUID
    public let memberHandle: GroupScopedMemberHandleV2
    public let credentialHandle: GroupScopedCredentialHandleV2
    public let admissionDigest: Data
    public let signingKey: SigningKeyPair
    public let agreementKey: AgreementKeyPair

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case groupId
        case memberHandle
        case credentialHandle
        case admissionDigest
        case signingKey
        case agreementKey
    }

    public init(
        groupId: UUID,
        memberHandle: GroupScopedMemberHandleV2,
        credentialHandle: GroupScopedCredentialHandleV2,
        admissionDigest: Data,
        signingKey: SigningKeyPair,
        agreementKey: AgreementKeyPair
    ) {
        self.groupId = groupId
        self.memberHandle = memberHandle
        self.credentialHandle = credentialHandle
        self.admissionDigest = admissionDigest
        self.signingKey = signingKey
        self.agreementKey = agreementKey
    }

    public init(from decoder: Decoder) throws {
        try requireExactPQGroupKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            groupId: try values.decode(UUID.self, forKey: .groupId),
            memberHandle: try values.decode(GroupScopedMemberHandleV2.self, forKey: .memberHandle),
            credentialHandle: try values.decode(GroupScopedCredentialHandleV2.self, forKey: .credentialHandle),
            admissionDigest: try values.decode(Data.self, forKey: .admissionDigest),
            signingKey: try values.decode(SigningKeyPair.self, forKey: .signingKey),
            agreementKey: try values.decode(AgreementKeyPair.self, forKey: .agreementKey)
        )
        guard try isStructurallyValidThrowing else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid local group credential")
            )
        }
    }

    /// Throwing protocol preflight. Local ML-DSA/ML-KEM runtime failures are
    /// preserved; the nonthrowing wrapper remains available for diagnostics.
    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard memberHandle.isStructurallyValid,
                  credentialHandle.isStructurallyValid,
                  admissionDigest.count == 32 else {
                return false
            }
            guard try SigningKeyPair.isValidPublicKeyThrowing(signingKey.publicKeyData) else {
                return false
            }
            return try AgreementKeyPair.isValidPublicKeyThrowing(agreementKey.publicKeyData)
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    public static func == (
        lhs: LocalGroupCredentialV2,
        rhs: LocalGroupCredentialV2
    ) -> Bool {
        lhs.groupId == rhs.groupId
            && lhs.memberHandle == rhs.memberHandle
            && lhs.credentialHandle == rhs.credentialHandle
            && lhs.admissionDigest == rhs.admissionDigest
            && lhs.signingKey.privateKeyData == rhs.signingKey.privateKeyData
            && lhs.signingKey.publicKeyData == rhs.signingKey.publicKeyData
            && lhs.agreementKey.privateKeyData == rhs.agreementKey.privateKeyData
            && lhs.agreementKey.publicKeyData == rhs.agreementKey.publicKeyData
    }
}

public enum NoctweavePQGroupCryptoActivationV2: String, Codable, Equatable {
    case provisional
    case active
}

public struct NoctweavePQGroupApplicationSealV2: Codable, Equatable {
    public let state: GroupCryptoState
    public let envelope: GroupApplicationEnvelopeV2

    public init(state: GroupCryptoState, envelope: GroupApplicationEnvelopeV2) {
        self.state = state
        self.envelope = envelope
    }
}

public struct NoctweavePQGroupApplicationOpenV2: Codable, Equatable {
    public let state: GroupCryptoState
    public let plaintext: Data

    public init(state: GroupCryptoState, plaintext: Data) {
        self.state = state
        self.plaintext = plaintext
    }
}

/// Experimental, non-MLS group cryptography for the signed v2 group state.
/// Every private-key operation takes an explicit group-only credential.
public struct NoctweavePQGroupExperimentalProviderV2 {
    public static let selection = GroupProtocolSelectionV2.currentExperimental
    private static let stateVersion = 1

    public init() {}

    public func membership(from state: SignedGroupStateV2) throws -> GroupProviderMembershipV2 {
        try membership(
            groupId: state.groupId,
            epoch: state.epoch,
            members: state.members,
            leaves: state.memberCredentials
        )
    }

    public func membership(
        groupId: UUID,
        epoch: UInt64,
        members: [GroupMemberV2],
        leaves: [GroupMemberCredentialV2]
    ) throws -> GroupProviderMembershipV2 {
        try GroupCryptographicRuntimeProbeV2.requireAlgorithms(
            signingPublicKey: leaves.first?.signingPublicKey ?? Data(),
            agreementPublicKey: leaves.first?.agreementPublicKey ?? Data()
        )
        guard epoch > 0 else { throw NoctweavePQGroupExperimentalErrorV2.invalidMembership }
        let activeMemberHandles = Set(members.filter { $0.isActive(at: epoch) }.map(\.id))
        let credentials = leaves.filter {
            $0.isActive(at: epoch) && activeMemberHandles.contains($0.memberHandle)
        }.map {
            GroupProviderCredentialV2(
                memberHandle: $0.memberHandle,
                credentialHandle: $0.credentialHandle,
                admissionDigest: $0.admissionDigest,
                signingPublicKey: $0.signingPublicKey,
                agreementPublicKey: $0.agreementPublicKey
            )
        }.sorted { $0.credentialHandle.rawValue < $1.credentialHandle.rawValue }
        guard !credentials.isEmpty,
              credentials.count <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalCredentials,
              credentials.count == activeMemberHandles.count,
              Set(credentials.map(\.memberHandle)).count == credentials.count else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidMembership
        }
        let digestPayload = PQGroupMembershipDigestPayloadV2(
            groupId: groupId,
            epoch: epoch,
            selection: Self.selection,
            credentials: credentials
        )
        let membership = GroupProviderMembershipV2(
            groupId: groupId,
            epoch: epoch,
            selection: Self.selection,
            credentials: credentials,
            membershipDigest: try pqGroupDigest(
                domain: "Noctweave/PQGroupExperimentalV2/membership",
                encoded: digestPayload
            )
        )
        guard membership.isStructurallyValid else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidMembership
        }
        return membership
    }

    public func activationState(
        of state: GroupCryptoState
    ) throws -> NoctweavePQGroupCryptoActivationV2 {
        try decodeState(state).activation
    }

    public func validateActiveState(
        _ state: GroupCryptoState,
        signedState: SignedGroupStateV2,
        localCredential: LocalGroupCredentialV2
    ) throws {
        let localState = try requireActiveState(state)
        try validateSignedBinding(localState, signedState: signedState)
        try validate(localCredential, in: try membership(from: signedState))
        guard localState.localCredentialHandle == localCredential.credentialHandle else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidCredential
        }
    }

    /// Validates the transient next-epoch state retained while a member's
    /// self-authored removal is being delivered. The local credential is
    /// deliberately absent from the next active membership, so this state may
    /// only be used to finish the exact removal fanout and must never authorize
    /// new group application traffic.
    public func validateSelfRemovalState(
        _ state: GroupCryptoState,
        signedState: SignedGroupStateV2,
        removedLocalCredential: LocalGroupCredentialV2
    ) throws {
        let localState = try requireActiveState(state)
        try validateSignedBinding(localState, signedState: signedState)
        guard try removedLocalCredential.isStructurallyValidThrowing,
              removedLocalCredential.groupId == signedState.groupId,
              localState.localCredentialHandle == removedLocalCredential.credentialHandle,
              let removedLeaf = signedState.memberCredentials.first(where: {
                  $0.credentialHandle == removedLocalCredential.credentialHandle
              }),
              removedLeaf.memberHandle == removedLocalCredential.memberHandle,
              removedLeaf.admissionDigest == removedLocalCredential.admissionDigest,
              removedLeaf.signingPublicKey == removedLocalCredential.signingKey.publicKeyData,
              removedLeaf.agreementPublicKey == removedLocalCredential.agreementKey.publicKeyData,
              removedLeaf.removedEpoch == signedState.epoch,
              !signedState.activeCredentials.contains(where: {
                  $0.memberHandle == removedLocalCredential.memberHandle
              }) else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidCredential
        }
    }

    public func prepareGenesis(
        membership: GroupProviderMembershipV2,
        localCredential: LocalGroupCredentialV2
    ) throws -> GroupCryptoPreparedEpochV2 {
        try validateMembership(membership)
        try validate(localCredential, in: membership)
        guard membership.epoch == 1 else {
            throw NoctweavePQGroupExperimentalErrorV2.staleEpoch
        }
        let proposal = GroupCryptoEpochProposalV2(
            groupId: membership.groupId,
            baseEpoch: 0,
            nextEpoch: 1,
            selection: Self.selection,
            currentMembershipDigest: nil,
            proposedMembershipDigest: membership.membershipDigest,
            authorCredentialHandle: localCredential.credentialHandle
        )
        return try makePreparedEpoch(
            proposal: proposal,
            proposedMembership: membership,
            localCredentialHandle: localCredential.credentialHandle
        )
    }

    public func prepareCommit(
        state: GroupCryptoState,
        currentMembership: GroupProviderMembershipV2,
        proposedMembership: GroupProviderMembershipV2,
        localCredential: LocalGroupCredentialV2,
        nextLocalCredential: LocalGroupCredentialV2? = nil,
        allowLocalSelfRemoval: Bool = false
    ) throws -> GroupCryptoPreparedEpochV2 {
        let localState = try requireActiveState(state)
        try validateMembership(currentMembership)
        try validateMembership(proposedMembership)
        try validate(localCredential, in: currentMembership)
        let nextCredentialHandle: GroupScopedCredentialHandleV2
        if allowLocalSelfRemoval {
            guard nextLocalCredential == nil,
                  !proposedMembership.credentials.contains(where: {
                      $0.memberHandle == localCredential.memberHandle
                  }) else {
                throw NoctweavePQGroupExperimentalErrorV2.invalidCredential
            }
            nextCredentialHandle = localCredential.credentialHandle
        } else {
            let nextCredential = nextLocalCredential ?? localCredential
            try validate(nextCredential, in: proposedMembership)
            guard nextCredential.groupId == localCredential.groupId,
                  nextCredential.memberHandle == localCredential.memberHandle else {
                throw NoctweavePQGroupExperimentalErrorV2.invalidCredential
            }
            nextCredentialHandle = nextCredential.credentialHandle
        }
        guard localState.groupId == currentMembership.groupId,
              localState.epoch == currentMembership.epoch,
              localState.membershipDigest == currentMembership.membershipDigest,
              localState.localCredentialHandle == localCredential.credentialHandle,
              proposedMembership.groupId == currentMembership.groupId,
              currentMembership.epoch < UInt64.max,
              proposedMembership.epoch == currentMembership.epoch + 1 else {
            throw NoctweavePQGroupExperimentalErrorV2.staleEpoch
        }
        let proposal = GroupCryptoEpochProposalV2(
            groupId: currentMembership.groupId,
            baseEpoch: currentMembership.epoch,
            nextEpoch: proposedMembership.epoch,
            selection: Self.selection,
            currentMembershipDigest: currentMembership.membershipDigest,
            proposedMembershipDigest: proposedMembership.membershipDigest,
            authorCredentialHandle: localCredential.credentialHandle
        )
        return try makePreparedEpoch(
            proposal: proposal,
            proposedMembership: proposedMembership,
            localCredentialHandle: nextCredentialHandle
        )
    }

    public func finalizePreparedEpoch(
        _ prepared: GroupCryptoPreparedEpochV2,
        acceptance: GroupCryptoAcceptedEpochV2
    ) throws -> GroupCryptoState {
        guard prepared.isStructurallyValid,
              acceptance.isStructurallyValid,
              prepared.proposal == acceptance.proposal,
              prepared.providerCommitDigest == acceptance.providerCommitDigest else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidCommit
        }
        let commit = try decodeAndValidateCommit(
            prepared.commitBytes,
            acceptance: acceptance
        )
        try validatePreparedPackages(prepared.welcomes, against: commit)
        var localState = try decodeState(prepared.provisionalState)
        guard localState.activation == .provisional,
              localState.providerCommitDigest == acceptance.providerCommitDigest,
              localState.epochSecretCommitment == commit.epochSecretCommitment else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidState
        }
        localState = localState.activating(
            signedCommitDigest: acceptance.signedCommitDigest,
            acceptedTranscriptHash: acceptance.acceptedTranscriptHash
        )
        return try encodeState(localState)
    }

    public func processCommit(
        state: GroupCryptoState,
        currentMembership: GroupProviderMembershipV2,
        proposedMembership: GroupProviderMembershipV2,
        acceptance: GroupCryptoAcceptedEpochV2,
        commitBytes: Data,
        localPackage: GroupWelcomePackage,
        localCredential: LocalGroupCredentialV2
    ) throws -> GroupCryptoState {
        let currentState = try requireActiveState(state)
        try validateMembership(currentMembership)
        try validateMembership(proposedMembership)
        try validate(localCredential, in: currentMembership)
        guard currentState.localCredentialHandle == localCredential.credentialHandle,
              currentState.epoch == currentMembership.epoch,
              currentState.membershipDigest == currentMembership.membershipDigest,
              proposedMembership.groupId == currentMembership.groupId,
              currentMembership.epoch < UInt64.max,
              proposedMembership.epoch == currentMembership.epoch + 1,
              acceptance.proposal.baseEpoch == currentMembership.epoch,
              acceptance.proposal.nextEpoch == proposedMembership.epoch,
              acceptance.proposal.currentMembershipDigest == currentMembership.membershipDigest,
              acceptance.proposal.proposedMembershipDigest == proposedMembership.membershipDigest else {
            throw NoctweavePQGroupExperimentalErrorV2.staleEpoch
        }
        guard proposedMembership.credentials.contains(where: {
            $0.credentialHandle == localCredential.credentialHandle
        }) else {
            throw NoctweavePQGroupExperimentalErrorV2.localCredentialRemoved
        }
        let commit = try decodeAndValidateCommit(commitBytes, acceptance: acceptance)
        return try openEpochPackage(
            localPackage,
            commit: commit,
            membership: proposedMembership,
            acceptance: acceptance,
            localCredential: localCredential
        )
    }

    public func processWelcome(
        _ welcome: GroupWelcomePackage,
        membership: GroupProviderMembershipV2,
        acceptance: GroupCryptoAcceptedEpochV2,
        commitBytes: Data,
        localCredential: LocalGroupCredentialV2
    ) throws -> GroupCryptoState {
        try validateMembership(membership)
        try validate(localCredential, in: membership)
        guard acceptance.proposal.groupId == membership.groupId,
              acceptance.proposal.nextEpoch == membership.epoch,
              acceptance.proposal.proposedMembershipDigest == membership.membershipDigest else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidCommit
        }
        let commit = try decodeAndValidateCommit(commitBytes, acceptance: acceptance)
        return try openEpochPackage(
            welcome,
            commit: commit,
            membership: membership,
            acceptance: acceptance,
            localCredential: localCredential
        )
    }

    public func encryptApplicationEvent(
        _ event: Data,
        state: GroupCryptoState,
        signedState: SignedGroupStateV2,
        localCredential: LocalGroupCredentialV2,
        eventId: UUID = UUID(),
        sentAt: Date = Date()
    ) throws -> NoctweavePQGroupApplicationSealV2 {
        guard !event.isEmpty,
              event.count <= NoctweaveArchitectureV2.maximumContentPayloadBytes else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidApplicationEnvelope
        }
        var localState = try requireActiveState(state)
        try validateSignedBinding(localState, signedState: signedState)
        try validate(localCredential, in: try membership(from: signedState))
        guard localState.localCredentialHandle == localCredential.credentialHandle,
              let chainIndex = localState.senderChains.firstIndex(where: {
                  $0.credentialHandle == localCredential.credentialHandle
              }) else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidCredential
        }
        var chain = localState.senderChains[chainIndex]
        guard chain.nextSendCounter < UInt64.max else {
            throw NoctweavePQGroupExperimentalErrorV2.counterExhausted
        }
        let bucketedSentAt = pqGroupBucketedDate(sentAt)
        let aad = try applicationAAD(
            state: localState,
            senderCredentialHandle: localCredential.credentialHandle,
            eventId: eventId,
            messageCounter: chain.nextSendCounter,
            sentAt: bucketedSentAt
        )
        let messageKey = deriveMessageKey(
            chainKey: chain.sendChainKey,
            groupId: localState.groupId,
            epoch: localState.epoch,
            credentialHandle: chain.credentialHandle,
            counter: chain.nextSendCounter
        )
        let payload = try CryptoBox.encrypt(
            event,
            key: SymmetricKey(data: messageKey),
            authenticatedData: aad
        )
        let envelope = try GroupApplicationEnvelopeV2.create(
            groupId: localState.groupId,
            epoch: localState.epoch,
            transcriptHash: try requiredTranscriptHash(localState),
            senderCredentialHandle: localCredential.credentialHandle,
            eventId: eventId,
            messageCounter: chain.nextSendCounter,
            sentAt: bucketedSentAt,
            payload: payload,
            signingKey: localCredential.signingKey
        )
        chain = chain.advancingSend(
            nextKey: deriveNextChainKey(
                chainKey: chain.sendChainKey,
                groupId: localState.groupId,
                epoch: localState.epoch,
                credentialHandle: chain.credentialHandle,
                counter: chain.nextSendCounter
            )
        )
        localState.senderChains[chainIndex] = chain
        return NoctweavePQGroupApplicationSealV2(
            state: try encodeState(localState),
            envelope: envelope
        )
    }

    public func decryptApplicationEvent(
        _ envelope: GroupApplicationEnvelopeV2,
        state: GroupCryptoState,
        signedState: SignedGroupStateV2
    ) throws -> NoctweavePQGroupApplicationOpenV2 {
        var localState = try requireActiveState(state)
        try validateSignedBinding(localState, signedState: signedState)
        guard envelope.isStructurallyValid,
              envelope.groupId == signedState.groupId,
              envelope.epoch == signedState.epoch,
              envelope.transcriptHash == signedState.confirmedTranscriptHash,
              let senderLeaf = signedState.activeCredentials.first(where: {
                  $0.credentialHandle == envelope.senderCredentialHandle
              }),
              try envelope.verifySignatureThrowing(
                  groupCredentialSigningPublicKey: senderLeaf.signingPublicKey
              ),
              let chainIndex = localState.senderChains.firstIndex(where: {
                  $0.credentialHandle == envelope.senderCredentialHandle
              }) else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidApplicationEnvelope
        }
        var chain = localState.senderChains[chainIndex]
        if envelope.messageCounter < chain.nextReceiveCounter {
            throw NoctweavePQGroupExperimentalErrorV2.replay
        }
        guard envelope.messageCounter == chain.nextReceiveCounter else {
            throw NoctweavePQGroupExperimentalErrorV2.outOfOrder
        }
        guard chain.nextReceiveCounter < UInt64.max else {
            throw NoctweavePQGroupExperimentalErrorV2.counterExhausted
        }
        let aad = try applicationAAD(
            state: localState,
            senderCredentialHandle: envelope.senderCredentialHandle,
            eventId: envelope.eventId,
            messageCounter: envelope.messageCounter,
            sentAt: envelope.sentAt
        )
        let messageKey = deriveMessageKey(
            chainKey: chain.receiveChainKey,
            groupId: localState.groupId,
            epoch: localState.epoch,
            credentialHandle: chain.credentialHandle,
            counter: chain.nextReceiveCounter
        )
        let plaintext: Data
        do {
            plaintext = try CryptoBox.decrypt(
                envelope.payload,
                key: SymmetricKey(data: messageKey),
                authenticatedData: aad
            )
        } catch CryptoError.invalidPayload {
            throw NoctweavePQGroupExperimentalErrorV2.authenticationFailed
        } catch {
            throw error
        }
        guard !plaintext.isEmpty,
              plaintext.count <= NoctweaveArchitectureV2.maximumContentPayloadBytes else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidApplicationEnvelope
        }
        chain = chain.advancingReceive(
            nextKey: deriveNextChainKey(
                chainKey: chain.receiveChainKey,
                groupId: localState.groupId,
                epoch: localState.epoch,
                credentialHandle: chain.credentialHandle,
                counter: chain.nextReceiveCounter
            )
        )
        localState.senderChains[chainIndex] = chain
        return NoctweavePQGroupApplicationOpenV2(
            state: try encodeState(localState),
            plaintext: plaintext
        )
    }

    private func makePreparedEpoch(
        proposal: GroupCryptoEpochProposalV2,
        proposedMembership: GroupProviderMembershipV2,
        localCredentialHandle: GroupScopedCredentialHandleV2
    ) throws -> GroupCryptoPreparedEpochV2 {
        guard proposal.isStructurallyValid,
              proposedMembership.membershipDigest == proposal.proposedMembershipDigest,
              proposedMembership.epoch == proposal.nextEpoch,
              proposedMembership.groupId == proposal.groupId else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidCommit
        }
        let epochSecret = pqGroupRandomData(count: 32)
        let commitment = epochSecretCommitment(
            epochSecret: epochSecret,
            groupId: proposal.groupId,
            epoch: proposal.nextEpoch
        )
        var cores: [PQGroupEpochSecretPackageCoreV2] = []
        var entries: [PQGroupDestinationAdmissionDigestV2] = []
        for credential in proposedMembership.credentials {
            let core = try makePackageCore(
                proposal: proposal,
                credential: credential,
                epochSecret: epochSecret,
                commitment: commitment
            )
            cores.append(core)
            entries.append(PQGroupDestinationAdmissionDigestV2(
                destinationCredentialHandle: credential.credentialHandle,
                packageDigest: try packageDigest(core)
            ))
        }
        entries.sort { $0.destinationCredentialHandle.rawValue < $1.destinationCredentialHandle.rawValue }
        let commit = PQGroupEpochCommitV2(
            proposal: proposal,
            epochSecretCommitment: commitment,
            destinationPackageDigests: entries
        )
        guard commit.isStructurallyValid else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidCommit
        }
        let commitBytes = try NoctweaveCoder.encode(commit, sortedKeys: true)
        let providerCommitDigest = Data(SHA256.hash(data: commitBytes))
        let welcomes = try cores.map { core in
            GroupWelcomePackage(
                destination: core.destinationCredentialHandle,
                bytes: try NoctweaveCoder.encode(
                    PQGroupEpochSecretPackageV2(
                        core: core,
                        epochSecretCommitment: commitment,
                        destinationPackageDigests: entries
                    ),
                    sortedKeys: true
                )
            )
        }
        let provisional = try makeLocalState(
            proposal: proposal,
            membership: proposedMembership,
            localCredentialHandle: localCredentialHandle,
            epochSecret: epochSecret,
            commitment: commitment,
            providerCommitDigest: providerCommitDigest,
            activation: .provisional,
            signedCommitDigest: nil,
            acceptedTranscriptHash: nil
        )
        let prepared = GroupCryptoPreparedEpochV2(
            proposal: proposal,
            provisionalState: provisional,
            commitBytes: commitBytes,
            welcomes: welcomes
        )
        guard prepared.isStructurallyValid else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidState
        }
        return prepared
    }

    private func makePackageCore(
        proposal: GroupCryptoEpochProposalV2,
        credential: GroupProviderCredentialV2,
        epochSecret: Data,
        commitment: Data
    ) throws -> PQGroupEpochSecretPackageCoreV2 {
        let kemOutput = try AgreementKeyPair.encapsulate(to: credential.agreementPublicKey)
        var sharedSecret = kemOutput.sharedSecret
        defer { sharedSecret.secureWipe() }
        let wrapKey = derivePackageKey(
            sharedSecret: sharedSecret,
            proposal: proposal,
            credential: credential,
            commitment: commitment
        )
        let plaintext = PQGroupEpochSecretPlaintextV2(
            groupId: proposal.groupId,
            epoch: proposal.nextEpoch,
            proposedMembershipDigest: proposal.proposedMembershipDigest,
            epochSecret: epochSecret,
            epochSecretCommitment: commitment
        )
        let aad = try packageAAD(
            proposal: proposal,
            destinationCredentialHandle: credential.credentialHandle,
            destinationAdmissionDigest: credential.admissionDigest,
            commitment: commitment
        )
        let sealed = try CryptoBox.encrypt(
            try NoctweaveCoder.encode(plaintext, sortedKeys: true),
            key: SymmetricKey(data: wrapKey),
            authenticatedData: aad
        )
        return PQGroupEpochSecretPackageCoreV2(
            groupId: proposal.groupId,
            epoch: proposal.nextEpoch,
            destinationCredentialHandle: credential.credentialHandle,
            destinationAdmissionDigest: credential.admissionDigest,
            kemCiphertext: kemOutput.ciphertext,
            encryptedEpochSecret: sealed
        )
    }

    private func openEpochPackage(
        _ welcome: GroupWelcomePackage,
        commit: PQGroupEpochCommitV2,
        membership: GroupProviderMembershipV2,
        acceptance: GroupCryptoAcceptedEpochV2,
        localCredential: LocalGroupCredentialV2
    ) throws -> GroupCryptoState {
        guard welcome.destination == localCredential.credentialHandle,
              let credential = membership.credentials.first(where: {
                  $0.credentialHandle == localCredential.credentialHandle
              }) else {
            throw NoctweavePQGroupExperimentalErrorV2.wrongDestination
        }
        let package: PQGroupEpochSecretPackageV2
        do {
            package = try decodePQGroupExact(
                PQGroupEpochSecretPackageV2.self,
                from: welcome.bytes
            )
        } catch {
            throw NoctweavePQGroupExperimentalErrorV2.invalidEpochPackage
        }
        guard package.isStructurallyValid,
              package.core.groupId == membership.groupId,
              package.core.epoch == membership.epoch,
              package.core.destinationCredentialHandle == localCredential.credentialHandle,
              package.core.destinationAdmissionDigest == localCredential.admissionDigest,
              package.epochSecretCommitment == commit.epochSecretCommitment,
              package.destinationPackageDigests == commit.destinationPackageDigests,
              let entry = commit.destinationPackageDigests.first(where: {
                  $0.destinationCredentialHandle == localCredential.credentialHandle
              }),
              entry.packageDigest == (try? packageDigest(package.core)) else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidEpochPackage
        }
        var sharedSecret: Data
        do {
            sharedSecret = try localCredential.agreementKey.decapsulate(
                ciphertext: package.core.kemCiphertext
            )
        } catch CryptoError.invalidPayload {
            throw NoctweavePQGroupExperimentalErrorV2.authenticationFailed
        } catch {
            // Algorithm/runtime failures are local and retryable. Do not
            // misclassify them as peer authentication failures.
            throw error
        }
        defer { sharedSecret.secureWipe() }
        let wrapKey = derivePackageKey(
            sharedSecret: sharedSecret,
            proposal: commit.proposal,
            credential: credential,
            commitment: commit.epochSecretCommitment
        )
        let aad = try packageAAD(
            proposal: commit.proposal,
            destinationCredentialHandle: credential.credentialHandle,
            destinationAdmissionDigest: credential.admissionDigest,
            commitment: commit.epochSecretCommitment
        )
        let opened: Data
        do {
            opened = try CryptoBox.decrypt(
                package.core.encryptedEpochSecret,
                key: SymmetricKey(data: wrapKey),
                authenticatedData: aad
            )
        } catch CryptoError.invalidPayload {
            throw NoctweavePQGroupExperimentalErrorV2.authenticationFailed
        } catch {
            throw error
        }
        let plaintext: PQGroupEpochSecretPlaintextV2
        do {
            plaintext = try decodePQGroupExact(
                PQGroupEpochSecretPlaintextV2.self,
                from: opened
            )
        } catch {
            throw NoctweavePQGroupExperimentalErrorV2.invalidEpochPackage
        }
        guard plaintext.groupId == membership.groupId,
              plaintext.epoch == membership.epoch,
              plaintext.proposedMembershipDigest == membership.membershipDigest,
              plaintext.epochSecret.count == 32,
              plaintext.epochSecretCommitment == commit.epochSecretCommitment,
              epochSecretCommitment(
                  epochSecret: plaintext.epochSecret,
                  groupId: membership.groupId,
                  epoch: membership.epoch
              ) == commit.epochSecretCommitment else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidEpochPackage
        }
        return try makeLocalState(
            proposal: commit.proposal,
            membership: membership,
            localCredentialHandle: localCredential.credentialHandle,
            epochSecret: plaintext.epochSecret,
            commitment: commit.epochSecretCommitment,
            providerCommitDigest: acceptance.providerCommitDigest,
            activation: .active,
            signedCommitDigest: acceptance.signedCommitDigest,
            acceptedTranscriptHash: acceptance.acceptedTranscriptHash
        )
    }

    private func decodeAndValidateCommit(
        _ bytes: Data,
        acceptance: GroupCryptoAcceptedEpochV2
    ) throws -> PQGroupEpochCommitV2 {
        guard !bytes.isEmpty,
              bytes.count <= NoctweaveGroupArchitectureV2.maximumCommitBytes,
              acceptance.isStructurallyValid,
              Data(SHA256.hash(data: bytes)) == acceptance.providerCommitDigest else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidCommit
        }
        let commit: PQGroupEpochCommitV2
        do {
            commit = try decodePQGroupExact(PQGroupEpochCommitV2.self, from: bytes)
        } catch {
            throw NoctweavePQGroupExperimentalErrorV2.invalidCommit
        }
        guard commit.isStructurallyValid,
              commit.proposal == acceptance.proposal else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidCommit
        }
        return commit
    }

    private func validatePreparedPackages(
        _ welcomes: [GroupWelcomePackage],
        against commit: PQGroupEpochCommitV2
    ) throws {
        guard welcomes.count == commit.destinationPackageDigests.count,
              Set(welcomes.map(\.destination)).count == welcomes.count else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidEpochPackage
        }
        for welcome in welcomes {
            guard let package = try? decodePQGroupExact(
                PQGroupEpochSecretPackageV2.self,
                from: welcome.bytes
            ),
                package.isStructurallyValid,
                package.core.destinationCredentialHandle == welcome.destination,
                package.epochSecretCommitment == commit.epochSecretCommitment,
                package.destinationPackageDigests == commit.destinationPackageDigests,
                let entry = commit.destinationPackageDigests.first(where: {
                    $0.destinationCredentialHandle == welcome.destination
                }),
                entry.packageDigest == (try? packageDigest(package.core)) else {
                throw NoctweavePQGroupExperimentalErrorV2.invalidEpochPackage
            }
        }
    }

    private func validateMembership(_ membership: GroupProviderMembershipV2) throws {
        try requirePQGroupCredentialAlgorithms(membership.credentials)
        guard membership.isStructurallyValid,
              membership.selection == Self.selection,
              membership.credentials.count <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalCredentials,
              membership.membershipDigest == (try? pqGroupDigest(
                  domain: "Noctweave/PQGroupExperimentalV2/membership",
                  encoded: PQGroupMembershipDigestPayloadV2(
                      groupId: membership.groupId,
                      epoch: membership.epoch,
                      selection: membership.selection,
                      credentials: membership.credentials
                  )
              )) else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidMembership
        }
    }

    private func validate(
        _ credential: LocalGroupCredentialV2,
        in membership: GroupProviderMembershipV2
    ) throws {
        guard try credential.isStructurallyValidThrowing,
              credential.groupId == membership.groupId,
              let projectedCredential = membership.credentials.first(where: {
                  $0.credentialHandle == credential.credentialHandle
              }),
              projectedCredential.memberHandle == credential.memberHandle,
              projectedCredential.admissionDigest == credential.admissionDigest,
              projectedCredential.signingPublicKey == credential.signingKey.publicKeyData,
              projectedCredential.agreementPublicKey == credential.agreementKey.publicKeyData else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidCredential
        }
    }

    private func validateSignedBinding(
        _ localState: PQGroupLocalCryptoStateV2,
        signedState: SignedGroupStateV2
    ) throws {
        try GroupCryptographicRuntimeProbeV2.requireAlgorithms(
            signingPublicKey: signedState.memberCredentials.first?.signingPublicKey ?? Data(),
            agreementPublicKey: signedState.memberCredentials.first?.agreementPublicKey ?? Data()
        )
        guard signedState.isStructurallyValid,
              localState.activation == .active,
              signedState.groupId == localState.groupId,
              signedState.epoch == localState.epoch,
              signedState.profile == Self.selection.profile,
              signedState.cipherSuite == Self.selection.cipherSuite,
              signedState.commitDigest == localState.signedCommitDigest,
              signedState.confirmedTranscriptHash == localState.acceptedTranscriptHash,
              (try membership(from: signedState)).membershipDigest == localState.membershipDigest else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidState
        }
    }

    private func makeLocalState(
        proposal: GroupCryptoEpochProposalV2,
        membership: GroupProviderMembershipV2,
        localCredentialHandle: GroupScopedCredentialHandleV2,
        epochSecret: Data,
        commitment: Data,
        providerCommitDigest: Data,
        activation: NoctweavePQGroupCryptoActivationV2,
        signedCommitDigest: Data?,
        acceptedTranscriptHash: Data?
    ) throws -> GroupCryptoState {
        let epochRoot = deriveEpochRoot(
            epochSecret: epochSecret,
            groupId: proposal.groupId,
            epoch: proposal.nextEpoch,
            membershipDigest: membership.membershipDigest
        )
        var senderHandles = membership.credentials.map(\.credentialHandle)
        if !senderHandles.contains(localCredentialHandle) {
            // A member preparing its own removal still needs one bounded,
            // transient local chain so the next-epoch state can be persisted
            // and the exact fanout resumed after a crash. Runtime policy never
            // exposes this state for new application sends.
            senderHandles.append(localCredentialHandle)
        }
        let chains = senderHandles.map { credentialHandle -> PQGroupSenderChainStateV2 in
            let senderRoot = deriveSenderRoot(
                epochRoot: epochRoot,
                groupId: proposal.groupId,
                epoch: proposal.nextEpoch,
                membershipDigest: membership.membershipDigest,
                credentialHandle: credentialHandle
            )
            return PQGroupSenderChainStateV2(
                credentialHandle: credentialHandle,
                nextSendCounter: 0,
                sendChainKey: senderRoot,
                nextReceiveCounter: 0,
                receiveChainKey: senderRoot
            )
        }.sorted { $0.credentialHandle.rawValue < $1.credentialHandle.rawValue }
        let state = PQGroupLocalCryptoStateV2(
            version: Self.stateVersion,
            activation: activation,
            selection: Self.selection,
            groupId: proposal.groupId,
            epoch: proposal.nextEpoch,
            localCredentialHandle: localCredentialHandle,
            membershipDigest: membership.membershipDigest,
            epochSecret: epochSecret,
            epochSecretCommitment: commitment,
            providerCommitDigest: providerCommitDigest,
            signedCommitDigest: signedCommitDigest,
            acceptedTranscriptHash: acceptedTranscriptHash,
            senderChains: chains
        )
        return try encodeState(state)
    }

    private func requireActiveState(_ state: GroupCryptoState) throws -> PQGroupLocalCryptoStateV2 {
        let localState = try decodeState(state)
        guard localState.activation == .active else {
            throw NoctweavePQGroupExperimentalErrorV2.inactiveState
        }
        return localState
    }

    private func encodeState(_ localState: PQGroupLocalCryptoStateV2) throws -> GroupCryptoState {
        guard localState.isStructurallyValid else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidState
        }
        let bytes = try NoctweaveCoder.encode(localState, sortedKeys: true)
        let state = GroupCryptoState(
            selection: Self.selection,
            groupId: localState.groupId,
            epoch: localState.epoch,
            opaqueState: bytes
        )
        guard state.isStructurallyValid else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidState
        }
        return state
    }

    private func decodeState(_ state: GroupCryptoState) throws -> PQGroupLocalCryptoStateV2 {
        guard state.isStructurallyValid,
              state.selection == Self.selection else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidState
        }
        let decoded: PQGroupLocalCryptoStateV2
        do {
            decoded = try decodePQGroupExact(
                PQGroupLocalCryptoStateV2.self,
                from: state.opaqueState
            )
        } catch {
            throw NoctweavePQGroupExperimentalErrorV2.invalidState
        }
        guard decoded.isStructurallyValid,
              decoded.groupId == state.groupId,
              decoded.epoch == state.epoch,
              decoded.selection == state.selection else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidState
        }
        return decoded
    }

    private func packageDigest(_ core: PQGroupEpochSecretPackageCoreV2) throws -> Data {
        try pqGroupDigest(
            domain: "Noctweave/PQGroupExperimentalV2/destination-package",
            encoded: core
        )
    }

    private func packageAAD(
        proposal: GroupCryptoEpochProposalV2,
        destinationCredentialHandle: GroupScopedCredentialHandleV2,
        destinationAdmissionDigest: Data,
        commitment: Data
    ) throws -> Data {
        try NoctweaveCoder.encode(
            PQGroupPackageAADV2(
                domain: "Noctweave/PQGroupExperimentalV2/package-aad",
                proposal: proposal,
                destinationCredentialHandle: destinationCredentialHandle,
                destinationAdmissionDigest: destinationAdmissionDigest,
                epochSecretCommitment: commitment
            ),
            sortedKeys: true
        )
    }

    private func applicationAAD(
        state: PQGroupLocalCryptoStateV2,
        senderCredentialHandle: GroupScopedCredentialHandleV2,
        eventId: UUID,
        messageCounter: UInt64,
        sentAt: Date
    ) throws -> Data {
        try NoctweaveCoder.encode(
            PQGroupApplicationAADV2(
                domain: "Noctweave/PQGroupExperimentalV2/application-aad",
                profile: Self.selection.profile,
                cipherSuite: Self.selection.cipherSuite,
                groupId: state.groupId,
                epoch: state.epoch,
                transcriptHash: try requiredTranscriptHash(state),
                senderCredentialHandle: senderCredentialHandle,
                eventId: eventId,
                messageCounter: messageCounter,
                sentAt: sentAt
            ),
            sortedKeys: true
        )
    }

    private func requiredTranscriptHash(_ state: PQGroupLocalCryptoStateV2) throws -> Data {
        guard let hash = state.acceptedTranscriptHash, hash.count == 32 else {
            throw NoctweavePQGroupExperimentalErrorV2.inactiveState
        }
        return hash
    }
}

private struct PQGroupMembershipDigestPayloadV2: Codable {
    let groupId: UUID
    let epoch: UInt64
    let selection: GroupProtocolSelectionV2
    let credentials: [GroupProviderCredentialV2]
}

private struct PQGroupDestinationAdmissionDigestV2: Codable, Equatable {
    let destinationCredentialHandle: GroupScopedCredentialHandleV2
    let packageDigest: Data

    var isStructurallyValid: Bool {
        destinationCredentialHandle.isStructurallyValid && packageDigest.count == 32
    }
}

private struct PQGroupEpochCommitV2: Codable, Equatable {
    let proposal: GroupCryptoEpochProposalV2
    let epochSecretCommitment: Data
    let destinationPackageDigests: [PQGroupDestinationAdmissionDigestV2]

    var isStructurallyValid: Bool {
        proposal.isStructurallyValid
            && epochSecretCommitment.count == 32
            && !destinationPackageDigests.isEmpty
            && destinationPackageDigests.count
                <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalCredentials
            && destinationPackageDigests == destinationPackageDigests.sorted {
                $0.destinationCredentialHandle.rawValue < $1.destinationCredentialHandle.rawValue
            }
            && Set(destinationPackageDigests.map(\.destinationCredentialHandle)).count
                == destinationPackageDigests.count
            && destinationPackageDigests.allSatisfy(\.isStructurallyValid)
    }
}

private struct PQGroupEpochSecretPackageCoreV2: Codable, Equatable {
    let groupId: UUID
    let epoch: UInt64
    let destinationCredentialHandle: GroupScopedCredentialHandleV2
    let destinationAdmissionDigest: Data
    let kemCiphertext: Data
    let encryptedEpochSecret: EncryptedPayload

    var isStructurallyValid: Bool {
        epoch > 0
            && destinationCredentialHandle.isStructurallyValid
            && destinationAdmissionDigest.count == 32
            && !kemCiphertext.isEmpty
            && encryptedEpochSecret.nonce.count == 12
            && !encryptedEpochSecret.ciphertext.isEmpty
            && encryptedEpochSecret.tag.count == 16
    }
}

private struct PQGroupEpochSecretPackageV2: Codable, Equatable {
    let core: PQGroupEpochSecretPackageCoreV2
    let epochSecretCommitment: Data
    let destinationPackageDigests: [PQGroupDestinationAdmissionDigestV2]

    var isStructurallyValid: Bool {
        core.isStructurallyValid
            && epochSecretCommitment.count == 32
            && !destinationPackageDigests.isEmpty
            && destinationPackageDigests.count
                <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalCredentials
            && destinationPackageDigests == destinationPackageDigests.sorted {
                $0.destinationCredentialHandle.rawValue < $1.destinationCredentialHandle.rawValue
            }
            && Set(destinationPackageDigests.map(\.destinationCredentialHandle)).count
                == destinationPackageDigests.count
            && destinationPackageDigests.allSatisfy(\.isStructurallyValid)
    }
}

private struct PQGroupEpochSecretPlaintextV2: Codable {
    let groupId: UUID
    let epoch: UInt64
    let proposedMembershipDigest: Data
    let epochSecret: Data
    let epochSecretCommitment: Data
}

private struct PQGroupPackageAADV2: Codable {
    let domain: String
    let proposal: GroupCryptoEpochProposalV2
    let destinationCredentialHandle: GroupScopedCredentialHandleV2
    let destinationAdmissionDigest: Data
    let epochSecretCommitment: Data
}

private struct PQGroupApplicationAADV2: Codable {
    let domain: String
    let profile: GroupProtocolProfile
    let cipherSuite: String
    let groupId: UUID
    let epoch: UInt64
    let transcriptHash: Data
    let senderCredentialHandle: GroupScopedCredentialHandleV2
    let eventId: UUID
    let messageCounter: UInt64
    let sentAt: Date
}

private struct PQGroupSenderChainStateV2: Codable, Equatable {
    let credentialHandle: GroupScopedCredentialHandleV2
    let nextSendCounter: UInt64
    let sendChainKey: Data
    let nextReceiveCounter: UInt64
    let receiveChainKey: Data

    var isStructurallyValid: Bool {
        credentialHandle.isStructurallyValid
            && sendChainKey.count == 32
            && receiveChainKey.count == 32
    }

    func advancingSend(nextKey: Data) -> PQGroupSenderChainStateV2 {
        PQGroupSenderChainStateV2(
            credentialHandle: credentialHandle,
            nextSendCounter: nextSendCounter + 1,
            sendChainKey: nextKey,
            nextReceiveCounter: nextReceiveCounter,
            receiveChainKey: receiveChainKey
        )
    }

    func advancingReceive(nextKey: Data) -> PQGroupSenderChainStateV2 {
        PQGroupSenderChainStateV2(
            credentialHandle: credentialHandle,
            nextSendCounter: nextSendCounter,
            sendChainKey: sendChainKey,
            nextReceiveCounter: nextReceiveCounter + 1,
            receiveChainKey: nextKey
        )
    }
}

private struct PQGroupLocalCryptoStateV2: Codable, Equatable {
    let version: Int
    let activation: NoctweavePQGroupCryptoActivationV2
    let selection: GroupProtocolSelectionV2
    let groupId: UUID
    let epoch: UInt64
    let localCredentialHandle: GroupScopedCredentialHandleV2
    let membershipDigest: Data
    let epochSecret: Data
    let epochSecretCommitment: Data
    let providerCommitDigest: Data
    let signedCommitDigest: Data?
    let acceptedTranscriptHash: Data?
    var senderChains: [PQGroupSenderChainStateV2]

    var isStructurallyValid: Bool {
        version == 1
            && selection == .currentExperimental
            && epoch > 0
            && localCredentialHandle.isStructurallyValid
            && membershipDigest.count == 32
            && epochSecret.count == 32
            && epochSecretCommitment.count == 32
            && providerCommitDigest.count == 32
            && ((activation == .provisional
                    && signedCommitDigest == nil
                    && acceptedTranscriptHash == nil)
                || (activation == .active
                    && signedCommitDigest?.count == 32
                    && acceptedTranscriptHash?.count == 32))
            && !senderChains.isEmpty
            && senderChains.count
                <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalCredentials
            && senderChains == senderChains.sorted {
                $0.credentialHandle.rawValue < $1.credentialHandle.rawValue
            }
            && Set(senderChains.map(\.credentialHandle)).count == senderChains.count
            && senderChains.contains { $0.credentialHandle == localCredentialHandle }
            && senderChains.allSatisfy(\.isStructurallyValid)
            && epochSecretCommitment == NoctweavePQGroupExperimentalProviderV2
                .computeEpochSecretCommitment(
                    epochSecret: epochSecret,
                    groupId: groupId,
                    epoch: epoch
                )
    }

    func activating(
        signedCommitDigest: Data,
        acceptedTranscriptHash: Data
    ) -> PQGroupLocalCryptoStateV2 {
        PQGroupLocalCryptoStateV2(
            version: version,
            activation: .active,
            selection: selection,
            groupId: groupId,
            epoch: epoch,
            localCredentialHandle: localCredentialHandle,
            membershipDigest: membershipDigest,
            epochSecret: epochSecret,
            epochSecretCommitment: epochSecretCommitment,
            providerCommitDigest: providerCommitDigest,
            signedCommitDigest: signedCommitDigest,
            acceptedTranscriptHash: acceptedTranscriptHash,
            senderChains: senderChains
        )
    }
}

private extension NoctweavePQGroupExperimentalProviderV2 {
    static func computeEpochSecretCommitment(
        epochSecret: Data,
        groupId: UUID,
        epoch: UInt64
    ) -> Data {
        epochSecretCommitment(epochSecret: epochSecret, groupId: groupId, epoch: epoch)
    }
}

private func pqGroupDigest<T: Encodable>(domain: String, encoded value: T) throws -> Data {
    var material = pqGroupDomainMaterial(domain, parts: [])
    material.append(try NoctweaveCoder.encode(value, sortedKeys: true))
    return Data(SHA256.hash(data: material))
}

private func epochSecretCommitment(
    epochSecret: Data,
    groupId: UUID,
    epoch: UInt64
) -> Data {
    Data(SHA256.hash(data: pqGroupDomainMaterial(
        "Noctweave/PQGroupExperimentalV2/epoch-secret-commitment",
        parts: [
            Data(groupId.uuidString.lowercased().utf8),
            pqGroupUInt64(epoch),
            epochSecret
        ]
    )))
}

private func derivePackageKey(
    sharedSecret: Data,
    proposal: GroupCryptoEpochProposalV2,
    credential: GroupProviderCredentialV2,
    commitment: Data
) -> Data {
    pqGroupHKDF(
        input: sharedSecret,
        salt: pqGroupDomainMaterial(
            "Noctweave/PQGroupExperimentalV2/package-salt",
            parts: [commitment, proposal.proposedMembershipDigest]
        ),
        info: pqGroupDomainMaterial(
            "Noctweave/PQGroupExperimentalV2/package-key",
            parts: [
                Data(proposal.groupId.uuidString.lowercased().utf8),
                pqGroupUInt64(proposal.nextEpoch),
                Data(credential.credentialHandle.rawValue.utf8),
                credential.admissionDigest
            ]
        )
    )
}

private func deriveEpochRoot(
    epochSecret: Data,
    groupId: UUID,
    epoch: UInt64,
    membershipDigest: Data
) -> Data {
    pqGroupHKDF(
        input: epochSecret,
        salt: pqGroupDomainMaterial(
            "Noctweave/PQGroupExperimentalV2/epoch-salt",
            parts: [Data(groupId.uuidString.lowercased().utf8), membershipDigest]
        ),
        info: pqGroupDomainMaterial(
            "Noctweave/PQGroupExperimentalV2/epoch-root",
            parts: [pqGroupUInt64(epoch)]
        )
    )
}

private func deriveSenderRoot(
    epochRoot: Data,
    groupId: UUID,
    epoch: UInt64,
    membershipDigest: Data,
    credentialHandle: GroupScopedCredentialHandleV2
) -> Data {
    pqGroupHKDF(
        input: epochRoot,
        salt: pqGroupDomainMaterial(
            "Noctweave/PQGroupExperimentalV2/sender-salt",
            parts: [membershipDigest]
        ),
        info: pqGroupDomainMaterial(
            "Noctweave/PQGroupExperimentalV2/sender-root",
            parts: [
                Data(groupId.uuidString.lowercased().utf8),
                pqGroupUInt64(epoch),
                Data(credentialHandle.rawValue.utf8)
            ]
        )
    )
}

private func deriveMessageKey(
    chainKey: Data,
    groupId: UUID,
    epoch: UInt64,
    credentialHandle: GroupScopedCredentialHandleV2,
    counter: UInt64
) -> Data {
    pqGroupHKDF(
        input: chainKey,
        salt: pqGroupDomainMaterial(
            "Noctweave/PQGroupExperimentalV2/message-salt",
            parts: [Data(groupId.uuidString.lowercased().utf8), pqGroupUInt64(epoch)]
        ),
        info: pqGroupDomainMaterial(
            "Noctweave/PQGroupExperimentalV2/message-key",
            parts: [Data(credentialHandle.rawValue.utf8), pqGroupUInt64(counter)]
        )
    )
}

private func deriveNextChainKey(
    chainKey: Data,
    groupId: UUID,
    epoch: UInt64,
    credentialHandle: GroupScopedCredentialHandleV2,
    counter: UInt64
) -> Data {
    pqGroupHKDF(
        input: chainKey,
        salt: pqGroupDomainMaterial(
            "Noctweave/PQGroupExperimentalV2/chain-salt",
            parts: [Data(groupId.uuidString.lowercased().utf8), pqGroupUInt64(epoch)]
        ),
        info: pqGroupDomainMaterial(
            "Noctweave/PQGroupExperimentalV2/chain-next",
            parts: [Data(credentialHandle.rawValue.utf8), pqGroupUInt64(counter)]
        )
    )
}

private func pqGroupHKDF(input: Data, salt: Data, info: Data) -> Data {
    HKDF<SHA256>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: input),
        salt: salt,
        info: info,
        outputByteCount: 32
    ).dataRepresentation
}

private func pqGroupDomainMaterial(_ domain: String, parts: [Data]) -> Data {
    var result = Data(domain.utf8)
    result.append(0)
    for part in parts {
        result.append(pqGroupUInt64(UInt64(part.count)))
        result.append(part)
    }
    return result
}

private func pqGroupUInt64(_ value: UInt64) -> Data {
    var bigEndian = value.bigEndian
    return withUnsafeBytes(of: &bigEndian) { Data($0) }
}

private func pqGroupRandomData(count: Int) -> Data {
    var generator = SystemRandomNumberGenerator()
    return Data((0..<count).map { _ in
        UInt8.random(in: UInt8.min...UInt8.max, using: &generator)
    })
}

/// Provider control objects use one canonical representation. This rejects
/// unknown fields and alternate encodings before any state transition.
private func decodePQGroupExact<Value: Codable>(
    _ type: Value.Type,
    from data: Data
) throws -> Value {
    let decoded = try NoctweaveCoder.decode(type, from: data)
    guard try NoctweaveCoder.encode(decoded, sortedKeys: true) == data else {
        throw NoctweavePQGroupExperimentalErrorV2.invalidState
    }
    return decoded
}

private func pqGroupBucketedDate(_ date: Date) -> Date {
    Date(
        timeIntervalSince1970: floor(
            date.timeIntervalSince1970 / GroupApplicationEnvelopeV2.timestampBucketSeconds
        ) * GroupApplicationEnvelopeV2.timestampBucketSeconds
    )
}
