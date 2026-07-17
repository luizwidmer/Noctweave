import CryptoKit
import Foundation

public enum NoctweavePQGroupExperimentalErrorV2: Error, Equatable {
    case invalidCredential
    case invalidMembership
    case invalidState
    case inactiveState
    case invalidCommit
    case invalidEpochPackage
    case wrongDestination
    case staleEpoch
    case localClientRemoved
    case invalidApplicationEnvelope
    case replay
    case outOfOrder
    case authenticationFailed
    case counterExhausted
}

/// Private material used by exactly one group-scoped client.
public struct LocalGroupClientCredential: Codable, Equatable {
    public let groupId: UUID
    public let groupUserId: UUID
    public let clientHandle: GroupScopedClientHandleV2
    public let keyPackageDigest: Data
    public let signingKey: SigningKeyPair
    public let agreementKey: AgreementKeyPair

    public init(
        groupId: UUID,
        groupUserId: UUID,
        clientHandle: GroupScopedClientHandleV2,
        keyPackageDigest: Data,
        signingKey: SigningKeyPair,
        agreementKey: AgreementKeyPair
    ) {
        self.groupId = groupId
        self.groupUserId = groupUserId
        self.clientHandle = clientHandle
        self.keyPackageDigest = keyPackageDigest
        self.signingKey = signingKey
        self.agreementKey = agreementKey
    }

    public var isStructurallyValid: Bool {
        clientHandle.isStructurallyValid
            && keyPackageDigest.count == 32
            && SigningKeyPair.isValidPublicKey(signingKey.publicKeyData)
            && AgreementKeyPair.isValidPublicKey(agreementKey.publicKeyData)
    }

    public static func == (
        lhs: LocalGroupClientCredential,
        rhs: LocalGroupClientCredential
    ) -> Bool {
        lhs.groupId == rhs.groupId
            && lhs.groupUserId == rhs.groupUserId
            && lhs.clientHandle == rhs.clientHandle
            && lhs.keyPackageDigest == rhs.keyPackageDigest
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
            users: state.users,
            leaves: state.clientLeaves
        )
    }

    public func membership(
        groupId: UUID,
        epoch: UInt64,
        users: [GroupUser],
        leaves: [GroupClientLeafV2]
    ) throws -> GroupProviderMembershipV2 {
        guard epoch > 0 else { throw NoctweavePQGroupExperimentalErrorV2.invalidMembership }
        let activeUserIds = Set(users.filter { $0.isActive(at: epoch) }.map(\.id))
        let clients = leaves.filter {
            $0.isActive(at: epoch) && activeUserIds.contains($0.userId)
        }.map {
            GroupProviderClientV2(
                userId: $0.userId,
                clientHandle: $0.clientHandle,
                keyPackageDigest: $0.keyPackageDigest,
                signingPublicKey: $0.signingPublicKey,
                agreementPublicKey: $0.agreementPublicKey
            )
        }.sorted { $0.clientHandle.rawValue < $1.clientHandle.rawValue }
        guard !clients.isEmpty,
              clients.count <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalClientLeaves else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidMembership
        }
        let digestPayload = PQGroupMembershipDigestPayloadV2(
            groupId: groupId,
            epoch: epoch,
            selection: Self.selection,
            clients: clients
        )
        let membership = GroupProviderMembershipV2(
            groupId: groupId,
            epoch: epoch,
            selection: Self.selection,
            clients: clients,
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
        localCredential: LocalGroupClientCredential
    ) throws {
        let localState = try requireActiveState(state)
        try validateSignedBinding(localState, signedState: signedState)
        try validate(localCredential, in: try membership(from: signedState))
        guard localState.localClientHandle == localCredential.clientHandle else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidCredential
        }
    }

    public func prepareGenesis(
        membership: GroupProviderMembershipV2,
        localCredential: LocalGroupClientCredential
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
            authorClientHandle: localCredential.clientHandle
        )
        return try makePreparedEpoch(
            proposal: proposal,
            proposedMembership: membership,
            localClientHandle: localCredential.clientHandle
        )
    }

    public func prepareCommit(
        state: GroupCryptoState,
        currentMembership: GroupProviderMembershipV2,
        proposedMembership: GroupProviderMembershipV2,
        localCredential: LocalGroupClientCredential
    ) throws -> GroupCryptoPreparedEpochV2 {
        let localState = try requireActiveState(state)
        try validateMembership(currentMembership)
        try validateMembership(proposedMembership)
        try validate(localCredential, in: currentMembership)
        guard localState.groupId == currentMembership.groupId,
              localState.epoch == currentMembership.epoch,
              localState.membershipDigest == currentMembership.membershipDigest,
              localState.localClientHandle == localCredential.clientHandle,
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
            authorClientHandle: localCredential.clientHandle
        )
        return try makePreparedEpoch(
            proposal: proposal,
            proposedMembership: proposedMembership,
            localClientHandle: localCredential.clientHandle
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
        localCredential: LocalGroupClientCredential
    ) throws -> GroupCryptoState {
        let currentState = try requireActiveState(state)
        try validateMembership(currentMembership)
        try validateMembership(proposedMembership)
        try validate(localCredential, in: currentMembership)
        guard currentState.localClientHandle == localCredential.clientHandle,
              currentState.epoch == currentMembership.epoch,
              currentState.membershipDigest == currentMembership.membershipDigest,
              proposedMembership.groupId == currentMembership.groupId,
              proposedMembership.epoch == currentMembership.epoch + 1,
              acceptance.proposal.baseEpoch == currentMembership.epoch,
              acceptance.proposal.nextEpoch == proposedMembership.epoch,
              acceptance.proposal.currentMembershipDigest == currentMembership.membershipDigest,
              acceptance.proposal.proposedMembershipDigest == proposedMembership.membershipDigest else {
            throw NoctweavePQGroupExperimentalErrorV2.staleEpoch
        }
        guard proposedMembership.clients.contains(where: {
            $0.clientHandle == localCredential.clientHandle
        }) else {
            throw NoctweavePQGroupExperimentalErrorV2.localClientRemoved
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
        localCredential: LocalGroupClientCredential
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
        localCredential: LocalGroupClientCredential,
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
        guard localState.localClientHandle == localCredential.clientHandle,
              let chainIndex = localState.senderChains.firstIndex(where: {
                  $0.clientHandle == localCredential.clientHandle
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
            senderClientHandle: localCredential.clientHandle,
            eventId: eventId,
            messageCounter: chain.nextSendCounter,
            sentAt: bucketedSentAt
        )
        let messageKey = deriveMessageKey(
            chainKey: chain.sendChainKey,
            groupId: localState.groupId,
            epoch: localState.epoch,
            clientHandle: chain.clientHandle,
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
            senderClientHandle: localCredential.clientHandle,
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
                clientHandle: chain.clientHandle,
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
              let senderLeaf = signedState.activeClientLeaves.first(where: {
                  $0.clientHandle == envelope.senderClientHandle
              }),
              envelope.verifySignature(
                  groupClientSigningPublicKey: senderLeaf.signingPublicKey
              ),
              let chainIndex = localState.senderChains.firstIndex(where: {
                  $0.clientHandle == envelope.senderClientHandle
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
            senderClientHandle: envelope.senderClientHandle,
            eventId: envelope.eventId,
            messageCounter: envelope.messageCounter,
            sentAt: envelope.sentAt
        )
        let messageKey = deriveMessageKey(
            chainKey: chain.receiveChainKey,
            groupId: localState.groupId,
            epoch: localState.epoch,
            clientHandle: chain.clientHandle,
            counter: chain.nextReceiveCounter
        )
        let plaintext: Data
        do {
            plaintext = try CryptoBox.decrypt(
                envelope.payload,
                key: SymmetricKey(data: messageKey),
                authenticatedData: aad
            )
        } catch {
            throw NoctweavePQGroupExperimentalErrorV2.authenticationFailed
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
                clientHandle: chain.clientHandle,
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
        localClientHandle: GroupScopedClientHandleV2
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
        var entries: [PQGroupDestinationPackageDigestV2] = []
        for client in proposedMembership.clients {
            let core = try makePackageCore(
                proposal: proposal,
                client: client,
                epochSecret: epochSecret,
                commitment: commitment
            )
            cores.append(core)
            entries.append(PQGroupDestinationPackageDigestV2(
                destinationClientHandle: client.clientHandle,
                packageDigest: try packageDigest(core)
            ))
        }
        entries.sort { $0.destinationClientHandle.rawValue < $1.destinationClientHandle.rawValue }
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
                destination: core.destinationClientHandle,
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
            localClientHandle: localClientHandle,
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
        client: GroupProviderClientV2,
        epochSecret: Data,
        commitment: Data
    ) throws -> PQGroupEpochSecretPackageCoreV2 {
        let kemOutput = try AgreementKeyPair.encapsulate(to: client.agreementPublicKey)
        var sharedSecret = kemOutput.sharedSecret
        defer { sharedSecret.secureWipe() }
        let wrapKey = derivePackageKey(
            sharedSecret: sharedSecret,
            proposal: proposal,
            client: client,
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
            destinationClientHandle: client.clientHandle,
            destinationKeyPackageDigest: client.keyPackageDigest,
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
            destinationClientHandle: client.clientHandle,
            destinationKeyPackageDigest: client.keyPackageDigest,
            kemCiphertext: kemOutput.ciphertext,
            encryptedEpochSecret: sealed
        )
    }

    private func openEpochPackage(
        _ welcome: GroupWelcomePackage,
        commit: PQGroupEpochCommitV2,
        membership: GroupProviderMembershipV2,
        acceptance: GroupCryptoAcceptedEpochV2,
        localCredential: LocalGroupClientCredential
    ) throws -> GroupCryptoState {
        guard welcome.destination == localCredential.clientHandle,
              let client = membership.clients.first(where: {
                  $0.clientHandle == localCredential.clientHandle
              }) else {
            throw NoctweavePQGroupExperimentalErrorV2.wrongDestination
        }
        let package: PQGroupEpochSecretPackageV2
        do {
            package = try NoctweaveCoder.decode(
                PQGroupEpochSecretPackageV2.self,
                from: welcome.bytes
            )
        } catch {
            throw NoctweavePQGroupExperimentalErrorV2.invalidEpochPackage
        }
        guard package.isStructurallyValid,
              package.core.groupId == membership.groupId,
              package.core.epoch == membership.epoch,
              package.core.destinationClientHandle == localCredential.clientHandle,
              package.core.destinationKeyPackageDigest == localCredential.keyPackageDigest,
              package.epochSecretCommitment == commit.epochSecretCommitment,
              package.destinationPackageDigests == commit.destinationPackageDigests,
              let entry = commit.destinationPackageDigests.first(where: {
                  $0.destinationClientHandle == localCredential.clientHandle
              }),
              entry.packageDigest == (try? packageDigest(package.core)) else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidEpochPackage
        }
        var sharedSecret: Data
        do {
            sharedSecret = try localCredential.agreementKey.decapsulate(
                ciphertext: package.core.kemCiphertext
            )
        } catch {
            throw NoctweavePQGroupExperimentalErrorV2.authenticationFailed
        }
        defer { sharedSecret.secureWipe() }
        let wrapKey = derivePackageKey(
            sharedSecret: sharedSecret,
            proposal: commit.proposal,
            client: client,
            commitment: commit.epochSecretCommitment
        )
        let opened: Data
        do {
            opened = try CryptoBox.decrypt(
                package.core.encryptedEpochSecret,
                key: SymmetricKey(data: wrapKey),
                authenticatedData: try packageAAD(
                    proposal: commit.proposal,
                    destinationClientHandle: client.clientHandle,
                    destinationKeyPackageDigest: client.keyPackageDigest,
                    commitment: commit.epochSecretCommitment
                )
            )
        } catch {
            throw NoctweavePQGroupExperimentalErrorV2.authenticationFailed
        }
        let plaintext: PQGroupEpochSecretPlaintextV2
        do {
            plaintext = try NoctweaveCoder.decode(
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
            localClientHandle: localCredential.clientHandle,
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
            commit = try NoctweaveCoder.decode(PQGroupEpochCommitV2.self, from: bytes)
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
            guard let package = try? NoctweaveCoder.decode(
                PQGroupEpochSecretPackageV2.self,
                from: welcome.bytes
            ),
                package.isStructurallyValid,
                package.core.destinationClientHandle == welcome.destination,
                package.epochSecretCommitment == commit.epochSecretCommitment,
                package.destinationPackageDigests == commit.destinationPackageDigests,
                let entry = commit.destinationPackageDigests.first(where: {
                    $0.destinationClientHandle == welcome.destination
                }),
                entry.packageDigest == (try? packageDigest(package.core)) else {
                throw NoctweavePQGroupExperimentalErrorV2.invalidEpochPackage
            }
        }
    }

    private func validateMembership(_ membership: GroupProviderMembershipV2) throws {
        guard membership.isStructurallyValid,
              membership.selection == Self.selection,
              membership.clients.count <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalClientLeaves,
              membership.membershipDigest == (try? pqGroupDigest(
                  domain: "Noctweave/PQGroupExperimentalV2/membership",
                  encoded: PQGroupMembershipDigestPayloadV2(
                      groupId: membership.groupId,
                      epoch: membership.epoch,
                      selection: membership.selection,
                      clients: membership.clients
                  )
              )) else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidMembership
        }
    }

    private func validate(
        _ credential: LocalGroupClientCredential,
        in membership: GroupProviderMembershipV2
    ) throws {
        guard credential.isStructurallyValid,
              credential.groupId == membership.groupId,
              let client = membership.clients.first(where: {
                  $0.clientHandle == credential.clientHandle
              }),
              client.userId == credential.groupUserId,
              client.keyPackageDigest == credential.keyPackageDigest,
              client.signingPublicKey == credential.signingKey.publicKeyData,
              client.agreementPublicKey == credential.agreementKey.publicKeyData else {
            throw NoctweavePQGroupExperimentalErrorV2.invalidCredential
        }
    }

    private func validateSignedBinding(
        _ localState: PQGroupLocalCryptoStateV2,
        signedState: SignedGroupStateV2
    ) throws {
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
        localClientHandle: GroupScopedClientHandleV2,
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
        let chains = membership.clients.map { client -> PQGroupSenderChainStateV2 in
            let senderRoot = deriveSenderRoot(
                epochRoot: epochRoot,
                groupId: proposal.groupId,
                epoch: proposal.nextEpoch,
                membershipDigest: membership.membershipDigest,
                clientHandle: client.clientHandle
            )
            return PQGroupSenderChainStateV2(
                clientHandle: client.clientHandle,
                nextSendCounter: 0,
                sendChainKey: senderRoot,
                nextReceiveCounter: 0,
                receiveChainKey: senderRoot
            )
        }.sorted { $0.clientHandle.rawValue < $1.clientHandle.rawValue }
        let state = PQGroupLocalCryptoStateV2(
            version: Self.stateVersion,
            activation: activation,
            selection: Self.selection,
            groupId: proposal.groupId,
            epoch: proposal.nextEpoch,
            localClientHandle: localClientHandle,
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
            decoded = try NoctweaveCoder.decode(
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
        destinationClientHandle: GroupScopedClientHandleV2,
        destinationKeyPackageDigest: Data,
        commitment: Data
    ) throws -> Data {
        try NoctweaveCoder.encode(
            PQGroupPackageAADV2(
                domain: "Noctweave/PQGroupExperimentalV2/package-aad",
                proposal: proposal,
                destinationClientHandle: destinationClientHandle,
                destinationKeyPackageDigest: destinationKeyPackageDigest,
                epochSecretCommitment: commitment
            ),
            sortedKeys: true
        )
    }

    private func applicationAAD(
        state: PQGroupLocalCryptoStateV2,
        senderClientHandle: GroupScopedClientHandleV2,
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
                senderClientHandle: senderClientHandle,
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
    let clients: [GroupProviderClientV2]
}

private struct PQGroupDestinationPackageDigestV2: Codable, Equatable {
    let destinationClientHandle: GroupScopedClientHandleV2
    let packageDigest: Data

    var isStructurallyValid: Bool {
        destinationClientHandle.isStructurallyValid && packageDigest.count == 32
    }
}

private struct PQGroupEpochCommitV2: Codable, Equatable {
    let proposal: GroupCryptoEpochProposalV2
    let epochSecretCommitment: Data
    let destinationPackageDigests: [PQGroupDestinationPackageDigestV2]

    var isStructurallyValid: Bool {
        proposal.isStructurallyValid
            && epochSecretCommitment.count == 32
            && !destinationPackageDigests.isEmpty
            && destinationPackageDigests.count
                <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalClientLeaves
            && destinationPackageDigests == destinationPackageDigests.sorted {
                $0.destinationClientHandle.rawValue < $1.destinationClientHandle.rawValue
            }
            && Set(destinationPackageDigests.map(\.destinationClientHandle)).count
                == destinationPackageDigests.count
            && destinationPackageDigests.allSatisfy(\.isStructurallyValid)
    }
}

private struct PQGroupEpochSecretPackageCoreV2: Codable, Equatable {
    let groupId: UUID
    let epoch: UInt64
    let destinationClientHandle: GroupScopedClientHandleV2
    let destinationKeyPackageDigest: Data
    let kemCiphertext: Data
    let encryptedEpochSecret: EncryptedPayload

    var isStructurallyValid: Bool {
        epoch > 0
            && destinationClientHandle.isStructurallyValid
            && destinationKeyPackageDigest.count == 32
            && !kemCiphertext.isEmpty
            && encryptedEpochSecret.nonce.count == 12
            && !encryptedEpochSecret.ciphertext.isEmpty
            && encryptedEpochSecret.tag.count == 16
    }
}

private struct PQGroupEpochSecretPackageV2: Codable, Equatable {
    let core: PQGroupEpochSecretPackageCoreV2
    let epochSecretCommitment: Data
    let destinationPackageDigests: [PQGroupDestinationPackageDigestV2]

    var isStructurallyValid: Bool {
        core.isStructurallyValid
            && epochSecretCommitment.count == 32
            && !destinationPackageDigests.isEmpty
            && destinationPackageDigests.count
                <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalClientLeaves
            && destinationPackageDigests == destinationPackageDigests.sorted {
                $0.destinationClientHandle.rawValue < $1.destinationClientHandle.rawValue
            }
            && Set(destinationPackageDigests.map(\.destinationClientHandle)).count
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
    let destinationClientHandle: GroupScopedClientHandleV2
    let destinationKeyPackageDigest: Data
    let epochSecretCommitment: Data
}

private struct PQGroupApplicationAADV2: Codable {
    let domain: String
    let profile: GroupProtocolProfile
    let cipherSuite: String
    let groupId: UUID
    let epoch: UInt64
    let transcriptHash: Data
    let senderClientHandle: GroupScopedClientHandleV2
    let eventId: UUID
    let messageCounter: UInt64
    let sentAt: Date
}

private struct PQGroupSenderChainStateV2: Codable, Equatable {
    let clientHandle: GroupScopedClientHandleV2
    let nextSendCounter: UInt64
    let sendChainKey: Data
    let nextReceiveCounter: UInt64
    let receiveChainKey: Data

    var isStructurallyValid: Bool {
        clientHandle.isStructurallyValid
            && sendChainKey.count == 32
            && receiveChainKey.count == 32
    }

    func advancingSend(nextKey: Data) -> PQGroupSenderChainStateV2 {
        PQGroupSenderChainStateV2(
            clientHandle: clientHandle,
            nextSendCounter: nextSendCounter + 1,
            sendChainKey: nextKey,
            nextReceiveCounter: nextReceiveCounter,
            receiveChainKey: receiveChainKey
        )
    }

    func advancingReceive(nextKey: Data) -> PQGroupSenderChainStateV2 {
        PQGroupSenderChainStateV2(
            clientHandle: clientHandle,
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
    let localClientHandle: GroupScopedClientHandleV2
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
            && localClientHandle.isStructurallyValid
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
                <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalClientLeaves
            && senderChains == senderChains.sorted {
                $0.clientHandle.rawValue < $1.clientHandle.rawValue
            }
            && Set(senderChains.map(\.clientHandle)).count == senderChains.count
            && senderChains.contains { $0.clientHandle == localClientHandle }
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
            localClientHandle: localClientHandle,
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
    client: GroupProviderClientV2,
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
                Data(client.clientHandle.rawValue.utf8),
                client.keyPackageDigest
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
    clientHandle: GroupScopedClientHandleV2
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
                Data(clientHandle.rawValue.utf8)
            ]
        )
    )
}

private func deriveMessageKey(
    chainKey: Data,
    groupId: UUID,
    epoch: UInt64,
    clientHandle: GroupScopedClientHandleV2,
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
            parts: [Data(clientHandle.rawValue.utf8), pqGroupUInt64(counter)]
        )
    )
}

private func deriveNextChainKey(
    chainKey: Data,
    groupId: UUID,
    epoch: UInt64,
    clientHandle: GroupScopedClientHandleV2,
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
            parts: [Data(clientHandle.rawValue.utf8), pqGroupUInt64(counter)]
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

private func pqGroupBucketedDate(_ date: Date) -> Date {
    Date(
        timeIntervalSince1970: floor(
            date.timeIntervalSince1970 / GroupApplicationEnvelopeV2.timestampBucketSeconds
        ) * GroupApplicationEnvelopeV2.timestampBucketSeconds
    )
}
