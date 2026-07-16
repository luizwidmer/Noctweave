import CryptoKit
import Foundation

public struct GroupRatchetState: Codable, Equatable {
    private static let digestByteCount = 32
    private static let maximumReceiveChains = 256
    public let groupId: UUID
    public var epoch: UInt64
    public var transcriptHash: Data
    public var rootKey: Data
    public var localSenderFingerprint: String?
    public var sendChain: ChainKeyState?
    public var receiveChains: [String: ChainKeyState]

    public init(
        groupId: UUID,
        epoch: UInt64,
        transcriptHash: Data,
        rootKey: Data,
        localSenderFingerprint: String? = nil,
        sendChain: ChainKeyState? = nil,
        receiveChains: [String: ChainKeyState] = [:]
    ) {
        self.groupId = groupId
        self.epoch = epoch
        self.transcriptHash = transcriptHash
        self.rootKey = rootKey
        self.localSenderFingerprint = localSenderFingerprint
        self.sendChain = sendChain
        self.receiveChains = receiveChains
        if let localSenderFingerprint, sendChain == nil {
            self.sendChain = Self.senderChain(
                rootKey: rootKey,
                transcriptHash: transcriptHash,
                senderFingerprint: localSenderFingerprint
            )
        }
    }

    public static func initialize(
        groupId: UUID,
        epoch: UInt64,
        transcriptHash: Data,
        groupSecret: Data,
        localSenderFingerprint: String? = nil
    ) -> GroupRatchetState {
        let rootKey = deriveRootKey(
            groupId: groupId,
            epoch: epoch,
            transcriptHash: transcriptHash,
            groupSecret: groupSecret,
            priorRootKey: nil
        )
        return GroupRatchetState(
            groupId: groupId,
            epoch: epoch,
            transcriptHash: transcriptHash,
            rootKey: rootKey,
            localSenderFingerprint: localSenderFingerprint
        )
    }

    public mutating func advanceEpoch(
        to epoch: UInt64,
        transcriptHash: Data,
        commitSecret: Data
    ) throws {
        guard isStructurallyValid,
              self.epoch < UInt64.max,
              epoch == self.epoch + 1,
              transcriptHash.count == Self.digestByteCount,
              commitSecret.count == Self.digestByteCount else {
            throw CryptoError.invalidPayload
        }
        let nextRootKey = Self.deriveRootKey(
            groupId: groupId,
            epoch: epoch,
            transcriptHash: transcriptHash,
            groupSecret: commitSecret,
            // Epoch commit secrets are distributed to every current member,
            // including late joiners. The epoch root must therefore be
            // recoverable from the commit secret alone.
            priorRootKey: nil
        )
        rootKey.secureWipe()
        rootKey = nextRootKey
        self.epoch = epoch
        self.transcriptHash = transcriptHash
        sendChain?.secureWipe()
        for fingerprint in receiveChains.keys {
            receiveChains[fingerprint]?.secureWipe()
        }
        receiveChains.removeAll()
        if let localSenderFingerprint {
            sendChain = Self.senderChain(
                rootKey: rootKey,
                transcriptHash: transcriptHash,
                senderFingerprint: localSenderFingerprint
            )
        } else {
            sendChain = nil
        }
    }

    mutating func nextSendKey(senderFingerprint: String) throws -> (counter: UInt64, key: SymmetricKey) {
        guard isStructurallyValid,
              Self.isCanonicalFingerprint(senderFingerprint) else {
            throw CryptoError.invalidPayload
        }
        if localSenderFingerprint == nil {
            localSenderFingerprint = senderFingerprint
        }
        guard localSenderFingerprint == senderFingerprint else {
            throw CryptoError.invalidPayload
        }
        if sendChain == nil {
            sendChain = Self.senderChain(
                rootKey: rootKey,
                transcriptHash: transcriptHash,
                senderFingerprint: senderFingerprint
            )
        }
        guard var chain = sendChain else {
            throw CryptoError.invalidPayload
        }
        let result = try chain.nextMessageKey()
        sendChain = chain
        return result
    }

    mutating func receiveKey(senderFingerprint: String, counter: UInt64) throws -> SymmetricKey {
        guard isStructurallyValid,
              Self.isCanonicalFingerprint(senderFingerprint),
              receiveChains[senderFingerprint] != nil || receiveChains.count < Self.maximumReceiveChains else {
            throw CryptoError.invalidPayload
        }
        var chain = receiveChains[senderFingerprint] ?? Self.senderChain(
            rootKey: rootKey,
            transcriptHash: transcriptHash,
            senderFingerprint: senderFingerprint
        )
        let key = try chain.messageKey(for: counter, maxSkip: ChainKeyState.defaultMaxSkip)
        receiveChains[senderFingerprint] = chain
        return key
    }

    public var isStructurallyValid: Bool {
        transcriptHash.count == Self.digestByteCount
            && rootKey.count == Self.digestByteCount
            && localSenderFingerprint.map(Self.isCanonicalFingerprint) ?? true
            && (sendChain?.isStructurallyValid ?? true)
            && receiveChains.count <= Self.maximumReceiveChains
            && receiveChains.allSatisfy { fingerprint, chain in
                Self.isCanonicalFingerprint(fingerprint) && chain.isStructurallyValid
            }
    }

    private static func isCanonicalFingerprint(_ value: String) -> Bool {
        guard let decoded = Data(base64Encoded: value), decoded.count == digestByteCount else {
            return false
        }
        return decoded.base64EncodedString() == value
    }

    private static func deriveRootKey(
        groupId: UUID,
        epoch: UInt64,
        transcriptHash: Data,
        groupSecret: Data,
        priorRootKey: Data?
    ) -> Data {
        var epochBytes = epoch.bigEndian
        var salt = Data("NOCTYRA-GROUP-ROOT-SALT-V1".utf8)
        salt.append(Data(groupId.uuidString.utf8))
        salt.append(Data(bytes: &epochBytes, count: MemoryLayout<UInt64>.size))
        salt.append(transcriptHash)
        if let priorRootKey {
            salt.append(priorRootKey)
        }
        return CryptoBox.deriveChainKey(
            sharedSecret: groupSecret,
            salt: salt,
            info: Data("NOCTYRA-GROUP-ROOT-V1".utf8)
        )
    }

    private static func senderChain(
        rootKey: Data,
        transcriptHash: Data,
        senderFingerprint: String
    ) -> ChainKeyState {
        var info = Data("NOCTYRA-GROUP-SENDER-CHAIN-V1".utf8)
        info.append(Data(senderFingerprint.utf8))
        let key = CryptoBox.deriveChainKey(
            sharedSecret: rootKey,
            salt: transcriptHash,
            info: info
        )
        return ChainKeyState(keyData: key)
    }
}

public enum GroupRatchetRecovery {
    public static func state(
        from descriptor: RelayGroupDescriptor,
        identity: Identity,
        existing: GroupRatchetState? = nil
    ) -> GroupRatchetState? {
        guard descriptor.mlsEpochState.protocolVersion == MLSGroupEpochState.currentProtocolVersion,
              descriptor.mlsEpochState.cipherSuite == MLSGroupEpochState.currentCipherSuite,
              MLSGroupEpochHistoryValidator.isValid(
            currentState: descriptor.mlsEpochState,
            history: descriptor.mlsEpochHistory
        ) else {
            return nil
        }

        let history = descriptor.mlsEpochHistory
            .sorted { $0.epoch < $1.epoch }
            .filter { $0.ratchetSecretDistribution != nil }

        if var state = existing,
           state.groupId == descriptor.id {
            for commit in history where commit.epoch > state.epoch {
                guard let secret = ratchetSecret(from: commit, groupId: descriptor.id, identity: identity),
                      advance(&state, to: commit.epoch, transcriptHash: commit.transcriptHash, secret: secret) else {
                    return nil
                }
            }
            return state.epoch == descriptor.epoch ? state : nil
        }

        if let first = history.first,
           first.epoch == 0,
           let secret = ratchetSecret(from: first, groupId: descriptor.id, identity: identity) {
            var state = GroupRatchetState.initialize(
                groupId: descriptor.id,
                epoch: first.epoch,
                transcriptHash: first.transcriptHash,
                groupSecret: secret,
                localSenderFingerprint: identity.fingerprint
            )
            for commit in history.dropFirst() {
                guard let secret = ratchetSecret(from: commit, groupId: descriptor.id, identity: identity),
                      advance(&state, to: commit.epoch, transcriptHash: commit.transcriptHash, secret: secret) else {
                    return nil
                }
            }
            if state.epoch == descriptor.epoch {
                return state
            }
        }

        guard let distribution = descriptor.mlsEpochState.lastCommit.ratchetSecretDistribution,
              distributionMatches(distribution, commit: descriptor.mlsEpochState.lastCommit, groupId: descriptor.id),
              distribution.epoch == descriptor.epoch,
              let secret = try? distribution.openSecret(
                recipientFingerprint: identity.fingerprint,
                agreementKey: identity.agreementKey
              ) else {
            if let existing,
               existing.groupId == descriptor.id,
               existing.epoch == descriptor.epoch {
                return existing
            }
            return nil
        }
        return GroupRatchetState.initialize(
            groupId: descriptor.id,
            epoch: descriptor.epoch,
            transcriptHash: descriptor.mlsEpochState.confirmedTranscriptHash,
            groupSecret: secret,
            localSenderFingerprint: identity.fingerprint
        )
    }

    private static func ratchetSecret(
        from commit: MLSGroupCommitSummary,
        groupId: UUID,
        identity: Identity
    ) -> Data? {
        guard let distribution = commit.ratchetSecretDistribution else {
            return nil
        }
        guard distributionMatches(distribution, commit: commit, groupId: groupId) else {
            return nil
        }
        return try? distribution.openSecret(
            recipientFingerprint: identity.fingerprint,
            agreementKey: identity.agreementKey
        )
    }

    private static func distributionMatches(
        _ distribution: GroupRatchetEpochSecretDistribution,
        commit: MLSGroupCommitSummary,
        groupId: UUID
    ) -> Bool {
        distribution.groupId == groupId
            && distribution.epoch == commit.epoch
            && distribution.operation == commit.operation
            && Set(distribution.memberFingerprints) == Set(commit.memberFingerprints)
            && Set(distribution.shares.map(\.recipientFingerprint)) == Set(commit.memberFingerprints)
    }

    private static func advance(
        _ state: inout GroupRatchetState,
        to epoch: UInt64,
        transcriptHash: Data,
        secret: Data
    ) -> Bool {
        guard state.epoch < UInt64.max, epoch == state.epoch + 1 else {
            return false
        }
        return (try? state.advanceEpoch(
            to: epoch,
            transcriptHash: transcriptHash,
            commitSecret: secret
        )) != nil
    }
}

public struct GroupRatchetEnvelope: Codable, Identifiable, Equatable {
    public let id: UUID
    public let protocolVersion: String
    public let cipherSuite: String
    public let groupId: UUID
    public let epoch: UInt64
    public let transcriptHash: Data
    public let senderFingerprint: String
    public let sentAt: Date
    public let messageCounter: UInt64
    public let payload: EncryptedPayload
    public let signature: Data

    public init(
        id: UUID = UUID(),
        protocolVersion: String = MLSGroupEpochState.currentProtocolVersion,
        cipherSuite: String = MLSGroupEpochState.currentCipherSuite,
        groupId: UUID,
        epoch: UInt64,
        transcriptHash: Data,
        senderFingerprint: String,
        sentAt: Date,
        messageCounter: UInt64,
        payload: EncryptedPayload,
        signature: Data
    ) {
        self.id = id
        self.protocolVersion = protocolVersion
        self.cipherSuite = cipherSuite
        self.groupId = groupId
        self.epoch = epoch
        self.transcriptHash = transcriptHash
        self.senderFingerprint = senderFingerprint
        self.sentAt = sentAt
        self.messageCounter = messageCounter
        self.payload = payload
        self.signature = signature
    }

    public func verifySignature(publicSigningKey: Data) -> Bool {
        guard isStructurallyValid,
              SigningKeyPair.isValidPublicKey(publicSigningKey),
              senderFingerprint == CryptoBox.fingerprint(for: publicSigningKey),
              let data = try? GroupRatchet.signableData(
                id: id,
                protocolVersion: protocolVersion,
                cipherSuite: cipherSuite,
                groupId: groupId,
                epoch: epoch,
                transcriptHash: transcriptHash,
                senderFingerprint: senderFingerprint,
                sentAt: sentAt,
                messageCounter: messageCounter,
                payload: payload
              ) else {
            return false
        }
        return SigningKeyPair.verify(signature: signature, data: data, publicKeyData: publicSigningKey)
    }

    public var isStructurallyValid: Bool {
        let ciphertextBytes = payload.ciphertext.count
        return protocolVersion == MLSGroupEpochState.currentProtocolVersion
            && cipherSuite == MLSGroupEpochState.currentCipherSuite
            && transcriptHash.count == 32
            && Self.isCanonicalFingerprint(senderFingerprint)
            && sentAt.timeIntervalSince1970.isFinite
            && payload.nonce.count == 12
            && payload.tag.count == 16
            && (PaddedMessagePlaintext.minimumPaddedBytes...PaddedMessagePlaintext.maximumPaddedBytes)
                .contains(ciphertextBytes)
            && ciphertextBytes > 0
            && (ciphertextBytes & (ciphertextBytes - 1)) == 0
            && signature.count == 3_309
    }

    private static func isCanonicalFingerprint(_ value: String) -> Bool {
        guard let decoded = Data(base64Encoded: value), decoded.count == 32 else { return false }
        return decoded.base64EncodedString() == value
    }
}

public struct GroupRatchetSecretShare: Codable, Equatable {
    public let recipientFingerprint: String
    public let kemCiphertext: Data
    public let encryptedSecret: EncryptedPayload

    public init(
        recipientFingerprint: String,
        kemCiphertext: Data,
        encryptedSecret: EncryptedPayload
    ) {
        self.recipientFingerprint = recipientFingerprint
        self.kemCiphertext = kemCiphertext
        self.encryptedSecret = encryptedSecret
    }
}

public struct GroupRatchetEpochSecretDistribution: Codable, Equatable {
    public static let maximumMembers = 256
    public let version: Int
    public let groupId: UUID
    public let epoch: UInt64
    public let operation: MLSGroupCommitOperation
    public let memberFingerprints: [String]
    public let shares: [GroupRatchetSecretShare]

    public init(
        version: Int = 1,
        groupId: UUID,
        epoch: UInt64,
        operation: MLSGroupCommitOperation,
        memberFingerprints: [String],
        shares: [GroupRatchetSecretShare]
    ) {
        self.version = version
        self.groupId = groupId
        self.epoch = epoch
        self.operation = operation
        self.memberFingerprints = memberFingerprints.sorted()
        self.shares = shares.sorted { $0.recipientFingerprint < $1.recipientFingerprint }
    }

    public var isStructurallyValid: Bool {
        let normalizedMembers = memberFingerprints.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        let shareRecipients = shares.map {
            $0.recipientFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return version == 1
            && !normalizedMembers.isEmpty
            && normalizedMembers.count <= Self.maximumMembers
            && normalizedMembers.allSatisfy(Self.isCanonicalFingerprint)
            && Set(normalizedMembers).count == normalizedMembers.count
            && shareRecipients.allSatisfy(Self.isCanonicalFingerprint)
            && Set(shareRecipients).count == shareRecipients.count
            && Set(shareRecipients) == Set(normalizedMembers)
            && shares.allSatisfy { share in
                share.kemCiphertext.count == 1_088
                    && share.encryptedSecret.ciphertext.count == 32
                    && share.encryptedSecret.nonce.count == 12
                    && share.encryptedSecret.tag.count == 16
            }
    }

    public static func seal(
        secret: Data,
        groupId: UUID,
        epoch: UInt64,
        operation: MLSGroupCommitOperation,
        recipients: [RelayGroupMemberProfile]
    ) throws -> GroupRatchetEpochSecretDistribution {
        guard secret.count == 32,
              recipients.count <= Self.maximumMembers else {
            throw CryptoError.invalidPayload
        }
        guard recipients.allSatisfy({ Self.isCanonicalFingerprint($0.fingerprint) }) else {
            throw CryptoError.invalidPayload
        }
        let normalizedRecipients = recipients.sorted { $0.fingerprint < $1.fingerprint }
        let recipientFingerprints = normalizedRecipients.map(\.fingerprint)
        guard !recipientFingerprints.isEmpty,
              Set(recipientFingerprints).count == recipientFingerprints.count else {
            throw CryptoError.invalidPayload
        }
        let memberFingerprints = normalizedRecipients.map(\.fingerprint)
        let shares = try normalizedRecipients.map { recipient -> GroupRatchetSecretShare in
            guard let publicKey = recipient.agreementPublicKey,
                  AgreementKeyPair.isValidPublicKey(publicKey) else {
                throw CryptoError.invalidPublicKey
            }
            var kem = try AgreementKeyPair.encapsulate(to: publicKey)
            defer { kem.sharedSecret.secureWipe() }
            let key = SymmetricKey(data: CryptoBox.deriveChainKey(
                sharedSecret: kem.sharedSecret,
                salt: Data(groupId.uuidString.utf8),
                info: shareInfo(
                    epoch: epoch,
                    operation: operation,
                    recipientFingerprint: recipient.fingerprint
                )
            ))
            let payload = try CryptoBox.encrypt(
                secret,
                key: key,
                authenticatedData: try shareAuthenticatedData(
                    version: 1,
                    groupId: groupId,
                    epoch: epoch,
                    operation: operation,
                    memberFingerprints: memberFingerprints,
                    recipientFingerprint: recipient.fingerprint
                )
            )
            return GroupRatchetSecretShare(
                recipientFingerprint: recipient.fingerprint,
                kemCiphertext: kem.ciphertext,
                encryptedSecret: payload
            )
        }
        return GroupRatchetEpochSecretDistribution(
            groupId: groupId,
            epoch: epoch,
            operation: operation,
            memberFingerprints: memberFingerprints,
            shares: shares
        )
    }

    public func openSecret(
        recipientFingerprint: String,
        agreementKey: AgreementKeyPair
    ) throws -> Data {
        guard isStructurallyValid,
              let share = shares.first(where: { $0.recipientFingerprint == recipientFingerprint }),
              memberFingerprints.contains(recipientFingerprint) else {
            throw CryptoError.invalidPayload
        }
        var sharedSecret = try agreementKey.decapsulate(ciphertext: share.kemCiphertext)
        defer { sharedSecret.secureWipe() }
        let key = SymmetricKey(data: CryptoBox.deriveChainKey(
            sharedSecret: sharedSecret,
            salt: Data(groupId.uuidString.utf8),
            info: Self.shareInfo(
                epoch: epoch,
                operation: operation,
                recipientFingerprint: recipientFingerprint
            )
        ))
        return try CryptoBox.decrypt(
            share.encryptedSecret,
            key: key,
            authenticatedData: try Self.shareAuthenticatedData(
                version: version,
                groupId: groupId,
                epoch: epoch,
                operation: operation,
                memberFingerprints: memberFingerprints,
                recipientFingerprint: recipientFingerprint
            )
        )
    }

    private static func isCanonicalFingerprint(_ value: String) -> Bool {
        guard let decoded = Data(base64Encoded: value), decoded.count == 32 else { return false }
        return decoded.base64EncodedString() == value
    }

    private static func shareInfo(
        epoch: UInt64,
        operation: MLSGroupCommitOperation,
        recipientFingerprint: String
    ) -> Data {
        var epochBytes = epoch.bigEndian
        var info = Data("NOCTYRA-GROUP-RATCHET-SECRET-SHARE-V1".utf8)
        info.append(Data(bytes: &epochBytes, count: MemoryLayout<UInt64>.size))
        info.append(Data(operation.rawValue.utf8))
        info.append(Data(recipientFingerprint.utf8))
        return info
    }

    private static func shareAuthenticatedData(
        version: Int,
        groupId: UUID,
        epoch: UInt64,
        operation: MLSGroupCommitOperation,
        memberFingerprints: [String],
        recipientFingerprint: String
    ) throws -> Data {
        try NoctweaveCoder.encode(
            GroupRatchetSecretShareAuthenticatedData(
                version: version,
                groupId: groupId,
                epoch: epoch,
                operation: operation,
                memberFingerprints: memberFingerprints.sorted(),
                recipientFingerprint: recipientFingerprint
            ),
            sortedKeys: true
        )
    }
}

public struct GroupRatchetPreparedMessageKey {
    public let counter: UInt64
    public let key: SymmetricKey

    public init(counter: UInt64, key: SymmetricKey) {
        self.counter = counter
        self.key = key
    }
}

public enum GroupRatchet {
    /// Version 2 binds the complete application-envelope context, including the
    /// envelope identifier and visible metadata, into both the signature and
    /// AEAD authenticated data. There is deliberately no v1 verification path.
    public static let applicationEnvelopeVersion = 2

    public static func encrypt(
        body: MessageBody,
        senderSigningKey: SigningKeyPair,
        senderFingerprint: String,
        state: inout GroupRatchetState,
        sentAt: Date = Date(),
        metadataBucketSeconds: Int? = nil
    ) throws -> GroupRatchetEnvelope {
        var candidateState = state
        let prepared = try candidateState.nextSendKey(senderFingerprint: senderFingerprint)
        let envelope = try encrypt(
            body: body,
            senderSigningKey: senderSigningKey,
            senderFingerprint: senderFingerprint,
            messageCounter: prepared.counter,
            messageKey: prepared.key,
            state: candidateState,
            sentAt: sentAt,
            metadataBucketSeconds: metadataBucketSeconds
        )
        state = candidateState
        return envelope
    }

    public static func prepareMessageKey(
        senderFingerprint: String,
        state: inout GroupRatchetState
    ) throws -> GroupRatchetPreparedMessageKey {
        let prepared = try state.nextSendKey(senderFingerprint: senderFingerprint)
        return GroupRatchetPreparedMessageKey(counter: prepared.counter, key: prepared.key)
    }

    public static func encrypt(
        body: MessageBody,
        senderSigningKey: SigningKeyPair,
        senderFingerprint: String,
        messageCounter: UInt64,
        messageKey: SymmetricKey,
        state: GroupRatchetState,
        sentAt: Date = Date(),
        metadataBucketSeconds: Int? = nil
    ) throws -> GroupRatchetEnvelope {
        guard state.isStructurallyValid,
              senderFingerprint == CryptoBox.fingerprint(for: senderSigningKey.publicKeyData) else {
            throw CryptoError.invalidPayload
        }
        var plaintext = try PaddedMessagePlaintext.encodeGroupMessageBody(body)
        defer { plaintext.secureWipe() }
        let sentAt = MetadataMinimizer.bucketedTimestamp(sentAt, bucketSeconds: metadataBucketSeconds)
        let envelopeId = UUID()
        let nonce = AES.GCM.Nonce()
        let nonceData = Data(nonce)
        let aad = try authenticatedData(
            id: envelopeId,
            protocolVersion: MLSGroupEpochState.currentProtocolVersion,
            cipherSuite: MLSGroupEpochState.currentCipherSuite,
            groupId: state.groupId,
            epoch: state.epoch,
            transcriptHash: state.transcriptHash,
            senderFingerprint: senderFingerprint,
            sentAt: sentAt,
            messageCounter: messageCounter,
            payloadNonce: nonceData,
            ciphertextByteCount: plaintext.count,
            authenticationTagByteCount: 16
        )
        let sealed = try AES.GCM.seal(
            plaintext,
            using: messageKey,
            nonce: nonce,
            authenticating: aad
        )
        let payload = EncryptedPayload(
            nonce: nonceData,
            ciphertext: sealed.ciphertext,
            tag: sealed.tag
        )
        let signable = try signableData(
            id: envelopeId,
            protocolVersion: MLSGroupEpochState.currentProtocolVersion,
            cipherSuite: MLSGroupEpochState.currentCipherSuite,
            groupId: state.groupId,
            epoch: state.epoch,
            transcriptHash: state.transcriptHash,
            senderFingerprint: senderFingerprint,
            sentAt: sentAt,
            messageCounter: messageCounter,
            payload: payload
        )
        return try GroupRatchetEnvelope(
            id: envelopeId,
            protocolVersion: MLSGroupEpochState.currentProtocolVersion,
            cipherSuite: MLSGroupEpochState.currentCipherSuite,
            groupId: state.groupId,
            epoch: state.epoch,
            transcriptHash: state.transcriptHash,
            senderFingerprint: senderFingerprint,
            sentAt: sentAt,
            messageCounter: messageCounter,
            payload: payload,
            signature: senderSigningKey.sign(signable)
        )
    }

    public static func decrypt(
        envelope: GroupRatchetEnvelope,
        senderPublicSigningKey: Data,
        state: inout GroupRatchetState
    ) throws -> MessageBody {
        try decryptWithKey(
            envelope: envelope,
            senderPublicSigningKey: senderPublicSigningKey,
            state: &state
        ).body
    }

    public static func decryptWithKey(
        envelope: GroupRatchetEnvelope,
        senderPublicSigningKey: Data,
        state: inout GroupRatchetState
    ) throws -> (body: MessageBody, messageKey: SymmetricKey) {
        guard envelope.groupId == state.groupId,
              envelope.protocolVersion == MLSGroupEpochState.currentProtocolVersion,
              envelope.cipherSuite == MLSGroupEpochState.currentCipherSuite,
              envelope.epoch == state.epoch,
              envelope.transcriptHash == state.transcriptHash,
              envelope.verifySignature(publicSigningKey: senderPublicSigningKey) else {
            throw CryptoError.invalidPayload
        }
        var candidateState = state
        let key = try candidateState.receiveKey(
            senderFingerprint: envelope.senderFingerprint,
            counter: envelope.messageCounter
        )
        let aad = try authenticatedData(
            id: envelope.id,
            protocolVersion: envelope.protocolVersion,
            cipherSuite: envelope.cipherSuite,
            groupId: envelope.groupId,
            epoch: envelope.epoch,
            transcriptHash: envelope.transcriptHash,
            senderFingerprint: envelope.senderFingerprint,
            sentAt: envelope.sentAt,
            messageCounter: envelope.messageCounter,
            payloadNonce: envelope.payload.nonce,
            ciphertextByteCount: envelope.payload.ciphertext.count,
            authenticationTagByteCount: envelope.payload.tag.count
        )
        var plaintext = try CryptoBox.decrypt(envelope.payload, key: key, authenticatedData: aad)
        defer { plaintext.secureWipe() }
        let body = try PaddedMessagePlaintext.decodeGroupMessageBody(plaintext)
        state = candidateState
        return (body, key)
    }

    static func signableData(
        id: UUID,
        protocolVersion: String,
        cipherSuite: String,
        groupId: UUID,
        epoch: UInt64,
        transcriptHash: Data,
        senderFingerprint: String,
        sentAt: Date,
        messageCounter: UInt64,
        payload: EncryptedPayload
    ) throws -> Data {
        try NoctweaveCoder.encode(
            GroupRatchetSignaturePayload(
                version: applicationEnvelopeVersion,
                id: id,
                protocolVersion: protocolVersion,
                cipherSuite: cipherSuite,
                groupId: groupId,
                epoch: epoch,
                transcriptHash: transcriptHash,
                senderFingerprint: senderFingerprint,
                sentAt: sentAt,
                messageCounter: messageCounter,
                payload: payload
            ),
            sortedKeys: true
        )
    }

    static func authenticatedData(
        id: UUID,
        protocolVersion: String,
        cipherSuite: String,
        groupId: UUID,
        epoch: UInt64,
        transcriptHash: Data,
        senderFingerprint: String,
        sentAt: Date,
        messageCounter: UInt64,
        payloadNonce: Data,
        ciphertextByteCount: Int,
        authenticationTagByteCount: Int
    ) throws -> Data {
        try NoctweaveCoder.encode(
            GroupRatchetAuthenticatedData(
                version: applicationEnvelopeVersion,
                id: id,
                protocolVersion: protocolVersion,
                cipherSuite: cipherSuite,
                groupId: groupId,
                epoch: epoch,
                transcriptHash: transcriptHash,
                senderFingerprint: senderFingerprint,
                sentAt: sentAt,
                messageCounter: messageCounter,
                payloadNonce: payloadNonce,
                ciphertextByteCount: ciphertextByteCount,
                authenticationTagByteCount: authenticationTagByteCount
            ),
            sortedKeys: true
        )
    }
}

private struct GroupRatchetAuthenticatedData: Codable {
    let version: Int
    let id: UUID
    let protocolVersion: String
    let cipherSuite: String
    let groupId: UUID
    let epoch: UInt64
    let transcriptHash: Data
    let senderFingerprint: String
    let sentAt: Date
    let messageCounter: UInt64
    let payloadNonce: Data
    let ciphertextByteCount: Int
    let authenticationTagByteCount: Int
}

private struct GroupRatchetSignaturePayload: Codable {
    let version: Int
    let id: UUID
    let protocolVersion: String
    let cipherSuite: String
    let groupId: UUID
    let epoch: UInt64
    let transcriptHash: Data
    let senderFingerprint: String
    let sentAt: Date
    let messageCounter: UInt64
    let payload: EncryptedPayload
}

private struct GroupRatchetSecretShareAuthenticatedData: Codable {
    let version: Int
    let groupId: UUID
    let epoch: UInt64
    let operation: MLSGroupCommitOperation
    let memberFingerprints: [String]
    let recipientFingerprint: String
}
