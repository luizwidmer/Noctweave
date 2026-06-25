import CryptoKit
import Foundation

public struct GroupRatchetState: Codable, Equatable {
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
        guard epoch > self.epoch,
              !transcriptHash.isEmpty,
              !commitSecret.isEmpty else {
            throw CryptoError.invalidPayload
        }
        rootKey = Self.deriveRootKey(
            groupId: groupId,
            epoch: epoch,
            transcriptHash: transcriptHash,
            groupSecret: commitSecret,
            priorRootKey: rootKey
        )
        self.epoch = epoch
        self.transcriptHash = transcriptHash
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
        return try sendChain!.nextMessageKey()
    }

    mutating func receiveKey(senderFingerprint: String, counter: UInt64) throws -> SymmetricKey {
        var chain = receiveChains[senderFingerprint] ?? Self.senderChain(
            rootKey: rootKey,
            transcriptHash: transcriptHash,
            senderFingerprint: senderFingerprint
        )
        let key = try chain.messageKey(for: counter, maxSkip: ChainKeyState.defaultMaxSkip)
        receiveChains[senderFingerprint] = chain
        return key
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
        let history = descriptor.mlsEpochHistory
            .sorted { $0.epoch < $1.epoch }
            .filter { $0.ratchetSecretDistribution != nil }

        if var state = existing,
           state.groupId == descriptor.id {
            for commit in history where commit.epoch > state.epoch {
                guard let secret = ratchetSecret(from: commit, identity: identity),
                      advance(&state, to: commit.epoch, transcriptHash: commit.transcriptHash, secret: secret) else {
                    return state.epoch == descriptor.epoch ? state : existing
                }
            }
            return state.epoch == descriptor.epoch ? state : existing
        }

        if let first = history.first,
           first.epoch == 0,
           let secret = ratchetSecret(from: first, identity: identity) {
            var state = GroupRatchetState.initialize(
                groupId: descriptor.id,
                epoch: first.epoch,
                transcriptHash: first.transcriptHash,
                groupSecret: secret,
                localSenderFingerprint: identity.fingerprint
            )
            for commit in history.dropFirst() {
                guard let secret = ratchetSecret(from: commit, identity: identity),
                      advance(&state, to: commit.epoch, transcriptHash: commit.transcriptHash, secret: secret) else {
                    return nil
                }
            }
            if state.epoch == descriptor.epoch {
                return state
            }
        }

        guard let distribution = descriptor.mlsEpochState.lastCommit.ratchetSecretDistribution,
              distribution.epoch == descriptor.epoch,
              let secret = try? distribution.openSecret(
                recipientFingerprint: identity.fingerprint,
                agreementKey: identity.agreementKey
              ) else {
            return existing
        }
        return GroupRatchetState.initialize(
            groupId: descriptor.id,
            epoch: descriptor.epoch,
            transcriptHash: descriptor.mlsEpochState.confirmedTranscriptHash,
            groupSecret: secret,
            localSenderFingerprint: identity.fingerprint
        )
    }

    private static func ratchetSecret(from commit: MLSGroupCommitSummary, identity: Identity) -> Data? {
        guard let distribution = commit.ratchetSecretDistribution else {
            return nil
        }
        return try? distribution.openSecret(
            recipientFingerprint: identity.fingerprint,
            agreementKey: identity.agreementKey
        )
    }

    private static func advance(
        _ state: inout GroupRatchetState,
        to epoch: UInt64,
        transcriptHash: Data,
        secret: Data
    ) -> Bool {
        guard epoch == state.epoch + 1 else {
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
        guard senderFingerprint == CryptoBox.fingerprint(for: publicSigningKey),
              let data = try? GroupRatchet.signableData(
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

    public static func seal(
        secret: Data,
        groupId: UUID,
        epoch: UInt64,
        operation: MLSGroupCommitOperation,
        recipients: [RelayGroupMemberProfile]
    ) throws -> GroupRatchetEpochSecretDistribution {
        guard !secret.isEmpty else {
            throw CryptoError.invalidPayload
        }
        let normalizedRecipients = recipients
            .filter { !$0.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
            .sorted { $0.fingerprint < $1.fingerprint }
        let memberFingerprints = normalizedRecipients.map(\.fingerprint)
        let shares = try normalizedRecipients.map { recipient -> GroupRatchetSecretShare in
            guard let publicKey = recipient.agreementPublicKey,
                  AgreementKeyPair.isValidPublicKey(publicKey) else {
                throw CryptoError.invalidPublicKey
            }
            let kem = try AgreementKeyPair.encapsulate(to: publicKey)
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
        guard let share = shares.first(where: { $0.recipientFingerprint == recipientFingerprint }),
              memberFingerprints.contains(recipientFingerprint) else {
            throw CryptoError.invalidPayload
        }
        let sharedSecret = try agreementKey.decapsulate(ciphertext: share.kemCiphertext)
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
        try PICCPCoder.encode(
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
    public static func encrypt(
        body: MessageBody,
        senderSigningKey: SigningKeyPair,
        senderFingerprint: String,
        state: inout GroupRatchetState
    ) throws -> GroupRatchetEnvelope {
        let prepared = try state.nextSendKey(senderFingerprint: senderFingerprint)
        return try encrypt(
            body: body,
            senderSigningKey: senderSigningKey,
            senderFingerprint: senderFingerprint,
            messageCounter: prepared.counter,
            messageKey: prepared.key,
            state: state
        )
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
        state: GroupRatchetState
    ) throws -> GroupRatchetEnvelope {
        let plaintext = try PICCPCoder.encode(body)
        let sentAt = Date()
        let aad = try authenticatedData(
            groupId: state.groupId,
            epoch: state.epoch,
            transcriptHash: state.transcriptHash,
            senderFingerprint: senderFingerprint,
            messageCounter: messageCounter
        )
        let payload = try CryptoBox.encrypt(plaintext, key: messageKey, authenticatedData: aad)
        let signable = try signableData(
            groupId: state.groupId,
            epoch: state.epoch,
            transcriptHash: state.transcriptHash,
            senderFingerprint: senderFingerprint,
            sentAt: sentAt,
            messageCounter: messageCounter,
            payload: payload
        )
        return try GroupRatchetEnvelope(
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
              envelope.epoch == state.epoch,
              envelope.transcriptHash == state.transcriptHash,
              envelope.verifySignature(publicSigningKey: senderPublicSigningKey) else {
            throw CryptoError.invalidPayload
        }
        let key = try state.receiveKey(
            senderFingerprint: envelope.senderFingerprint,
            counter: envelope.messageCounter
        )
        let aad = try authenticatedData(
            groupId: envelope.groupId,
            epoch: envelope.epoch,
            transcriptHash: envelope.transcriptHash,
            senderFingerprint: envelope.senderFingerprint,
            messageCounter: envelope.messageCounter
        )
        let plaintext = try CryptoBox.decrypt(envelope.payload, key: key, authenticatedData: aad)
        return (try PICCPCoder.decode(MessageBody.self, from: plaintext), key)
    }

    static func signableData(
        groupId: UUID,
        epoch: UInt64,
        transcriptHash: Data,
        senderFingerprint: String,
        sentAt: Date,
        messageCounter: UInt64,
        payload: EncryptedPayload
    ) throws -> Data {
        try PICCPCoder.encode(
            GroupRatchetSignaturePayload(
                version: 1,
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

    private static func authenticatedData(
        groupId: UUID,
        epoch: UInt64,
        transcriptHash: Data,
        senderFingerprint: String,
        messageCounter: UInt64
    ) throws -> Data {
        try PICCPCoder.encode(
            GroupRatchetAuthenticatedData(
                version: 1,
                groupId: groupId,
                epoch: epoch,
                transcriptHash: transcriptHash,
                senderFingerprint: senderFingerprint,
                messageCounter: messageCounter
            ),
            sortedKeys: true
        )
    }
}

private struct GroupRatchetAuthenticatedData: Codable {
    let version: Int
    let groupId: UUID
    let epoch: UInt64
    let transcriptHash: Data
    let senderFingerprint: String
    let messageCounter: UInt64
}

private struct GroupRatchetSignaturePayload: Codable {
    let version: Int
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
