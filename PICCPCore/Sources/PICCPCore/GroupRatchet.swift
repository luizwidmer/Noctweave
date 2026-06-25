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

public enum GroupRatchet {
    public static func encrypt(
        body: MessageBody,
        senderSigningKey: SigningKeyPair,
        senderFingerprint: String,
        state: inout GroupRatchetState
    ) throws -> GroupRatchetEnvelope {
        let plaintext = try PICCPCoder.encode(body)
        let prepared = try state.nextSendKey(senderFingerprint: senderFingerprint)
        let sentAt = Date()
        let aad = try authenticatedData(
            groupId: state.groupId,
            epoch: state.epoch,
            transcriptHash: state.transcriptHash,
            senderFingerprint: senderFingerprint,
            messageCounter: prepared.counter
        )
        let payload = try CryptoBox.encrypt(plaintext, key: prepared.key, authenticatedData: aad)
        let signable = try signableData(
            groupId: state.groupId,
            epoch: state.epoch,
            transcriptHash: state.transcriptHash,
            senderFingerprint: senderFingerprint,
            sentAt: sentAt,
            messageCounter: prepared.counter,
            payload: payload
        )
        return try GroupRatchetEnvelope(
            groupId: state.groupId,
            epoch: state.epoch,
            transcriptHash: state.transcriptHash,
            senderFingerprint: senderFingerprint,
            sentAt: sentAt,
            messageCounter: prepared.counter,
            payload: payload,
            signature: senderSigningKey.sign(signable)
        )
    }

    public static func decrypt(
        envelope: GroupRatchetEnvelope,
        senderPublicSigningKey: Data,
        state: inout GroupRatchetState
    ) throws -> MessageBody {
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
        return try PICCPCoder.decode(MessageBody.self, from: plaintext)
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
