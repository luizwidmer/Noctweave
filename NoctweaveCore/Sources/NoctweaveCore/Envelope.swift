import Foundation

public enum DirectBootstrapV4: Codable, Equatable {
    case none
    case signedPrekey(kemCiphertext: Data, prekey: PrekeyReference)

    private enum Kind: String, Codable {
        case none
        case signedPrekey
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case kind
        case kemCiphertext
        case prekey
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: StrictEnvelopeCodingKey.self)
        let keys = Set(strict.allKeys.map(\.stringValue))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try container.decode(Kind.self, forKey: .kind)
        switch kind {
        case .none:
            guard keys == [CodingKeys.kind.rawValue] else {
                throw DecodingError.dataCorruptedError(
                    forKey: .kind,
                    in: container,
                    debugDescription: "The none bootstrap case accepts no payload fields."
                )
            }
            self = .none
        case .signedPrekey:
            guard keys == Set(CodingKeys.allCases.map(\.rawValue)) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .kind,
                    in: container,
                    debugDescription: "The signed-prekey bootstrap case requires exactly one KEM ciphertext and prekey reference."
                )
            }
            self = .signedPrekey(
                kemCiphertext: try container.decode(Data.self, forKey: .kemCiphertext),
                prekey: try container.decode(PrekeyReference.self, forKey: .prekey)
            )
        }
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .kind,
                in: container,
                debugDescription: "Invalid direct bootstrap."
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid direct bootstrap."
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .none:
            try container.encode(Kind.none, forKey: .kind)
        case .signedPrekey(let kemCiphertext, let prekey):
            try container.encode(Kind.signedPrekey, forKey: .kind)
            try container.encode(kemCiphertext, forKey: .kemCiphertext)
            try container.encode(prekey, forKey: .prekey)
        }
    }

    public var isStructurallyValid: Bool {
        switch self {
        case .none:
            return true
        case .signedPrekey(let kemCiphertext, let prekey):
            return kemCiphertext.count == 1_088 && prekey.kind == .signed
        }
    }

    public var signedPrekeyMaterial: (kemCiphertext: Data, prekey: PrekeyReference)? {
        guard case .signedPrekey(let kemCiphertext, let prekey) = self else { return nil }
        return (kemCiphertext, prekey)
    }
}

/// The only direct-message inner envelope for the 1.0 protocol baseline.
/// Every authenticated field is required and appears in both the signature
/// transcript and the AEAD associated-data transcript.
public struct DirectEnvelopeV4: Codable, Identifiable, Equatable {
    public static let version = 4

    public let version: Int
    public let id: UUID
    public let payloadFormat: String
    public let conversationId: String
    public let sessionId: String
    public let eventId: UUID
    public let senderEndpointHandle: RelationshipEndpointHandle
    public let senderCertificateDigest: Data
    public let senderEndpointSetEpoch: UInt64
    public let recipientEndpointHandle: RelationshipEndpointHandle
    public let recipientCertificateDigest: Data
    public let recipientEndpointSetEpoch: UInt64
    public let cipherSuite: String
    public let negotiatedCapabilitiesDigest: Data
    public let bootstrap: DirectBootstrapV4
    public let sentAt: Date
    public let messageCounter: UInt64
    public let payload: EncryptedPayload
    public let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case id
        case payloadFormat
        case conversationId
        case sessionId
        case eventId
        case senderEndpointHandle
        case senderCertificateDigest
        case senderEndpointSetEpoch
        case recipientEndpointHandle
        case recipientCertificateDigest
        case recipientEndpointSetEpoch
        case cipherSuite
        case negotiatedCapabilitiesDigest
        case bootstrap
        case sentAt
        case messageCounter
        case payload
        case signature
    }

    public init(
        version: Int = DirectEnvelopeV4.version,
        id: UUID,
        payloadFormat: String = NoctweaveWirePayloadV2.directV4Format,
        conversationId: String,
        sessionId: String,
        eventId: UUID,
        senderEndpointHandle: RelationshipEndpointHandle,
        senderCertificateDigest: Data,
        senderEndpointSetEpoch: UInt64,
        recipientEndpointHandle: RelationshipEndpointHandle,
        recipientCertificateDigest: Data,
        recipientEndpointSetEpoch: UInt64,
        cipherSuite: String,
        negotiatedCapabilitiesDigest: Data,
        bootstrap: DirectBootstrapV4,
        sentAt: Date,
        messageCounter: UInt64,
        payload: EncryptedPayload,
        signature: Data
    ) {
        self.version = version
        self.id = id
        self.payloadFormat = payloadFormat
        self.conversationId = conversationId
        self.sessionId = sessionId
        self.eventId = eventId
        self.senderEndpointHandle = senderEndpointHandle
        self.senderCertificateDigest = senderCertificateDigest
        self.senderEndpointSetEpoch = senderEndpointSetEpoch
        self.recipientEndpointHandle = recipientEndpointHandle
        self.recipientCertificateDigest = recipientCertificateDigest
        self.recipientEndpointSetEpoch = recipientEndpointSetEpoch
        self.cipherSuite = cipherSuite
        self.negotiatedCapabilitiesDigest = negotiatedCapabilitiesDigest
        self.bootstrap = bootstrap
        self.sentAt = sentAt
        self.messageCounter = messageCounter
        self.payload = payload
        self.signature = signature
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: StrictEnvelopeCodingKey.self)
        let keys = Set(strict.allKeys.map(\.stringValue))
        guard keys == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "A direct-v4 envelope requires exactly its canonical field set."
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        id = try container.decode(UUID.self, forKey: .id)
        payloadFormat = try container.decode(String.self, forKey: .payloadFormat)
        conversationId = try container.decode(String.self, forKey: .conversationId)
        sessionId = try container.decode(String.self, forKey: .sessionId)
        eventId = try container.decode(UUID.self, forKey: .eventId)
        senderEndpointHandle = try container.decode(
            RelationshipEndpointHandle.self,
            forKey: .senderEndpointHandle
        )
        senderCertificateDigest = try container.decode(Data.self, forKey: .senderCertificateDigest)
        senderEndpointSetEpoch = try container.decode(UInt64.self, forKey: .senderEndpointSetEpoch)
        recipientEndpointHandle = try container.decode(
            RelationshipEndpointHandle.self,
            forKey: .recipientEndpointHandle
        )
        recipientCertificateDigest = try container.decode(
            Data.self,
            forKey: .recipientCertificateDigest
        )
        recipientEndpointSetEpoch = try container.decode(
            UInt64.self,
            forKey: .recipientEndpointSetEpoch
        )
        cipherSuite = try container.decode(String.self, forKey: .cipherSuite)
        negotiatedCapabilitiesDigest = try container.decode(
            Data.self,
            forKey: .negotiatedCapabilitiesDigest
        )
        bootstrap = try container.decode(DirectBootstrapV4.self, forKey: .bootstrap)
        sentAt = try container.decode(Date.self, forKey: .sentAt)
        messageCounter = try container.decode(UInt64.self, forKey: .messageCounter)
        payload = try container.decode(EncryptedPayload.self, forKey: .payload)
        signature = try container.decode(Data.self, forKey: .signature)
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Structurally invalid direct-v4 envelope."
                )
            )
        }
    }

    public var isStructurallyValid: Bool {
        let ciphertextBytes = payload.ciphertext.count
        return version == Self.version
            && payloadFormat == NoctweaveWirePayloadV2.directV4Format
            && !conversationId.isEmpty
            && conversationId.utf8.count <= 256
            && !sessionId.isEmpty
            && sessionId.utf8.count <= 128
            && senderEndpointHandle.isStructurallyValid
            && senderCertificateDigest.count == 32
            && recipientEndpointHandle.isStructurallyValid
            && recipientCertificateDigest.count == 32
            && cipherSuite == DirectV4CipherSuite.identifier
            && negotiatedCapabilitiesDigest.count == 32
            && bootstrap.isStructurallyValid
            && sentAt.timeIntervalSince1970.isFinite
            && payload.nonce.count == 12
            && payload.tag.count == 16
            && (PaddedMessagePlaintext.minimumPaddedBytes...PaddedMessagePlaintext.maximumPaddedBytes)
                .contains(ciphertextBytes)
            && ciphertextBytes > 0
            && (ciphertextBytes & (ciphertextBytes - 1)) == 0
            && signature.count == 3_309
    }

    public func authenticatedData() throws -> Data {
        try Self.authenticatedData(
            id: id,
            payloadFormat: payloadFormat,
            conversationId: conversationId,
            sessionId: sessionId,
            eventId: eventId,
            senderEndpointHandle: senderEndpointHandle,
            senderCertificateDigest: senderCertificateDigest,
            senderEndpointSetEpoch: senderEndpointSetEpoch,
            recipientEndpointHandle: recipientEndpointHandle,
            recipientCertificateDigest: recipientCertificateDigest,
            recipientEndpointSetEpoch: recipientEndpointSetEpoch,
            cipherSuite: cipherSuite,
            negotiatedCapabilitiesDigest: negotiatedCapabilitiesDigest,
            bootstrap: bootstrap,
            sentAt: sentAt,
            messageCounter: messageCounter
        )
    }

    public static func authenticatedData(
        id: UUID,
        payloadFormat: String = NoctweaveWirePayloadV2.directV4Format,
        conversationId: String,
        sessionId: String,
        eventId: UUID,
        senderEndpointHandle: RelationshipEndpointHandle,
        senderCertificateDigest: Data,
        senderEndpointSetEpoch: UInt64,
        recipientEndpointHandle: RelationshipEndpointHandle,
        recipientCertificateDigest: Data,
        recipientEndpointSetEpoch: UInt64,
        cipherSuite: String,
        negotiatedCapabilitiesDigest: Data,
        bootstrap: DirectBootstrapV4,
        sentAt: Date,
        messageCounter: UInt64
    ) throws -> Data {
        try NoctweaveCoder.encode(
            DirectEnvelopeAuthenticatedDataV4(
                version: Self.version,
                id: id,
                payloadFormat: payloadFormat,
                conversationId: conversationId,
                sessionId: sessionId,
                eventId: eventId,
                senderEndpointHandle: senderEndpointHandle,
                senderCertificateDigest: senderCertificateDigest,
                senderEndpointSetEpoch: senderEndpointSetEpoch,
                recipientEndpointHandle: recipientEndpointHandle,
                recipientCertificateDigest: recipientCertificateDigest,
                recipientEndpointSetEpoch: recipientEndpointSetEpoch,
                cipherSuite: cipherSuite,
                negotiatedCapabilitiesDigest: negotiatedCapabilitiesDigest,
                bootstrap: bootstrap,
                sentAt: sentAt,
                messageCounter: messageCounter
            ),
            sortedKeys: true
        )
    }

    public func signableData() throws -> Data {
        try NoctweaveCoder.encode(
            DirectEnvelopeSignaturePayloadV4(
                version: version,
                id: id,
                payloadFormat: payloadFormat,
                conversationId: conversationId,
                sessionId: sessionId,
                eventId: eventId,
                senderEndpointHandle: senderEndpointHandle,
                senderCertificateDigest: senderCertificateDigest,
                senderEndpointSetEpoch: senderEndpointSetEpoch,
                recipientEndpointHandle: recipientEndpointHandle,
                recipientCertificateDigest: recipientCertificateDigest,
                recipientEndpointSetEpoch: recipientEndpointSetEpoch,
                cipherSuite: cipherSuite,
                negotiatedCapabilitiesDigest: negotiatedCapabilitiesDigest,
                bootstrap: bootstrap,
                sentAt: sentAt,
                messageCounter: messageCounter,
                payload: payload
            ),
            sortedKeys: true
        )
    }

    public func verifySignature(publicSigningKey: Data) -> Bool {
        guard isStructurallyValid,
              SigningKeyPair.isValidPublicKey(publicSigningKey),
              let signable = try? signableData() else {
            return false
        }
        return SigningKeyPair.verify(
            signature: signature,
            data: signable,
            publicKeyData: publicSigningKey
        )
    }
}

/// Strict group-only application envelope for the experimental v2 profile.
/// It intentionally contains no endpoint, generation, or relationship data.
public struct GroupApplicationEnvelopeV2: Codable, Identifiable, Equatable {
    public static let timestampBucketSeconds: TimeInterval = 300

    public var id: UUID { eventId }
    public let version: Int
    public let profile: GroupProtocolProfile
    public let cipherSuite: String
    public let groupId: UUID
    public let epoch: UInt64
    public let transcriptHash: Data
    public let senderClientHandle: GroupScopedClientHandleV2
    public let eventId: UUID
    public let messageCounter: UInt64
    public let sentAt: Date
    public let payload: EncryptedPayload
    public let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case profile
        case cipherSuite
        case groupId
        case epoch
        case transcriptHash
        case senderClientHandle
        case eventId
        case messageCounter
        case sentAt
        case payload
        case signature
    }

    public init(
        version: Int = NoctweaveSignedGroupV2.version,
        profile: GroupProtocolProfile,
        cipherSuite: String,
        groupId: UUID,
        epoch: UInt64,
        transcriptHash: Data,
        senderClientHandle: GroupScopedClientHandleV2,
        eventId: UUID,
        messageCounter: UInt64,
        sentAt: Date,
        payload: EncryptedPayload,
        signature: Data
    ) {
        self.version = version
        self.profile = profile
        self.cipherSuite = cipherSuite
        self.groupId = groupId
        self.epoch = epoch
        self.transcriptHash = transcriptHash
        self.senderClientHandle = senderClientHandle
        self.eventId = eventId
        self.messageCounter = messageCounter
        self.sentAt = sentAt
        self.payload = payload
        self.signature = signature
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: StrictEnvelopeCodingKey.self)
        let keys = Set(strict.allKeys.map(\.stringValue))
        guard keys == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "A group application envelope requires exactly its canonical field set."
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        profile = try container.decode(GroupProtocolProfile.self, forKey: .profile)
        cipherSuite = try container.decode(String.self, forKey: .cipherSuite)
        groupId = try container.decode(UUID.self, forKey: .groupId)
        epoch = try container.decode(UInt64.self, forKey: .epoch)
        transcriptHash = try container.decode(Data.self, forKey: .transcriptHash)
        senderClientHandle = try container.decode(
            GroupScopedClientHandleV2.self,
            forKey: .senderClientHandle
        )
        eventId = try container.decode(UUID.self, forKey: .eventId)
        messageCounter = try container.decode(UInt64.self, forKey: .messageCounter)
        sentAt = try container.decode(Date.self, forKey: .sentAt)
        payload = try container.decode(EncryptedPayload.self, forKey: .payload)
        signature = try container.decode(Data.self, forKey: .signature)
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Structurally invalid group application envelope."
                )
            )
        }
    }

    public static func create(
        groupId: UUID,
        epoch: UInt64,
        transcriptHash: Data,
        senderClientHandle: GroupScopedClientHandleV2,
        eventId: UUID = UUID(),
        messageCounter: UInt64,
        sentAt: Date = Date(),
        payload: EncryptedPayload,
        signingKey: SigningKeyPair
    ) throws -> GroupApplicationEnvelopeV2 {
        let bucketedSentAt = Date(
            timeIntervalSince1970: floor(
                sentAt.timeIntervalSince1970 / timestampBucketSeconds
            ) * timestampBucketSeconds
        )
        var envelope = GroupApplicationEnvelopeV2(
            profile: NoctweaveSignedGroupV2.experimentalProfile,
            cipherSuite: NoctweaveSignedGroupV2.experimentalCipherSuite,
            groupId: groupId,
            epoch: epoch,
            transcriptHash: transcriptHash,
            senderClientHandle: senderClientHandle,
            eventId: eventId,
            messageCounter: messageCounter,
            sentAt: bucketedSentAt,
            payload: payload,
            signature: Data()
        )
        let signature = try signingKey.sign(envelope.signableData())
        envelope = GroupApplicationEnvelopeV2(
            profile: envelope.profile,
            cipherSuite: envelope.cipherSuite,
            groupId: envelope.groupId,
            epoch: envelope.epoch,
            transcriptHash: envelope.transcriptHash,
            senderClientHandle: envelope.senderClientHandle,
            eventId: envelope.eventId,
            messageCounter: envelope.messageCounter,
            sentAt: envelope.sentAt,
            payload: envelope.payload,
            signature: signature
        )
        guard envelope.isStructurallyValid else { throw SignedGroupV2Error.invalidStructure }
        return envelope
    }

    public var isStructurallyValid: Bool {
        let timestamp = sentAt.timeIntervalSince1970
        return version == NoctweaveSignedGroupV2.version
            && profile == NoctweaveSignedGroupV2.experimentalProfile
            && cipherSuite == NoctweaveSignedGroupV2.experimentalCipherSuite
            && epoch > 0
            && transcriptHash.count == 32
            && senderClientHandle.isStructurallyValid
            && timestamp.isFinite
            && timestamp.truncatingRemainder(dividingBy: Self.timestampBucketSeconds) == 0
            && payload.nonce.count == 12
            && !payload.ciphertext.isEmpty
            && payload.ciphertext.count <= NoctweaveArchitectureV2.maximumContentPayloadBytes
            && payload.tag.count == 16
            && signature.count == NoctweaveSignedGroupV2.signatureBytes
    }

    public func signableData() throws -> Data {
        try NoctweaveCoder.encode(
            GroupApplicationSignaturePayloadV2(
                version: version,
                profile: profile,
                cipherSuite: cipherSuite,
                groupId: groupId,
                epoch: epoch,
                transcriptHash: transcriptHash,
                senderClientHandle: senderClientHandle,
                eventId: eventId,
                messageCounter: messageCounter,
                sentAt: sentAt,
                payload: payload
            ),
            sortedKeys: true
        )
    }

    public func verifySignature(groupClientSigningPublicKey: Data) -> Bool {
        guard isStructurallyValid,
              SigningKeyPair.isValidPublicKey(groupClientSigningPublicKey),
              let signable = try? signableData() else {
            return false
        }
        return SigningKeyPair.verify(
            signature: signature,
            data: signable,
            publicKeyData: groupClientSigningPublicKey
        )
    }
}

/// Exact-one inner protocol union. Unknown keys, missing cases, multiple cases,
/// and structurally invalid nested envelopes all fail during decoding.
public enum ProtocolEnvelopeV1: Codable, Identifiable, Equatable {
    public static let version = 1

    case directV4(DirectEnvelopeV4)
    case groupApplicationV2(GroupApplicationEnvelopeV2)
    case groupCommitV2(SignedGroupCommitV2)
    case groupWelcomeV2(SignedGroupWelcomeV2)
    case groupDeletionV2(SignedGroupDeletionTombstoneV2)

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case directV4
        case groupApplicationV2
        case groupCommitV2
        case groupWelcomeV2
        case groupDeletionV2
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: StrictEnvelopeCodingKey.self)
        let keyNames = Set(strict.allKeys.map(\.stringValue))
        let allowed = Set(CodingKeys.allCases.map(\.rawValue))
        guard keyNames.isSubset(of: allowed) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Unknown protocol-envelope case or field."
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard try container.decode(Int.self, forKey: .version) == Self.version else {
            throw DecodingError.dataCorruptedError(
                forKey: .version,
                in: container,
                debugDescription: "Unsupported protocol-envelope version."
            )
        }
        let cases = CodingKeys.allCases.filter { $0 != .version && container.contains($0) }
        guard keyNames.count == 2, cases.count == 1 else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "A protocol envelope must contain exactly one case."
                )
            )
        }
        switch cases[0] {
        case .directV4:
            self = .directV4(try container.decode(DirectEnvelopeV4.self, forKey: .directV4))
        case .groupApplicationV2:
            self = .groupApplicationV2(
                try container.decode(GroupApplicationEnvelopeV2.self, forKey: .groupApplicationV2)
            )
        case .groupCommitV2:
            self = .groupCommitV2(
                try container.decode(SignedGroupCommitV2.self, forKey: .groupCommitV2)
            )
        case .groupWelcomeV2:
            self = .groupWelcomeV2(
                try container.decode(SignedGroupWelcomeV2.self, forKey: .groupWelcomeV2)
            )
        case .groupDeletionV2:
            self = .groupDeletionV2(
                try container.decode(SignedGroupDeletionTombstoneV2.self, forKey: .groupDeletionV2)
            )
        case .version:
            throw DecodingError.dataCorruptedError(
                forKey: .version,
                in: container,
                debugDescription: "Missing protocol-envelope case."
            )
        }
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Structurally invalid protocol envelope."
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Structurally invalid protocol envelope."
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(Self.version, forKey: .version)
        switch self {
        case .directV4(let envelope):
            try container.encode(envelope, forKey: .directV4)
        case .groupApplicationV2(let envelope):
            try container.encode(envelope, forKey: .groupApplicationV2)
        case .groupCommitV2(let commit):
            try container.encode(commit, forKey: .groupCommitV2)
        case .groupWelcomeV2(let welcome):
            try container.encode(welcome, forKey: .groupWelcomeV2)
        case .groupDeletionV2(let deletion):
            try container.encode(deletion, forKey: .groupDeletionV2)
        }
    }

    public var id: UUID {
        switch self {
        case .directV4(let envelope): return envelope.id
        case .groupApplicationV2(let envelope): return envelope.id
        case .groupCommitV2(let commit): return commit.id
        case .groupWelcomeV2(let welcome): return welcome.id
        case .groupDeletionV2(let deletion): return deletion.id
        }
    }

    public var isStructurallyValid: Bool {
        switch self {
        case .directV4(let envelope): return envelope.isStructurallyValid
        case .groupApplicationV2(let envelope): return envelope.isStructurallyValid
        case .groupCommitV2(let commit): return commit.isStructurallyValid
        case .groupWelcomeV2(let welcome): return welcome.isStructurallyValid
        case .groupDeletionV2(let deletion): return deletion.isStructurallyValid
        }
    }

    public var encodedPayloadByteCount: Int {
        switch self {
        case .directV4(let envelope):
            return envelope.payload.nonce.count
                + envelope.payload.ciphertext.count
                + envelope.payload.tag.count
        case .groupApplicationV2(let envelope):
            return envelope.payload.nonce.count
                + envelope.payload.ciphertext.count
                + envelope.payload.tag.count
        case .groupCommitV2, .groupWelcomeV2, .groupDeletionV2:
            return (try? NoctweaveCoder.encode(self).count) ?? Int.max
        }
    }
}

private struct DirectEnvelopeAuthenticatedDataV4: Codable {
    let version: Int
    let id: UUID
    let payloadFormat: String
    let conversationId: String
    let sessionId: String
    let eventId: UUID
    let senderEndpointHandle: RelationshipEndpointHandle
    let senderCertificateDigest: Data
    let senderEndpointSetEpoch: UInt64
    let recipientEndpointHandle: RelationshipEndpointHandle
    let recipientCertificateDigest: Data
    let recipientEndpointSetEpoch: UInt64
    let cipherSuite: String
    let negotiatedCapabilitiesDigest: Data
    let bootstrap: DirectBootstrapV4
    let sentAt: Date
    let messageCounter: UInt64
}

private struct DirectEnvelopeSignaturePayloadV4: Codable {
    let version: Int
    let id: UUID
    let payloadFormat: String
    let conversationId: String
    let sessionId: String
    let eventId: UUID
    let senderEndpointHandle: RelationshipEndpointHandle
    let senderCertificateDigest: Data
    let senderEndpointSetEpoch: UInt64
    let recipientEndpointHandle: RelationshipEndpointHandle
    let recipientCertificateDigest: Data
    let recipientEndpointSetEpoch: UInt64
    let cipherSuite: String
    let negotiatedCapabilitiesDigest: Data
    let bootstrap: DirectBootstrapV4
    let sentAt: Date
    let messageCounter: UInt64
    let payload: EncryptedPayload
}

private struct GroupApplicationSignaturePayloadV2: Codable {
    let version: Int
    let profile: GroupProtocolProfile
    let cipherSuite: String
    let groupId: UUID
    let epoch: UInt64
    let transcriptHash: Data
    let senderClientHandle: GroupScopedClientHandleV2
    let eventId: UUID
    let messageCounter: UInt64
    let sentAt: Date
    let payload: EncryptedPayload
}

private struct StrictEnvelopeCodingKey: CodingKey, Hashable {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }

    init?(intValue: Int) {
        self.stringValue = String(intValue)
        self.intValue = intValue
    }
}
