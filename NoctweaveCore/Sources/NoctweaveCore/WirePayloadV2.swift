import CryptoKit
import Foundation

public enum NoctweaveWirePayloadV2 {
    public static let version = 2
    public static let directV4Format = "nw.wire-payload.v2"
    public static let maximumControlPayloadBytes = 48 * 1_024
    public static let unsupportedFallbackPrefix = "Unsupported message"
}

public enum WirePayloadV2Error: Error, Equatable {
    case invalidPayload
    case invalidApplicationEvent
    case invalidKnownApplicationContent
    case invalidKnownControl
    case unknownControl
    case directV4FormatRequired
}

public enum WirePayloadKindV2: String, Codable, Equatable {
    case application
    case control
}

public enum RelationshipControlKindV2: String, Codable, Equatable, CaseIterable {
    case sessionReset
    case resendRequest
    case continuityOffer
    case routeSetUpdate
    case routeProbe
    case endpointPrekeyUpdate

    public var contentType: ContentTypeId {
        ContentTypeId(
            authority: "org.noctweave.control",
            name: rawValue,
            major: 2,
            minor: 0
        )
    }

    public init?(contentType: ContentTypeId) {
        guard contentType.authority == "org.noctweave.control",
              contentType.major == 2,
              contentType.minor == 0 else {
            return nil
        }
        self.init(rawValue: contentType.name)
    }
}

/// A successor invitation delivered to one existing relationship. It creates
/// no global old/new persona link and is meaningful only to that peer.
public struct RelationshipContinuityOfferV2: Codable, Equatable {
    public let relationshipID: UUID
    public let invitation: ContactPairingInvitationV2
    public let expiresAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case relationshipID
        case invitation
        case expiresAt
    }

    public init(
        relationshipID: UUID,
        invitation: ContactPairingInvitationV2,
        expiresAt: Date
    ) {
        self.relationshipID = relationshipID
        self.invitation = invitation
        self.expiresAt = expiresAt
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: WirePayloadCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Continuity offer fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            relationshipID: try container.decode(UUID.self, forKey: .relationshipID),
            invitation: try container.decode(
                ContactPairingInvitationV2.self,
                forKey: .invitation
            ),
            expiresAt: try container.decode(Date.self, forKey: .expiresAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .invitation,
                in: container,
                debugDescription: "Invalid relationship continuity offer"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid relationship continuity offer"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(relationshipID, forKey: .relationshipID)
        try container.encode(invitation, forKey: .invitation)
        try container.encode(expiresAt, forKey: .expiresAt)
    }

    public var isStructurallyValid: Bool {
        invitation.isStructurallyValid
            && expiresAt.timeIntervalSince1970.isFinite
            && expiresAt == invitation.offer.expiresAt
    }
}

public struct RelationshipRouteSetUpdateV2: Codable, Equatable {
    public let relationshipID: UUID
    public let routeSet: PairwiseRouteSetV2

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case relationshipID
        case routeSet
    }

    public init(relationshipID: UUID, routeSet: PairwiseRouteSetV2) {
        self.relationshipID = relationshipID
        self.routeSet = routeSet
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: WirePayloadCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Route-set update fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        relationshipID = try container.decode(UUID.self, forKey: .relationshipID)
        routeSet = try container.decode(PairwiseRouteSetV2.self, forKey: .routeSet)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .routeSet,
                in: container,
                debugDescription: "Route-set update is invalid"
            )
        }
    }

    public var isStructurallyValid: Bool {
        routeSet.relationshipID == relationshipID && routeSet.isStructurallyValid
    }
}

public struct RelationshipRouteProbeV2: Codable, Equatable {
    public let relationshipID: UUID
    public let routeID: OpaqueReceiveRouteIDV2
    public let routeSetRevision: UInt64
    public let nonce: UUID

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case relationshipID
        case routeID
        case routeSetRevision
        case nonce
    }

    public init(
        relationshipID: UUID,
        routeID: OpaqueReceiveRouteIDV2,
        routeSetRevision: UInt64,
        nonce: UUID = UUID()
    ) {
        self.relationshipID = relationshipID
        self.routeID = routeID
        self.routeSetRevision = routeSetRevision
        self.nonce = nonce
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: WirePayloadCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Route-probe fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        relationshipID = try container.decode(UUID.self, forKey: .relationshipID)
        routeID = try container.decode(OpaqueReceiveRouteIDV2.self, forKey: .routeID)
        routeSetRevision = try container.decode(UInt64.self, forKey: .routeSetRevision)
        nonce = try container.decode(UUID.self, forKey: .nonce)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .routeID,
                in: container,
                debugDescription: "Route probe is invalid"
            )
        }
    }

    public var isStructurallyValid: Bool {
        routeID.isStructurallyValid
    }
}

public struct RelationshipEndpointPrekeyUpdateV2: Codable, Equatable {
    public let relationshipID: UUID
    public let endpointBinding: RelationshipEndpointBindingV4

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case relationshipID
        case endpointBinding
    }

    public init(
        relationshipID: UUID,
        endpointBinding: RelationshipEndpointBindingV4
    ) {
        self.relationshipID = relationshipID
        self.endpointBinding = endpointBinding
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: WirePayloadCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Endpoint-prekey update fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        relationshipID = try container.decode(UUID.self, forKey: .relationshipID)
        endpointBinding = try container.decode(
            RelationshipEndpointBindingV4.self,
            forKey: .endpointBinding
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .endpointBinding,
                in: container,
                debugDescription: "Endpoint-prekey update is invalid"
            )
        }
    }

    public var isStructurallyValid: Bool {
        endpointBinding.authorizationDigest?.count == SHA256.byteCount
    }
}

public enum KnownRelationshipControlV2: Equatable {
    case sessionReset(SessionReset)
    case resendRequest(ResendRequest)
    case continuityOffer(RelationshipContinuityOfferV2)
    case routeSetUpdate(RelationshipRouteSetUpdateV2)
    case routeProbe(RelationshipRouteProbeV2)
    case endpointPrekeyUpdate(RelationshipEndpointPrekeyUpdateV2)
}

/// Security-sensitive controls are authenticated independently from the outer
/// direct envelope and explicitly bound to one relationship, event and sender.
public struct AuthenticatedRelationshipControlV2: Codable, Equatable {
    public static let version = 2

    public let version: Int
    public let type: ContentTypeId
    public let relationshipID: UUID
    public let eventID: UUID
    public let senderEndpointHandle: RelationshipEndpointHandle
    public let issuedAt: Date
    public let nonce: UUID
    public let encodedPayload: Data
    public let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case type
        case relationshipID
        case eventID
        case senderEndpointHandle
        case issuedAt
        case nonce
        case encodedPayload
        case signature
    }

    public init(
        version: Int = Self.version,
        type: ContentTypeId,
        relationshipID: UUID,
        eventID: UUID,
        senderEndpointHandle: RelationshipEndpointHandle,
        issuedAt: Date,
        nonce: UUID,
        encodedPayload: Data,
        signature: Data
    ) {
        self.version = version
        self.type = type
        self.relationshipID = relationshipID
        self.eventID = eventID
        self.senderEndpointHandle = senderEndpointHandle
        self.issuedAt = issuedAt
        self.nonce = nonce
        self.encodedPayload = encodedPayload
        self.signature = signature
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: WirePayloadCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Relationship-control fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try container.decode(Int.self, forKey: .version),
            type: try container.decode(ContentTypeId.self, forKey: .type),
            relationshipID: try container.decode(UUID.self, forKey: .relationshipID),
            eventID: try container.decode(UUID.self, forKey: .eventID),
            senderEndpointHandle: try container.decode(
                RelationshipEndpointHandle.self,
                forKey: .senderEndpointHandle
            ),
            issuedAt: try container.decode(Date.self, forKey: .issuedAt),
            nonce: try container.decode(UUID.self, forKey: .nonce),
            encodedPayload: try container.decode(Data.self, forKey: .encodedPayload),
            signature: try container.decode(Data.self, forKey: .signature)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .signature,
                in: container,
                debugDescription: "Relationship control is structurally invalid"
            )
        }
    }

    public static func create<Payload: Codable>(
        kind: RelationshipControlKindV2,
        payload: Payload,
        relationshipID: UUID,
        eventID: UUID,
        senderEndpointHandle: RelationshipEndpointHandle,
        issuedAt: Date,
        signingKey: SigningKeyPair,
        nonce: UUID = UUID()
    ) throws -> AuthenticatedRelationshipControlV2 {
        let encoded = try NoctweaveCoder.encode(payload, sortedKeys: true)
        var control = AuthenticatedRelationshipControlV2(
            type: kind.contentType,
            relationshipID: relationshipID,
            eventID: eventID,
            senderEndpointHandle: senderEndpointHandle,
            issuedAt: issuedAt,
            nonce: nonce,
            encodedPayload: encoded,
            signature: Data()
        )
        control = AuthenticatedRelationshipControlV2(
            type: control.type,
            relationshipID: control.relationshipID,
            eventID: control.eventID,
            senderEndpointHandle: control.senderEndpointHandle,
            issuedAt: control.issuedAt,
            nonce: control.nonce,
            encodedPayload: control.encodedPayload,
            signature: try signingKey.sign(control.signableData())
        )
        guard control.isStructurallyValid else { throw WirePayloadV2Error.invalidKnownControl }
        return control
    }

    public var knownKind: RelationshipControlKindV2? {
        RelationshipControlKindV2(contentType: type)
    }

    public var isStructurallyValid: Bool {
        version == Self.version
            && type.isStructurallyValid
            && type.authority == "org.noctweave.control"
            && senderEndpointHandle.isStructurallyValid
            && issuedAt.timeIntervalSince1970.isFinite
            && !encodedPayload.isEmpty
            && encodedPayload.count <= NoctweaveWirePayloadV2.maximumControlPayloadBytes
            && signature.count == 3_309
    }

    public func verify(
        relationshipID expectedRelationshipID: UUID,
        senderEndpointHandle expectedSender: RelationshipEndpointHandle,
        eventID expectedEventID: UUID,
        signingPublicKey: Data
    ) -> Bool {
        guard isStructurallyValid,
              relationshipID == expectedRelationshipID,
              senderEndpointHandle == expectedSender,
              eventID == expectedEventID,
              let data = try? signableData() else {
            return false
        }
        return SigningKeyPair.verify(
            signature: signature,
            data: data,
            publicKeyData: signingPublicKey
        )
    }

    public func decodeKnown() throws -> KnownRelationshipControlV2? {
        guard isStructurallyValid else { throw WirePayloadV2Error.invalidKnownControl }
        guard let knownKind else { return nil }
        do {
            switch knownKind {
            case .sessionReset:
                return .sessionReset(
                    try decodeCanonical(SessionReset.self, from: encodedPayload)
                )
            case .resendRequest:
                return .resendRequest(
                    try decodeCanonical(ResendRequest.self, from: encodedPayload)
                )
            case .continuityOffer:
                let value = try decodeCanonical(
                    RelationshipContinuityOfferV2.self,
                    from: encodedPayload
                )
                guard value.relationshipID == relationshipID,
                      value.isStructurallyValid else {
                    throw WirePayloadV2Error.invalidKnownControl
                }
                return .continuityOffer(value)
            case .routeSetUpdate:
                let value = try decodeCanonical(
                    RelationshipRouteSetUpdateV2.self,
                    from: encodedPayload
                )
                guard value.relationshipID == relationshipID,
                      value.isStructurallyValid else {
                    throw WirePayloadV2Error.invalidKnownControl
                }
                return .routeSetUpdate(value)
            case .routeProbe:
                let value = try decodeCanonical(
                    RelationshipRouteProbeV2.self,
                    from: encodedPayload
                )
                guard value.relationshipID == relationshipID,
                      value.isStructurallyValid else {
                    throw WirePayloadV2Error.invalidKnownControl
                }
                return .routeProbe(value)
            case .endpointPrekeyUpdate:
                let value = try decodeCanonical(
                    RelationshipEndpointPrekeyUpdateV2.self,
                    from: encodedPayload
                )
                guard value.relationshipID == relationshipID,
                      value.isStructurallyValid else {
                    throw WirePayloadV2Error.invalidKnownControl
                }
                return .endpointPrekeyUpdate(value)
            }
        } catch {
            throw WirePayloadV2Error.invalidKnownControl
        }
    }

    fileprivate func signableData() throws -> Data {
        try NoctweaveCoder.encode(
            RelationshipControlSignaturePayloadV2(
                version: version,
                type: type,
                relationshipID: relationshipID,
                eventID: eventID,
                senderEndpointHandle: senderEndpointHandle,
                issuedAt: issuedAt,
                nonce: nonce,
                encodedPayload: encodedPayload
            ),
            sortedKeys: true
        )
    }
}

private struct RelationshipControlSignaturePayloadV2: Codable {
    let version: Int
    let type: ContentTypeId
    let relationshipID: UUID
    let eventID: UUID
    let senderEndpointHandle: RelationshipEndpointHandle
    let issuedAt: Date
    let nonce: UUID
    let encodedPayload: Data
}

public struct UnsupportedApplicationContentV2: Codable, Equatable {
    public let eventId: UUID
    public let type: ContentTypeId
    public let fallbackText: String
    public let disposition: ContentDisposition
}

public enum ApplicationContentProjectionV2: Equatable {
    case text(String)
    case attachment(AttachmentDescriptor)
    case reaction(ReactionContentV1, targetEventId: UUID)
    case retraction(RetractionContentV1, targetEventId: UUID)
    case deliveryReceipt(EventReceiptContentV1)
    case readReceipt(EventReceiptContentV1)
    case unsupported(UnsupportedApplicationContentV2)

    public var body: MessageBody? {
        switch self {
        case .text(let text): return .text(text)
        case .attachment(let descriptor): return .attachment(descriptor)
        case .reaction(let reaction, _): return .text(reaction.fallbackText)
        case .retraction: return .text(RetractionContentV1.fallbackText)
        case .deliveryReceipt, .readReceipt: return nil
        case .unsupported(let unsupported):
            return unsupported.disposition == .visible ? .text(unsupported.fallbackText) : nil
        }
    }
}

public struct WirePayloadV2: Codable, Equatable {
    public let version: Int
    public let kind: WirePayloadKindV2
    public let application: ConversationEvent?
    public let control: AuthenticatedRelationshipControlV2?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case kind
        case application
        case control
    }

    public init(
        version: Int = NoctweaveWirePayloadV2.version,
        kind: WirePayloadKindV2,
        application: ConversationEvent?,
        control: AuthenticatedRelationshipControlV2?
    ) {
        self.version = version
        self.kind = kind
        self.application = application
        self.control = control
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: WirePayloadCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Wire-payload fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        kind = try container.decode(WirePayloadKindV2.self, forKey: .kind)
        application = try container.decodeIfPresent(ConversationEvent.self, forKey: .application)
        control = try container.decodeIfPresent(
            AuthenticatedRelationshipControlV2.self,
            forKey: .control
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .kind,
                in: container,
                debugDescription: "Wire payload is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Wire payload is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(kind, forKey: .kind)
        if let application {
            try container.encode(application, forKey: .application)
        } else {
            try container.encodeNil(forKey: .application)
        }
        if let control {
            try container.encode(control, forKey: .control)
        } else {
            try container.encodeNil(forKey: .control)
        }
    }

    public static func application(_ event: ConversationEvent) throws -> WirePayloadV2 {
        let payload = WirePayloadV2(kind: .application, application: event, control: nil)
        guard payload.isStructurallyValid else { throw WirePayloadV2Error.invalidApplicationEvent }
        return payload
    }

    public static func control(
        _ control: AuthenticatedRelationshipControlV2
    ) throws -> WirePayloadV2 {
        let payload = WirePayloadV2(kind: .control, application: nil, control: control)
        guard payload.isStructurallyValid else { throw WirePayloadV2Error.invalidKnownControl }
        return payload
    }

    public static func projectingMessageBody(
        _ body: MessageBody,
        eventId: UUID,
        clientTransactionId: UUID,
        conversationId: String,
        authorEndpointHandle: RelationshipEndpointHandle,
        createdAt: Date
    ) throws -> WirePayloadV2 {
        let content: EncodedContent
        switch body {
        case .text(let text):
            guard let encoded = EncodedContent.text(text) else {
                throw WirePayloadV2Error.invalidApplicationEvent
            }
            content = encoded
        case .attachment(let descriptor):
            guard descriptor.isStructurallyValid() else {
                throw WirePayloadV2Error.invalidKnownApplicationContent
            }
            content = EncodedContent(
                type: .attachment,
                payload: try NoctweaveCoder.encode(descriptor, sortedKeys: true),
                fallbackText: Self.attachmentFallbackText(for: descriptor),
                disposition: .visible
            )
        }
        return try .application(
            ConversationEvent(
                id: eventId,
                clientTransactionId: clientTransactionId,
                conversationId: conversationId,
                authorEndpointHandle: authorEndpointHandle,
                createdAt: createdAt,
                kind: .application,
                content: content
            )
        )
    }

    public var isStructurallyValid: Bool {
        guard version == NoctweaveWirePayloadV2.version else { return false }
        switch kind {
        case .application:
            return control == nil
                && application?.isStructurallyValid == true
                && application?.kind != .control
        case .control:
            return application == nil && control?.isStructurallyValid == true
        }
    }

    public func validateDirectV4(
        eventId: UUID,
        senderEndpointHandle: RelationshipEndpointHandle,
        conversationId: String,
        sentAt: Date,
        signingPublicKey: Data? = nil
    ) throws {
        guard isStructurallyValid,
              senderEndpointHandle.isStructurallyValid,
              let relationshipID = UUID(uuidString: conversationId) else {
            throw WirePayloadV2Error.invalidPayload
        }
        switch kind {
        case .application:
            guard let application,
                  application.id == eventId,
                  application.conversationId == conversationId,
                  application.authorEndpointHandle == senderEndpointHandle,
                  floor(application.createdAt.timeIntervalSince1970)
                    == floor(sentAt.timeIntervalSince1970) else {
                throw WirePayloadV2Error.invalidApplicationEvent
            }
        case .control:
            guard let control,
                  floor(control.issuedAt.timeIntervalSince1970)
                    == floor(sentAt.timeIntervalSince1970),
                  let signingPublicKey,
                  control.verify(
                    relationshipID: relationshipID,
                    senderEndpointHandle: senderEndpointHandle,
                    eventID: eventId,
                    signingPublicKey: signingPublicKey
                  ) else {
                throw WirePayloadV2Error.invalidKnownControl
            }
        }
    }

    public func applicationProjection() throws -> ApplicationContentProjectionV2 {
        guard kind == .application,
              let event = application,
              event.isStructurallyValid else {
            throw WirePayloadV2Error.invalidApplicationEvent
        }
        if event.kind == .receipt { return try Self.receiptProjection(event) }
        guard event.kind == .application else {
            throw WirePayloadV2Error.invalidApplicationEvent
        }
        if event.content.type == .text {
            guard Self.isTextOrAttachmentRelation(event.relation),
                  event.content.parameters.isEmpty,
                  event.content.disposition == .visible,
                  let text = String(data: event.content.payload, encoding: .utf8),
                  EncodedContent.text(text) != nil,
                  event.content.fallbackText == text else {
                throw WirePayloadV2Error.invalidKnownApplicationContent
            }
            return .text(text)
        }
        if event.content.type == .attachment {
            guard Self.isTextOrAttachmentRelation(event.relation),
                  event.content.parameters.isEmpty,
                  event.content.disposition == .visible,
                  let descriptor = try? decodeCanonical(
                    AttachmentDescriptor.self,
                    from: event.content.payload
                  ), descriptor.isStructurallyValid(),
                  event.content.fallbackText == Self.attachmentFallbackText(for: descriptor) else {
                throw WirePayloadV2Error.invalidKnownApplicationContent
            }
            return .attachment(descriptor)
        }
        if event.content.type == .reaction {
            guard event.content.parameters.isEmpty,
                  event.content.disposition == .visible,
                  event.relation?.kind == .reaction,
                  let target = event.relation?.targetEventId,
                  let reaction = try? decodeCanonical(
                    ReactionContentV1.self,
                    from: event.content.payload
                  ), reaction.isStructurallyValid,
                  event.content.fallbackText == reaction.fallbackText else {
                throw WirePayloadV2Error.invalidKnownApplicationContent
            }
            return .reaction(reaction, targetEventId: target)
        }
        if event.content.type == .retraction {
            guard event.content.parameters.isEmpty,
                  event.content.disposition == .visible,
                  event.relation?.kind == .retraction,
                  let target = event.relation?.targetEventId,
                  let retraction = try? decodeCanonical(
                    RetractionContentV1.self,
                    from: event.content.payload
                  ), retraction.isStructurallyValid,
                  event.content.fallbackText == RetractionContentV1.fallbackText else {
                throw WirePayloadV2Error.invalidKnownApplicationContent
            }
            return .retraction(retraction, targetEventId: target)
        }
        guard event.relation?.kind != .reaction,
              event.relation?.kind != .retraction else {
            throw WirePayloadV2Error.invalidApplicationEvent
        }
        return .unsupported(
            UnsupportedApplicationContentV2(
                eventId: event.id,
                type: event.content.type,
                fallbackText: event.content.fallbackText
                    ?? "\(NoctweaveWirePayloadV2.unsupportedFallbackPrefix) (\(event.content.type.canonicalName))",
                disposition: event.content.disposition
            )
        )
    }

    public func controlDisposition(
        conversationId: String,
        eventId: UUID,
        senderEndpointHandle: RelationshipEndpointHandle,
        receivedAt: Date,
        signingPublicKey: Data
    ) throws -> DirectV4PayloadDispositionV2 {
        guard kind == .control,
              let control else {
            throw WirePayloadV2Error.invalidKnownControl
        }
        try validateDirectV4(
            eventId: eventId,
            senderEndpointHandle: senderEndpointHandle,
            conversationId: conversationId,
            sentAt: receivedAt,
            signingPublicKey: signingPublicKey
        )
        let auditEvent = ConversationEvent(
            id: eventId,
            clientTransactionId: control.nonce,
            conversationId: conversationId,
            authorEndpointHandle: senderEndpointHandle,
            createdAt: receivedAt,
            kind: .control,
            content: EncodedContent(
                type: control.type,
                parameters: ["wirePayloadVersion": String(version)],
                payload: control.encodedPayload,
                fallbackText: nil,
                disposition: .silent
            )
        )
        guard auditEvent.isStructurallyValid else {
            throw WirePayloadV2Error.invalidKnownControl
        }
        if let known = try control.decodeKnown() {
            return .control(known, auditEvent)
        }
        return .quarantinedControl(
            QuarantinedControlEvent(
                event: auditEvent,
                receivedAt: receivedAt,
                reason: "Unsupported authenticated relationship control: \(control.type.canonicalName)"
            )
        )
    }

    private static func attachmentFallbackText(for descriptor: AttachmentDescriptor) -> String {
        let mimeType = descriptor.mimeType.lowercased()
        if mimeType.hasPrefix("audio/") { return "Voice message" }
        if mimeType.hasPrefix("image/") { return "Image" }
        return "Attachment"
    }

    private static func isTextOrAttachmentRelation(_ relation: EventRelation?) -> Bool {
        guard let relation else { return true }
        switch relation.kind {
        case .reply, .replacement, .reference: return true
        case .reaction, .retraction: return false
        }
    }

    private static func receiptProjection(
        _ event: ConversationEvent
    ) throws -> ApplicationContentProjectionV2 {
        guard event.relation == nil,
              event.content.parameters.isEmpty,
              event.content.disposition == .silent,
              event.content.fallbackText == nil,
              let receipt = try? decodeCanonical(
                EventReceiptContentV1.self,
                from: event.content.payload
              ), receipt.targetEventId != event.id else {
            throw WirePayloadV2Error.invalidKnownApplicationContent
        }
        switch event.content.type {
        case .deliveryReceipt: return .deliveryReceipt(receipt)
        case .readReceipt: return .readReceipt(receipt)
        default: throw WirePayloadV2Error.invalidApplicationEvent
        }
    }
}

public enum DirectV4PayloadDispositionV2: Equatable {
    case application(ConversationEvent, ApplicationContentProjectionV2)
    case control(KnownRelationshipControlV2, ConversationEvent)
    case quarantinedControl(QuarantinedControlEvent)

    public var body: MessageBody? {
        guard case .application(_, let projection) = self else { return nil }
        return projection.body
    }
}

public struct DirectV4DecryptionResultV2 {
    public let disposition: DirectV4PayloadDispositionV2
    public let messageKey: SymmetricKey
}

private func decodeCanonical<Value: Codable>(
    _ type: Value.Type,
    from payload: Data
) throws -> Value {
    let value = try NoctweaveCoder.decode(type, from: payload)
    guard try NoctweaveCoder.encode(value, sortedKeys: true) == payload else {
        throw WirePayloadV2Error.invalidKnownApplicationContent
    }
    return value
}

private struct WirePayloadCodingKey: CodingKey {
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
