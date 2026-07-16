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
    case legacyFormatRequired
    case directV4FormatRequired
}

public enum WirePayloadKindV2: String, Codable, Equatable {
    case application
    case control
}

public enum AuthenticatedControlKindV2: String, Codable, Equatable, CaseIterable {
    case identityRotation
    case identityReset
    case sessionReset
    case resendRequest

    public var contentType: ContentTypeId {
        let name: String
        switch self {
        case .identityRotation: name = "identity-rotation"
        case .identityReset: name = "identity-reset"
        case .sessionReset: name = "session-reset"
        case .resendRequest: name = "resend-request"
        }
        return ContentTypeId(
            authority: "org.noctweave.control",
            name: name,
            major: 1,
            minor: 0
        )
    }

    public init?(contentType: ContentTypeId) {
        guard contentType.authority == "org.noctweave.control",
              contentType.major == 1,
              contentType.minor == 0 else {
            return nil
        }
        switch contentType.name {
        case "identity-rotation": self = .identityRotation
        case "identity-reset": self = .identityReset
        case "session-reset": self = .sessionReset
        case "resend-request": self = .resendRequest
        default: return nil
        }
    }
}

/// Security-sensitive direct-v4 controls use a closed, separately authenticated family.
/// The type remains an open content identifier on decode so future controls can be quarantined
/// without being interpreted by an older client.
public struct AuthenticatedControlPayloadV2: Codable, Equatable {
    public let type: ContentTypeId
    public let encodedPayload: Data

    public init(type: ContentTypeId, encodedPayload: Data) {
        self.type = type
        self.encodedPayload = encodedPayload
    }

    public var knownKind: AuthenticatedControlKindV2? {
        AuthenticatedControlKindV2(contentType: type)
    }

    public var isStructurallyValid: Bool {
        type.isStructurallyValid
            && type.authority == "org.noctweave.control"
            && !encodedPayload.isEmpty
            && encodedPayload.count <= NoctweaveWirePayloadV2.maximumControlPayloadBytes
    }

    public static func encode(_ body: MessageBody) throws -> AuthenticatedControlPayloadV2 {
        let kind: AuthenticatedControlKindV2
        let encoded: Data
        switch body {
        case .identityRotation(let value):
            kind = .identityRotation
            encoded = try NoctweaveCoder.encode(value, sortedKeys: true)
        case .identityReset(let value):
            kind = .identityReset
            encoded = try NoctweaveCoder.encode(value, sortedKeys: true)
        case .sessionReset(let value):
            kind = .sessionReset
            encoded = try NoctweaveCoder.encode(value, sortedKeys: true)
        case .resendRequest(let value):
            kind = .resendRequest
            encoded = try NoctweaveCoder.encode(value, sortedKeys: true)
        case .text, .attachment:
            throw WirePayloadV2Error.invalidKnownControl
        }
        let result = AuthenticatedControlPayloadV2(type: kind.contentType, encodedPayload: encoded)
        guard result.isStructurallyValid else { throw WirePayloadV2Error.invalidKnownControl }
        return result
    }

    /// Returns nil for a structurally valid but unknown control. Callers must quarantine it.
    public func decodeKnownControl() throws -> KnownAuthenticatedControlV2? {
        guard isStructurallyValid else { throw WirePayloadV2Error.invalidKnownControl }
        guard let kind = knownKind else { return nil }
        do {
            switch kind {
            case .identityRotation:
                return .identityRotation(
                    try NoctweaveCoder.decode(IdentityRotation.self, from: encodedPayload)
                )
            case .identityReset:
                return .identityReset(
                    try NoctweaveCoder.decode(IdentityReset.self, from: encodedPayload)
                )
            case .sessionReset:
                return .sessionReset(
                    try NoctweaveCoder.decode(SessionReset.self, from: encodedPayload)
                )
            case .resendRequest:
                return .resendRequest(
                    try NoctweaveCoder.decode(ResendRequest.self, from: encodedPayload)
                )
            }
        } catch {
            throw WirePayloadV2Error.invalidKnownControl
        }
    }
}

public enum KnownAuthenticatedControlV2: Equatable {
    case identityRotation(IdentityRotation)
    case identityReset(IdentityReset)
    case sessionReset(SessionReset)
    case resendRequest(ResendRequest)

    public var body: MessageBody {
        switch self {
        case .identityRotation(let value): return .identityRotation(value)
        case .identityReset(let value): return .identityReset(value)
        case .sessionReset(let value): return .sessionReset(value)
        case .resendRequest(let value): return .resendRequest(value)
        }
    }
}

public struct UnsupportedApplicationContentV2: Codable, Equatable {
    public let eventId: UUID
    public let type: ContentTypeId
    public let fallbackText: String
    public let disposition: ContentDisposition

    public init(
        eventId: UUID,
        type: ContentTypeId,
        fallbackText: String,
        disposition: ContentDisposition
    ) {
        self.eventId = eventId
        self.type = type
        self.fallbackText = fallbackText
        self.disposition = disposition
    }
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

    public var isUnsupported: Bool {
        if case .unsupported = self { return true }
        return false
    }
}

/// Direct-v4 plaintext. Application and control fields are mutually exclusive and the top-level
/// version is authenticated by AEAD and indirectly by the envelope signature over ciphertext.
public struct WirePayloadV2: Codable, Equatable {
    public let version: Int
    public let kind: WirePayloadKindV2
    public let application: ConversationEvent?
    public let control: AuthenticatedControlPayloadV2?

    public init(
        version: Int = NoctweaveWirePayloadV2.version,
        kind: WirePayloadKindV2,
        application: ConversationEvent?,
        control: AuthenticatedControlPayloadV2?
    ) {
        self.version = version
        self.kind = kind
        self.application = application
        self.control = control
    }

    public static func application(_ event: ConversationEvent) throws -> WirePayloadV2 {
        let payload = WirePayloadV2(kind: .application, application: event, control: nil)
        guard payload.isStructurallyValid else { throw WirePayloadV2Error.invalidApplicationEvent }
        return payload
    }

    public static func control(_ control: AuthenticatedControlPayloadV2) throws -> WirePayloadV2 {
        let payload = WirePayloadV2(kind: .control, application: nil, control: control)
        guard payload.isStructurallyValid else { throw WirePayloadV2Error.invalidKnownControl }
        return payload
    }

    public static func control(_ body: MessageBody) throws -> WirePayloadV2 {
        try control(AuthenticatedControlPayloadV2.encode(body))
    }

    public static func projectingMessageBody(
        _ body: MessageBody,
        eventId: UUID,
        clientTransactionId: UUID,
        conversationId: String,
        authorInstallationHandle: RelationshipInstallationHandle,
        createdAt: Date
    ) throws -> WirePayloadV2 {
        switch body {
        case .text(let text):
            guard let content = EncodedContent.text(text) else {
                throw WirePayloadV2Error.invalidApplicationEvent
            }
            return try .application(
                ConversationEvent(
                    id: eventId,
                    clientTransactionId: clientTransactionId,
                    conversationId: conversationId,
                    authorInstallationHandle: authorInstallationHandle,
                    createdAt: createdAt,
                    kind: .application,
                    content: content
                )
            )
        case .attachment(let descriptor):
            guard descriptor.isStructurallyValid() else {
                throw WirePayloadV2Error.invalidKnownApplicationContent
            }
            let content = EncodedContent(
                type: .attachment,
                payload: try NoctweaveCoder.encode(descriptor, sortedKeys: true),
                fallbackText: Self.attachmentFallbackText(for: descriptor),
                disposition: .visible
            )
            return try .application(
                ConversationEvent(
                    id: eventId,
                    clientTransactionId: clientTransactionId,
                    conversationId: conversationId,
                    authorInstallationHandle: authorInstallationHandle,
                    createdAt: createdAt,
                    kind: .application,
                    content: content
                )
            )
        case .identityRotation, .identityReset, .sessionReset, .resendRequest:
            return try .control(body)
        }
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
        context: DirectMessageAuthenticatedContextV4,
        conversationId: String,
        sentAt: Date
    ) throws {
        guard isStructurallyValid,
              context.isStructurallyValid,
              context.payloadFormat == NoctweaveWirePayloadV2.directV4Format else {
            throw WirePayloadV2Error.invalidPayload
        }
        if let application {
            guard application.id == context.eventId,
                  application.conversationId == conversationId,
                  application.authorInstallationHandle == context.senderInstallationHandle,
                  floor(application.createdAt.timeIntervalSince1970)
                    == floor(sentAt.timeIntervalSince1970) else {
                throw WirePayloadV2Error.invalidApplicationEvent
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
            guard event.kind == .application,
                  Self.isTextOrAttachmentRelation(event.relation),
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
            guard event.kind == .application,
                  Self.isTextOrAttachmentRelation(event.relation),
                  event.content.parameters.isEmpty,
                  event.content.disposition == .visible,
                  let descriptor = try? Self.decodeCanonical(
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
                  let targetEventId = event.relation?.targetEventId,
                  let reaction = try? Self.decodeCanonical(
                    ReactionContentV1.self,
                    from: event.content.payload
                  ), reaction.isStructurallyValid,
                  event.content.fallbackText == reaction.fallbackText else {
                throw WirePayloadV2Error.invalidKnownApplicationContent
            }
            return .reaction(reaction, targetEventId: targetEventId)
        }
        if event.content.type == .retraction {
            guard event.content.parameters.isEmpty,
                  event.content.disposition == .visible,
                  event.relation?.kind == .retraction,
                  let targetEventId = event.relation?.targetEventId,
                  let retraction = try? Self.decodeCanonical(
                    RetractionContentV1.self,
                    from: event.content.payload
                  ), retraction.isStructurallyValid,
                  event.content.fallbackText == RetractionContentV1.fallbackText else {
                throw WirePayloadV2Error.invalidKnownApplicationContent
            }
            return .retraction(retraction, targetEventId: targetEventId)
        }
        guard event.relation?.kind != .reaction,
              event.relation?.kind != .retraction else {
            throw WirePayloadV2Error.invalidApplicationEvent
        }
        let fallback = event.content.fallbackText
            ?? "\(NoctweaveWirePayloadV2.unsupportedFallbackPrefix) (\(event.content.type.canonicalName))"
        return .unsupported(
            UnsupportedApplicationContentV2(
                eventId: event.id,
                type: event.content.type,
                fallbackText: fallback,
                disposition: event.content.disposition
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

    private static func decodeCanonical<Value: Codable>(
        _ type: Value.Type,
        from payload: Data
    ) throws -> Value {
        let value = try NoctweaveCoder.decode(type, from: payload)
        guard try NoctweaveCoder.encode(value, sortedKeys: true) == payload else {
            throw WirePayloadV2Error.invalidKnownApplicationContent
        }
        return value
    }

    public func controlDisposition(
        conversationId: String,
        context: DirectMessageAuthenticatedContextV4,
        receivedAt: Date
    ) throws -> DirectV4PayloadDispositionV2 {
        guard kind == .control,
              let control,
              control.isStructurallyValid else {
            throw WirePayloadV2Error.invalidKnownControl
        }
        let auditContent = EncodedContent(
            type: control.type,
            parameters: ["wirePayloadVersion": String(version)],
            payload: control.encodedPayload,
            fallbackText: nil,
            disposition: .silent
        )
        let auditEvent = ConversationEvent(
            id: context.eventId,
            clientTransactionId: context.eventId,
            conversationId: conversationId,
            authorInstallationHandle: context.senderInstallationHandle,
            createdAt: receivedAt,
            kind: .control,
            content: auditContent
        )
        guard auditEvent.isStructurallyValid else {
            throw WirePayloadV2Error.invalidKnownControl
        }
        if let known = try control.decodeKnownControl() {
            return .control(known, auditEvent)
        }
        return .quarantinedControl(
            QuarantinedControlEvent(
                event: auditEvent,
                receivedAt: receivedAt,
                reason: "Unsupported authenticated control: \(control.type.canonicalName)"
            )
        )
    }
}

public enum DirectV4PayloadDispositionV2: Equatable {
    case application(ConversationEvent, ApplicationContentProjectionV2)
    case control(KnownAuthenticatedControlV2, ConversationEvent)
    case quarantinedControl(QuarantinedControlEvent)

    public var body: MessageBody? {
        switch self {
        case .application(_, let projection): return projection.body
        case .control(let control, _): return control.body
        case .quarantinedControl: return nil
        }
    }
}

public struct DirectV4DecryptionResultV2 {
    public let disposition: DirectV4PayloadDispositionV2
    public let messageKey: SymmetricKey

    public init(disposition: DirectV4PayloadDispositionV2, messageKey: SymmetricKey) {
        self.disposition = disposition
        self.messageKey = messageKey
    }
}
