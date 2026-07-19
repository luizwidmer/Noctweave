import CryptoKit
import Foundation

public enum RendezvousRelayAdapterV2Error: Error, Equatable {
    case invalidOffer
    case invalidDirection
    case invalidPayload
    case payloadTooLarge
    case decryptionFailed
}

/// Relay lanes are directional. The names describe the sender so the transport
/// never needs a persona, contact, account, or endpoint identifier.
public enum RendezvousRelayDirectionV2: String, Codable, Equatable, Hashable {
    case offererToResponder
    case responderToOfferer

    public var senderRole: RendezvousRoleV2 {
        switch self {
        case .offererToResponder: return .offerer
        case .responderToOfferer: return .responder
        }
    }

    public static func outbound(for role: RendezvousRoleV2) -> RendezvousRelayDirectionV2 {
        role == .offerer ? .offererToResponder : .responderToOfferer
    }

    public static func inbound(for role: RendezvousRoleV2) -> RendezvousRelayDirectionV2 {
        role == .offerer ? .responderToOfferer : .offererToResponder
    }
}

public struct RendezvousRelayLaneMaterialV2: Equatable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let direction: RendezvousRelayDirectionV2
    public let registration: RendezvousRelayLaneRegistrationV2

    public var description: String { "RendezvousRelayLaneMaterialV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

public enum RendezvousRelayDecodedPayloadV2: Equatable {
    case open(RendezvousOpenV2)
    case sessionFrame(RendezvousFrameV2)
}

/// Deterministically expands the invitation's random transport capability into
/// one opaque relay route, two directional lanes, independent bearer
/// capabilities, and transport-encryption keys. Both invitation holders derive
/// the same material; the relay learns only unrelated random-looking values.
public struct RendezvousRelayAdapterV2: Equatable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private static let transportOverhead = 28 // AES-GCM nonce + tag
    private static let framingBytes = 9 // magic + kind + UInt32 payload length
    private static let magic = Data([0x4e, 0x57, 0x52, 0x32]) // NWR2

    public let offer: RendezvousOfferV2
    public let routeCapability: RendezvousRelayRouteCapabilityV2
    public let offererToResponder: RendezvousRelayLaneMaterialV2
    public let responderToOfferer: RendezvousRelayLaneMaterialV2

    private let offererToResponderKey: Data
    private let responderToOffererKey: Data

    public init(offer: RendezvousOfferV2) throws {
        guard offer.isStructurallyValid,
              offer.purpose == .contactPairing else {
            throw RendezvousRelayAdapterV2Error.invalidOffer
        }
        self.offer = offer
        let seed = offer.transportCapability.opaqueValue
        let transcript = offer.transcriptDigest
        func material(_ label: String) -> Data {
            Self.derive(label: label, seed: seed, transcript: transcript)
        }

        routeCapability = RendezvousRelayRouteCapabilityV2(
            rawValue: material("route-capability")
        )
        offererToResponder = RendezvousRelayLaneMaterialV2(
            direction: .offererToResponder,
            registration: RendezvousRelayLaneRegistrationV2(
                laneId: RendezvousRelayLaneIDV2(
                    rawValue: material("offerer-to-responder/lane")
                ),
                publishCapability: RendezvousRelayPublishCapabilityV2(
                    rawValue: material("offerer-to-responder/publish")
                ),
                readCapability: RendezvousRelayReadCapabilityV2(
                    rawValue: material("offerer-to-responder/read")
                ),
                deleteCapability: RendezvousRelayDeleteCapabilityV2(
                    rawValue: material("offerer-to-responder/delete")
                )
            )
        )
        responderToOfferer = RendezvousRelayLaneMaterialV2(
            direction: .responderToOfferer,
            registration: RendezvousRelayLaneRegistrationV2(
                laneId: RendezvousRelayLaneIDV2(
                    rawValue: material("responder-to-offerer/lane")
                ),
                publishCapability: RendezvousRelayPublishCapabilityV2(
                    rawValue: material("responder-to-offerer/publish")
                ),
                readCapability: RendezvousRelayReadCapabilityV2(
                    rawValue: material("responder-to-offerer/read")
                ),
                deleteCapability: RendezvousRelayDeleteCapabilityV2(
                    rawValue: material("responder-to-offerer/delete")
                )
            )
        )
        offererToResponderKey = material("offerer-to-responder/transport-key")
        responderToOffererKey = material("responder-to-offerer/transport-key")

        guard isStructurallyValid else {
            throw RendezvousRelayAdapterV2Error.invalidOffer
        }
    }

    public var isStructurallyValid: Bool {
        let registration = registrationRequest
        let allAuthorities = [routeCapability.rawValue]
            + registration.lanes.flatMap {
                [
                    $0.publishCapability.rawValue,
                    $0.readCapability.rawValue,
                    $0.deleteCapability.rawValue
                ]
            }
        return offer.isStructurallyValid
            && routeCapability.isStructurallyValid
            && offererToResponder.registration.isStructurallyValid
            && responderToOfferer.registration.isStructurallyValid
            && offererToResponderKey.count == 32
            && responderToOffererKey.count == 32
            && Set(allAuthorities).count == allAuthorities.count
    }

    public var registrationRequest: RegisterRendezvousTransportV2Request {
        RegisterRendezvousTransportV2Request(
            routeCapability: routeCapability,
            expiresAt: offer.expiresAt,
            lanes: [offererToResponder.registration, responderToOfferer.registration]
        )
    }

    public func lane(
        for direction: RendezvousRelayDirectionV2
    ) -> RendezvousRelayLaneMaterialV2 {
        direction == .offererToResponder ? offererToResponder : responderToOfferer
    }

    public func syncRequest(
        receivingAs role: RendezvousRoleV2,
        afterSequence: UInt64 = 0,
        maxCount: Int? = nil
    ) -> SyncRendezvousTransportV2Request {
        let inbound = lane(for: .inbound(for: role)).registration
        return SyncRendezvousTransportV2Request(
            routeCapability: routeCapability,
            laneId: inbound.laneId,
            readCapability: inbound.readCapability,
            afterSequence: afterSequence,
            maxCount: maxCount
        )
    }

    public func deletionRequests() -> [DeleteRendezvousTransportV2Request] {
        [offererToResponder, responderToOfferer].map { lane in
            DeleteRendezvousTransportV2Request(
                routeCapability: routeCapability,
                laneId: lane.registration.laneId,
                deleteCapability: lane.registration.deleteCapability
            )
        }
    }

    public func sealOpen(
        _ open: RendezvousOpenV2,
        frameID: RendezvousRelayFrameIDV2 = .generate()
    ) throws -> AppendRendezvousTransportV2Request {
        guard open.isStructurallyValid(for: offer) else {
            throw RendezvousRelayAdapterV2Error.invalidPayload
        }
        return try seal(
            encodedPayload: NoctweaveCoder.encode(open, sortedKeys: true),
            payloadKind: 1,
            direction: .responderToOfferer,
            sequence: 1,
            frameID: frameID
        )
    }

    public func sealSessionFrame(
        _ frame: RendezvousFrameV2,
        transportSequence: UInt64,
        frameID: RendezvousRelayFrameIDV2 = .generate()
    ) throws -> AppendRendezvousTransportV2Request {
        guard frame.isStructurallyValid else {
            throw RendezvousRelayAdapterV2Error.invalidPayload
        }
        let direction = RendezvousRelayDirectionV2.outbound(for: frame.senderRole)
        return try seal(
            encodedPayload: NoctweaveCoder.encode(frame, sortedKeys: true),
            payloadKind: 2,
            direction: direction,
            sequence: transportSequence,
            frameID: frameID
        )
    }

    public func open(
        _ frame: RendezvousRelayCiphertextFrameV2,
        direction: RendezvousRelayDirectionV2
    ) throws -> RendezvousRelayDecodedPayloadV2 {
        guard frame.isStructurallyValid else {
            throw RendezvousRelayAdapterV2Error.invalidPayload
        }
        let key = SymmetricKey(data: transportKey(for: direction))
        let aad = authenticatedData(
            direction: direction,
            frameID: frame.frameId,
            sequence: frame.sequence
        )
        let plaintext: Data
        do {
            let box = try AES.GCM.SealedBox(combined: frame.ciphertext)
            plaintext = try AES.GCM.open(box, using: key, authenticating: aad)
        } catch {
            throw RendezvousRelayAdapterV2Error.decryptionFailed
        }
        guard plaintext.count >= Self.framingBytes,
              plaintext.prefix(Self.magic.count) == Self.magic else {
            throw RendezvousRelayAdapterV2Error.invalidPayload
        }
        let kind = plaintext[Self.magic.count]
        let lengthOffset = Self.magic.count + 1
        let payloadLength = Int(Self.decodeUInt32(
            plaintext[lengthOffset..<(lengthOffset + 4)]
        ))
        let payloadStart = lengthOffset + 4
        guard payloadLength > 0,
              payloadStart + payloadLength <= plaintext.count else {
            throw RendezvousRelayAdapterV2Error.invalidPayload
        }
        let payload = Data(plaintext[payloadStart..<(payloadStart + payloadLength)])
        do {
            switch kind {
            case 1:
                guard direction == .responderToOfferer,
                      frame.sequence == 1 else {
                    throw RendezvousRelayAdapterV2Error.invalidDirection
                }
                let open = try NoctweaveCoder.decode(RendezvousOpenV2.self, from: payload)
                guard try open.isStructurallyValidThrowing(for: offer) else {
                    throw RendezvousRelayAdapterV2Error.invalidPayload
                }
                return .open(open)
            case 2:
                let sessionFrame = try NoctweaveCoder.decode(
                    RendezvousFrameV2.self,
                    from: payload
                )
                guard sessionFrame.senderRole == direction.senderRole else {
                    throw RendezvousRelayAdapterV2Error.invalidDirection
                }
                return .sessionFrame(sessionFrame)
            default:
                throw RendezvousRelayAdapterV2Error.invalidPayload
            }
        } catch let error as RendezvousRelayAdapterV2Error {
            throw error
        } catch let error as CryptoError {
            throw error
        } catch {
            throw RendezvousRelayAdapterV2Error.invalidPayload
        }
    }

    public var description: String { "RendezvousRelayAdapterV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }

    private func seal(
        encodedPayload: Data,
        payloadKind: UInt8,
        direction: RendezvousRelayDirectionV2,
        sequence: UInt64,
        frameID: RendezvousRelayFrameIDV2
    ) throws -> AppendRendezvousTransportV2Request {
        guard sequence > 0,
              sequence <= RendezvousRelayTransportV2.maximumFramesPerLane,
              frameID.isStructurallyValid else {
            throw RendezvousRelayAdapterV2Error.invalidPayload
        }
        let minimumPlaintextBytes = Self.framingBytes + encodedPayload.count
        guard let bucket = RendezvousRelayTransportV2.allowedCiphertextByteCounts.first(where: {
            $0 >= minimumPlaintextBytes + Self.transportOverhead
        }) else {
            throw RendezvousRelayAdapterV2Error.payloadTooLarge
        }
        var plaintext = Self.magic
        plaintext.append(payloadKind)
        plaintext.append(Self.encodeUInt32(UInt32(encodedPayload.count)))
        plaintext.append(encodedPayload)
        var random = SystemRandomNumberGenerator()
        while plaintext.count < bucket - Self.transportOverhead {
            plaintext.append(UInt8.random(in: UInt8.min...UInt8.max, using: &random))
        }
        let sealed = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: transportKey(for: direction)),
            nonce: AES.GCM.Nonce(),
            authenticating: authenticatedData(
                direction: direction,
                frameID: frameID,
                sequence: sequence
            )
        )
        guard let ciphertext = sealed.combined,
              ciphertext.count == bucket else {
            throw RendezvousRelayAdapterV2Error.invalidPayload
        }
        let relayFrame = RendezvousRelayCiphertextFrameV2(
            frameId: frameID,
            sequence: sequence,
            ciphertext: ciphertext
        )
        let outbound = lane(for: direction).registration
        let request = AppendRendezvousTransportV2Request(
            routeCapability: routeCapability,
            laneId: outbound.laneId,
            publishCapability: outbound.publishCapability,
            frame: relayFrame
        )
        guard request.isStructurallyValid else {
            throw RendezvousRelayAdapterV2Error.invalidPayload
        }
        return request
    }

    private func transportKey(for direction: RendezvousRelayDirectionV2) -> Data {
        direction == .offererToResponder
            ? offererToResponderKey
            : responderToOffererKey
    }

    private func authenticatedData(
        direction: RendezvousRelayDirectionV2,
        frameID: RendezvousRelayFrameIDV2,
        sequence: UInt64
    ) -> Data {
        var data = Data("org.noctweave.rendezvous-relay-frame/v2".utf8)
        data.append(0)
        data.append(offer.transcriptDigest)
        data.append(0)
        data.append(Data(direction.rawValue.utf8))
        data.append(0)
        data.append(frameID.rawValue)
        var bigEndian = sequence.bigEndian
        withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
        return data
    }

    private static func derive(label: String, seed: Data, transcript: Data) -> Data {
        var input = Data("org.noctweave.rendezvous-relay-derivation/v2".utf8)
        input.append(0)
        input.append(Data(label.utf8))
        input.append(0)
        input.append(transcript)
        return Data(HMAC<SHA256>.authenticationCode(
            for: input,
            using: SymmetricKey(data: seed)
        ))
    }

    private static func encodeUInt32(_ value: UInt32) -> Data {
        var bigEndian = value.bigEndian
        return withUnsafeBytes(of: &bigEndian) { Data($0) }
    }

    private static func decodeUInt32(_ bytes: Data.SubSequence) -> UInt32 {
        bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }
}
