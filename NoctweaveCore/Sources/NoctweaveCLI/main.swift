import Foundation
import NoctweaveCore

#if os(Linux)
import Glibc
#else
import Darwin
#endif

@main
struct NoctweaveCLI {
    static func main() async {
        do {
            try await CommandRunner(arguments: Array(CommandLine.arguments.dropFirst())).run()
        } catch let error as CLIError {
            FileHandle.standardError.writeLine(error.message)
            exit(Int32(error.exitCode))
        } catch {
            FileHandle.standardError.writeLine(error.localizedDescription)
            exit(1)
        }
    }
}

private struct CommandRunner {
    private static let maximumRawRequestBytes = 512 * 1_024
    private static let maximumSensitiveInputBytes = 8 * 1_024 * 1_024
    let arguments: [String]

    func run() async throws {
        guard let command = arguments.first else {
            printHelp()
            return
        }
        let options = try ParsedOptions(Array(arguments.dropFirst()))
        switch command {
        case "help", "--help", "-h":
            printHelp()
        case "init":
            try await initialize(options)
        case "status":
            try await status(options)
        case "relationships":
            let client = try await headlessClient(options)
            try writeJSON(await client.activePersona().relationships.map(
                RelationshipStatusOutput.init
            ))
        case "prepare-participant":
            try await prepareParticipant(options)
        case "pairing-invitation":
            try await pairingInvitation(options)
        case "pair-offer":
            try await completePairingAsOfferer(options)
        case "pair-accept":
            try await completePairingAsResponder(options)
        case "send":
            try await sendText(options)
        case "sync":
            try await sync(options)
        case "maintain":
            try await maintain(options)
        case "relationship-policy":
            try await relationshipPolicy(options)
        case "continuity-policy":
            try await continuityPolicy(options)
        case "continuity-offer":
            try await continuityOffer(options)
        case "continuity-invitation":
            try await continuityInvitation(options)
        case "safety-number":
            try await safetyNumber(options)
        case "block":
            try await blockRelationship(options)
        case "mark-read":
            try await markRead(options)
        case "retry-deliveries":
            try await retryDeliveries(options)
        case "discard-delivery":
            try await discardDelivery(options)
        case "resume-rollovers":
            try await resumeRollovers(options)
        case "finalize-routes":
            try await finalizeRoutes(options)
        case "discard-rollover":
            try await discardRollover(options)
        case "burn-persona":
            try await burnPersona(options)
        case "endpoint":
            try writeJSON(try endpoint(options))
        case "health":
            try await sendRelay(.health(), options: options)
        case "info":
            try await sendRelay(.info(), options: options)
        case "raw":
            try await sendRelay(try relayRequest(options), options: options)
        default:
            throw CLIError("Unknown command: \(command). Run `NoctweaveCLI help`.")
        }
    }

    private func initialize(_ options: ParsedOptions) async throws {
        let name = try required(options, "--display-name")
        let store = try stateStore(options)
        if try await store.load() != nil {
            throw CLIError("State already exists.")
        }
        let client = try await HeadlessMessagingClient.open(
            stateStore: store,
            displayName: name
        )
        try writeJSON(PersonaStatusOutput(await client.activePersona()))
    }

    private func status(_ options: ParsedOptions) async throws {
        let client = try await headlessClient(options)
        try writeJSON(PersonaStatusOutput(await client.activePersona()))
    }

    private func prepareParticipant(_ options: ParsedOptions) async throws {
        let output = try required(options, "--out")
        let client = try await headlessClient(options)
        let pending = try await client.prepareContactParticipant(
            relay: try endpoint(options),
            relationshipPseudonym: options.value("--relationship-pseudonym")
                ?? "Noctweave peer"
        )
        let prepared = try await client.activateContactParticipant(pending)
        try writeSensitiveJSON(prepared, to: output)
        FileHandle.standardOutput.writeLine(output)
    }

    private func pairingInvitation(_ options: ParsedOptions) async throws {
        let offerOutput = try required(options, "--offer-out")
        let invitationOutput = try required(options, "--invitation-out")
        let lifetime = try options.int("--lifetime") ?? 600
        guard (30...600).contains(lifetime) else {
            throw CLIError("Pairing invitation lifetime must be between 30 and 600 seconds.")
        }
        let client = try await headlessClient(options)
        let createdAt = pairingTimestamp()
        let result = try await client.makeContactPairingInvitation(
            createdAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(TimeInterval(lifetime))
        )
        try writeSensitiveJSON(PairingOfferFile(
            pending: result.pending,
            invitation: result.invitation
        ), to: offerOutput)
        try writeSensitiveText(try result.invitation.encoded(), to: invitationOutput)
        try writeJSON(PairingInvitationOutput(
            offerFile: offerOutput,
            invitationFile: invitationOutput,
            expiresAt: result.invitation.offer.expiresAt
        ))
    }

    /// Completes one live offerer-side rendezvous exchange. The short-lived
    /// flow deliberately remains process-local and non-Codable; interruption
    /// requires a fresh invitation instead of exporting session keys.
    private func completePairingAsOfferer(_ options: ParsedOptions) async throws {
        let offerFile = try readSensitiveJSON(
            PairingOfferFile.self,
            from: try required(options, "--offer-file")
        )
        let participant = try readSensitiveJSON(
            PreparedContactParticipantV2.self,
            from: try required(options, "--participant-file")
        )
        let client = try await headlessClient(options)
        let scope = await client.mintActivePersonaScopeToken()
        let adapter = try RendezvousRelayAdapterV2(offer: offerFile.invitation.offer)
        let relay = try rendezvousRelayClient(options)
        try await requireEmptyRelaySuccess(
            relay.send(.registerRendezvousTransportV2(adapter.registrationRequest)),
            operation: "register rendezvous transport"
        )

        let inbound = try await waitForRendezvousFrames(
            adapter: adapter,
            receivingAs: .offerer,
            afterSequence: 0,
            count: 2,
            invitation: offerFile.invitation,
            relay: relay,
            options: options
        )
        guard inbound.map(\.sequence) == [1, 2],
              case .open(let openRequest) = try adapter.open(
                  inbound[0],
                  direction: .responderToOfferer
              ),
              case .sessionFrame(let acceptanceFrame) = try adapter.open(
                  inbound[1],
                  direction: .responderToOfferer
              ) else {
            throw CLIError("Rendezvous responder frames were incomplete or out of order.")
        }

        var pending = offerFile.pending
        var ledger = RendezvousRedemptionLedgerV2()
        let startedAt = pairingTimestamp()
        var started = try ContactPairingOffererFlowV2.begin(
            pendingOffer: &pending,
            invitation: offerFile.invitation,
            participant: participant,
            openRequest: openRequest,
            acceptanceFrame: acceptanceFrame,
            ledger: &ledger,
            at: startedAt
        )
        try await appendRendezvous(
            adapter.sealSessionFrame(started.offerFrame, transportSequence: 1),
            relay: relay
        )

        let confirmationFrames = try await waitForRendezvousFrames(
            adapter: adapter,
            receivingAs: .offerer,
            afterSequence: 2,
            count: 1,
            invitation: offerFile.invitation,
            relay: relay,
            options: options
        )
        guard confirmationFrames.first?.sequence == 3,
              case .sessionFrame(let responderConfirmation) = try adapter.open(
                  confirmationFrames[0],
                  direction: .responderToOfferer
              ) else {
            throw CLIError("Rendezvous confirmation was incomplete or out of order.")
        }
        let completion = try started.flow.receiveConfirmation(
            responderConfirmation,
            at: pairingTimestamp()
        )
        try await appendRendezvous(
            adapter.sealSessionFrame(completion.confirmationFrame, transportSequence: 2),
            relay: relay
        )
        try await client.addRelationship(
            completion.relationship,
            personaScope: scope
        )
        try writeJSON(PairingCompletionOutput(
            relationshipID: completion.relationship.id,
            rendezvousCleanup: "responder-or-expiry"
        ))
    }

    /// Completes one live responder-side rendezvous exchange. Both roles may
    /// register the same deterministic opaque lanes, so either command can be
    /// started first without introducing a stable rendezvous or persona ID.
    private func completePairingAsResponder(_ options: ParsedOptions) async throws {
        let invitation = try ContactPairingInvitationV2.decode(try readSensitiveText(
            from: try required(options, "--invitation-file")
        ))
        let participant = try readSensitiveJSON(
            PreparedContactParticipantV2.self,
            from: try required(options, "--participant-file")
        )
        let client = try await headlessClient(options)
        let scope = await client.mintActivePersonaScopeToken()
        let adapter = try RendezvousRelayAdapterV2(offer: invitation.offer)
        let relay = try rendezvousRelayClient(options)
        try await requireEmptyRelaySuccess(
            relay.send(.registerRendezvousTransportV2(adapter.registrationRequest)),
            operation: "register rendezvous transport"
        )

        var started = try ContactPairingResponderFlowV2.begin(
            invitation: invitation,
            participant: participant,
            at: pairingTimestamp()
        )
        try await appendRendezvous(adapter.sealOpen(started.openRequest), relay: relay)
        try await appendRendezvous(
            adapter.sealSessionFrame(started.acceptanceFrame, transportSequence: 2),
            relay: relay
        )

        let offerFrames = try await waitForRendezvousFrames(
            adapter: adapter,
            receivingAs: .responder,
            afterSequence: 0,
            count: 1,
            invitation: invitation,
            relay: relay,
            options: options
        )
        guard offerFrames.first?.sequence == 1,
              case .sessionFrame(let offerFrame) = try adapter.open(
                  offerFrames[0],
                  direction: .offererToResponder
              ) else {
            throw CLIError("Rendezvous offer was incomplete or out of order.")
        }
        let confirmation = try started.flow.receiveOffer(
            offerFrame,
            at: pairingTimestamp()
        )
        try await appendRendezvous(
            adapter.sealSessionFrame(confirmation, transportSequence: 3),
            relay: relay
        )

        let finalFrames = try await waitForRendezvousFrames(
            adapter: adapter,
            receivingAs: .responder,
            afterSequence: 1,
            count: 1,
            invitation: invitation,
            relay: relay,
            options: options
        )
        guard finalFrames.first?.sequence == 2,
              case .sessionFrame(let finalConfirmation) = try adapter.open(
                  finalFrames[0],
                  direction: .offererToResponder
              ) else {
            throw CLIError("Final rendezvous confirmation was incomplete or out of order.")
        }
        let relationship = try started.flow.receiveConfirmation(
            finalConfirmation,
            at: pairingTimestamp()
        )
        try await client.addRelationship(relationship, personaScope: scope)

        var cleanupComplete = true
        for request in adapter.deletionRequests() {
            do {
                try await requireEmptyRelaySuccess(
                    relay.send(.deleteRendezvousTransportV2(request)),
                    operation: "delete rendezvous lane"
                )
            } catch {
                cleanupComplete = false
            }
        }
        try writeJSON(PairingCompletionOutput(
            relationshipID: relationship.id,
            rendezvousCleanup: cleanupComplete ? "deleted" : "expires-automatically"
        ))
    }

    private func sendText(_ options: ParsedOptions) async throws {
        let relationshipID = try relationshipIdentifier(options)
        let text = try readPrivateMessageText(
            from: try required(options, "--text-file")
        )
        let result = try await headlessClient(options).sendText(
            text,
            relationshipID: relationshipID
        )
        try writeJSON(SendStatusOutput(relationshipID: relationshipID, result: result))
    }

    private func sync(_ options: ParsedOptions) async throws {
        let relationshipID = try relationshipIdentifier(options)
        let maximum = try options.int("--max") ?? 128
        guard let limit = UInt16(exactly: maximum), limit > 0 else {
            throw CLIError("Sync maximum must be a positive 16-bit integer.")
        }
        let result = try await headlessClient(options).sync(
            relationshipID: relationshipID,
            maximumPackets: limit
        )
        try writeJSON(SyncStatusOutput(relationshipID: relationshipID, result: result))
    }

    private func maintain(_ options: ParsedOptions) async throws {
        let client = try await headlessClient(options)
        if try options.bool("--all") == true {
            guard options.value("--relationship") == nil else {
                throw CLIError("Use either `--all true` or `--relationship`, not both.")
            }
            try writeJSON(try await client.maintainAllRelationships())
            return
        }
        guard options.value("--all") == nil else {
            throw CLIError("`--all` must be true when supplied.")
        }
        try writeJSON(try await client.maintainRelationship(
            relationshipID: try relationshipIdentifier(options)
        ))
    }

    private func relationshipPolicy(_ options: ParsedOptions) async throws {
        let relationshipID = try relationshipIdentifier(options)
        let client = try await headlessClient(options)
        var policy = try await client.relationship(relationshipID).localPolicy
        var changed = false

        if let rawConsent = options.value("--consent") {
            guard let consent = RelationshipConsentStateV2(rawValue: rawConsent) else {
                throw CLIError("Consent must be pendingRequest, accepted, or blocked.")
            }
            policy.consent = consent
            changed = true
        }
        if let rawMute = options.value("--mute-until") {
            policy.mutedUntil = try parseMuteDate(rawMute)
            changed = true
        }
        if let enabled = try options.bool("--delivery-receipts") {
            policy.deliveryReceiptsEnabled = enabled
            changed = true
        }
        if let enabled = try options.bool("--read-receipts") {
            policy.readReceiptsEnabled = enabled
            changed = true
        }
        guard changed else {
            throw CLIError("No relationship-policy change was supplied.")
        }
        try await client.setRelationshipLocalPolicy(
            policy,
            relationshipID: relationshipID
        )
        try writeJSON(try await client.relationship(relationshipID).localPolicy)
    }

    private func continuityPolicy(_ options: ParsedOptions) async throws {
        let relationshipID = try relationshipIdentifier(options)
        let rawMode = try required(options, "--mode")
        guard let policy = RelationshipContinuityPolicyV2(rawValue: rawMode) else {
            throw CLIError("Continuity mode must be disabled, sendOnly, receiveOnly, or bidirectional.")
        }
        let client = try await headlessClient(options)
        try await client.setContinuityPolicy(policy, relationshipID: relationshipID)
        try writeJSON(ContinuityPolicyOutput(
            relationshipID: relationshipID,
            mode: policy
        ))
    }

    private func continuityOffer(_ options: ParsedOptions) async throws {
        let relationshipID = try relationshipIdentifier(options)
        let invitation = try ContactPairingInvitationV2.decode(try readSensitiveText(
            from: try required(options, "--invitation-file")
        ))
        let result = try await headlessClient(options).sendContinuityOffer(
            relationshipID: relationshipID,
            invitation: invitation
        )
        try writeJSON(SendStatusOutput(relationshipID: relationshipID, result: result))
    }

    private func continuityInvitation(_ options: ParsedOptions) async throws {
        let relationshipID = try relationshipIdentifier(options)
        let eventID = try uuidOption(options, "--event")
        let output = try required(options, "--out")
        let invitation = try await headlessClient(options).continuityInvitation(
            relationshipID: relationshipID,
            eventID: eventID
        )
        try writeSensitiveText(try invitation.encoded(), to: output)
        try writeJSON(ContinuityInvitationOutput(
            relationshipID: relationshipID,
            eventID: eventID,
            invitationFile: output,
            expiresAt: invitation.offer.expiresAt
        ))
    }

    private func safetyNumber(_ options: ParsedOptions) async throws {
        let relationshipID = try relationshipIdentifier(options)
        let relationship = try await headlessClient(options).relationship(relationshipID)
        let value = try RelationshipSafetyNumberV2.make(
            localAuthoritySigningPublicKey: relationship.localIdentity
                .relationshipAuthority.signingKey.publicKeyData,
            peerAuthoritySigningPublicKey: relationship.peerIdentity.signingPublicKey
        )
        try writeJSON(RelationshipSafetyNumberOutput(
            relationshipID: relationshipID,
            safetyNumber: value
        ))
    }

    private func blockRelationship(_ options: ParsedOptions) async throws {
        let relationshipID = try relationshipIdentifier(options)
        let tornDown = try await headlessClient(options).blockRelationship(relationshipID)
        try writeJSON(RelationshipBlockOutput(
            relationshipID: relationshipID,
            tornDownRouteIDs: tornDown
        ))
    }

    private func markRead(_ options: ParsedOptions) async throws {
        let relationshipID = try relationshipIdentifier(options)
        let eventID = try uuidOption(options, "--event")
        let result = try await headlessClient(options).markRead(
            eventID: eventID,
            relationshipID: relationshipID
        )
        try writeJSON(SendStatusOutput(relationshipID: relationshipID, result: result))
    }

    private func retryDeliveries(_ options: ParsedOptions) async throws {
        let relationshipID = try relationshipIdentifier(options)
        let accepted = try await headlessClient(options).retryPendingDeliveries(
            relationshipID: relationshipID
        )
        try writeJSON(DeliveryRetryOutput(
            relationshipID: relationshipID,
            acceptedDeliveryCount: accepted
        ))
    }

    private func discardDelivery(_ options: ParsedOptions) async throws {
        let relationshipID = try relationshipIdentifier(options)
        let intentID = try uuidOption(options, "--intent")
        try await headlessClient(options).discardFailedDelivery(
            intentID: intentID,
            relationshipID: relationshipID
        )
        try writeJSON(DiscardOutput(
            relationshipID: relationshipID,
            discardedKind: "delivery",
            discardedIdentifier: intentID.uuidString.lowercased()
        ))
    }

    private func resumeRollovers(_ options: ParsedOptions) async throws {
        let relationshipID = try relationshipIdentifier(options)
        try writeJSON(try await headlessClient(options).resumePendingRouteRollovers(
            relationshipID: relationshipID
        ))
    }

    private func finalizeRoutes(_ options: ParsedOptions) async throws {
        let relationshipID = try relationshipIdentifier(options)
        try writeJSON(try await headlessClient(options).finalizeDrainedRoutes(
            relationshipID: relationshipID
        ))
    }

    private func discardRollover(_ options: ParsedOptions) async throws {
        let relationshipID = try relationshipIdentifier(options)
        let routeID = try opaqueRouteIdentifier(options)
        let publication = try await headlessClient(options).discardFailedRouteRollover(
            routeID: routeID,
            relationshipID: relationshipID
        )
        try writeJSON(DiscardRolloverOutput(
            relationshipID: relationshipID,
            routeID: routeID,
            routeSetPublication: publication
        ))
    }

    private func burnPersona(_ options: ParsedOptions) async throws {
        guard options.value("--confirm") == "BURN" else {
            throw CLIError("Persona burn requires `--confirm BURN`.")
        }
        let replacementName = try required(options, "--replacement-name")
        let replacement = try await headlessClient(options).burnActivePersona(
            replacementDisplayName: replacementName
        )
        try writeJSON(PersonaStatusOutput(replacement))
    }

    private func headlessClient(_ options: ParsedOptions) async throws -> HeadlessMessagingClient {
        let store = try stateStore(options)
        guard let state = try await store.load() else {
            throw CLIError("No state exists. Run `NoctweaveCLI init` first.")
        }
        return try HeadlessMessagingClient(stateStore: store, initialState: state)
    }

    private func stateStore(_ options: ParsedOptions) throws -> ClientStateStore {
        let path = options.value("--state") ?? "./noctweave-state.json"
        let plaintext = try options.bool("--plaintext") ?? false
        return ClientStateStore(
            fileURL: URL(fileURLWithPath: path),
            useEncryption: !plaintext
        )
    }

    private func relationshipIdentifier(_ options: ParsedOptions) throws -> UUID {
        try uuidOption(options, "--relationship")
    }

    private func uuidOption(_ options: ParsedOptions, _ name: String) throws -> UUID {
        let raw = try required(options, name)
        guard let id = UUID(uuidString: raw) else {
            throw CLIError("`\(name)` must be a UUID.")
        }
        return id
    }

    private func opaqueRouteIdentifier(_ options: ParsedOptions) throws -> OpaqueReceiveRouteIDV2 {
        let encoded = try required(options, "--route-id")
        guard let rawValue = Data(base64Encoded: encoded), rawValue.count == 32 else {
            throw CLIError("`--route-id` must be a base64-encoded 32-byte opaque route ID.")
        }
        return try NoctweaveCoder.decode(
            OpaqueReceiveRouteIDV2.self,
            from: NoctweaveCoder.encode(OpaqueRouteIDInput(rawValue: rawValue))
        )
    }

    private func parseMuteDate(_ raw: String) throws -> Date? {
        if raw.lowercased() == "none" { return nil }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let ordinary = ISO8601DateFormatter()
        ordinary.formatOptions = [.withInternetDateTime]
        guard let date = fractional.date(from: raw) ?? ordinary.date(from: raw),
              date.timeIntervalSince1970.isFinite else {
            throw CLIError("`--mute-until` must be RFC 3339 or `none`.")
        }
        return date
    }

    private func endpoint(_ options: ParsedOptions) throws -> RelayEndpoint {
        try RelayEndpointParser.parse(try required(options, "--relay"))
    }

    private func rendezvousRelayClient(_ options: ParsedOptions) throws -> RelayClient {
        RelayClient(
            endpoint: try endpoint(options),
            authToken: try authToken(options)
        )
    }

    private func appendRendezvous(
        _ request: AppendRendezvousTransportV2Request,
        relay: RelayClient
    ) async throws {
        try await requireEmptyRelaySuccess(
            relay.send(.appendRendezvousTransportV2(request)),
            operation: "append rendezvous frame"
        )
    }

    private func requireEmptyRelaySuccess(
        _ response: RelayResponse,
        operation: String
    ) throws {
        guard response.status == .success,
              case .empty? = response.successBody else {
            throw CLIError("Relay rejected the request to \(operation).")
        }
    }

    private func waitForRendezvousFrames(
        adapter: RendezvousRelayAdapterV2,
        receivingAs role: RendezvousRoleV2,
        afterSequence: UInt64,
        count: Int,
        invitation: ContactPairingInvitationV2,
        relay: RelayClient,
        options: ParsedOptions
    ) async throws -> [RendezvousRelayCiphertextFrameV2] {
        let waitSeconds = try options.double("--wait-seconds") ?? 600
        let pollMilliseconds = try options.int("--poll-ms") ?? 250
        guard waitSeconds > 0,
              waitSeconds <= 3_600,
              (50...5_000).contains(pollMilliseconds),
              count > 0,
              count <= RendezvousRelayTransportV2.maximumSyncFrames else {
            throw CLIError(
                "Pairing waits require 1...3600 seconds and a 50...5000 ms polling interval."
            )
        }
        let deadline = min(
            invitation.offer.expiresAt,
            Date().addingTimeInterval(waitSeconds)
        )
        var cursor = afterSequence
        var frames: [RendezvousRelayCiphertextFrameV2] = []
        while frames.count < count, Date() < deadline {
            let response = try await relay.send(.syncRendezvousTransportV2(
                adapter.syncRequest(
                    receivingAs: role,
                    afterSequence: cursor,
                    maxCount: count - frames.count
                )
            ))
            guard response.status == .success,
                  case .rendezvousSync(let batch)? = response.successBody else {
                throw CLIError("Relay rejected the rendezvous synchronization request.")
            }
            guard batch.frames.first?.sequence == nil
                    || batch.frames.first?.sequence == cursor + 1,
                  zip(batch.frames, batch.frames.dropFirst()).allSatisfy({ pair in
                      pair.1.sequence == pair.0.sequence + 1
                  }) else {
                throw CLIError("Relay returned non-contiguous rendezvous frames.")
            }
            frames.append(contentsOf: batch.frames)
            cursor = batch.nextSequence
            if frames.count < count {
                try await Task.sleep(
                    nanoseconds: UInt64(pollMilliseconds) * 1_000_000
                )
            }
        }
        guard frames.count == count else {
            throw CLIError(
                "Rendezvous exchange timed out; create a fresh invitation before retrying."
            )
        }
        return frames
    }

    private func pairingTimestamp() -> Date {
        Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
    }

    private func sendRelay(_ request: RelayRequest, options: ParsedOptions) async throws {
        let timeout = try options.double("--timeout") ?? RelayClient.defaultTimeout
        let response = try await RelayClient(
            endpoint: try endpoint(options),
            authToken: try authToken(options)
        ).send(request, timeout: timeout)
        try writeJSON(response)
    }

    private func relayRequest(_ options: ParsedOptions) throws -> RelayRequest {
        let raw = try required(options, "--request")
        let data: Data
        if raw.hasPrefix("@") {
            let path = String(raw.dropFirst())
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            guard let size = attributes[.size] as? NSNumber,
                  size.intValue <= Self.maximumRawRequestBytes else {
                throw CLIError("Relay request file exceeds the size limit.")
            }
            data = try Data(contentsOf: URL(fileURLWithPath: path))
        } else {
            data = Data(raw.utf8)
        }
        guard !data.isEmpty, data.count <= Self.maximumRawRequestBytes else {
            throw CLIError("Relay request is empty or exceeds the size limit.")
        }
        return try NoctweaveCoder.decode(RelayRequest.self, from: data)
    }

    private func authToken(_ options: ParsedOptions) throws -> String? {
        guard let path = options.value("--auth-file") else { return nil }
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        guard let size = attributes[.size] as? NSNumber, size.intValue <= 4_096 else {
            throw CLIError("Relay authentication file exceeds the size limit.")
        }
        let value = try String(contentsOfFile: path, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { throw CLIError("Relay authentication file is empty.") }
        return value
    }

    private func readSensitiveJSON<T: Decodable>(
        _ type: T.Type,
        from path: String
    ) throws -> T {
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        guard let size = attributes[.size] as? NSNumber,
              size.intValue > 0,
              size.intValue <= Self.maximumSensitiveInputBytes else {
            throw CLIError("Sensitive input file is empty or exceeds the size limit.")
        }
        var data = try Data(contentsOf: URL(fileURLWithPath: path))
        defer { data.wipeCLIOutputBuffer() }
        return try NoctweaveCoder.decode(type, from: data)
    }

    private func readSensitiveText(from path: String) throws -> String {
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        guard let size = attributes[.size] as? NSNumber,
              size.intValue > 0,
              size.intValue <= Self.maximumSensitiveInputBytes else {
            throw CLIError("Sensitive input file is empty or exceeds the size limit.")
        }
        var data = try Data(contentsOf: URL(fileURLWithPath: path))
        defer { data.wipeCLIOutputBuffer() }
        guard let value = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines),
              !value.isEmpty else {
            throw CLIError("Sensitive input file is not valid UTF-8 text.")
        }
        return value
    }

    private func readPrivateMessageText(from path: String) throws -> String {
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        guard let size = attributes[.size] as? NSNumber,
              size.intValue > 0,
              size.intValue <= Self.maximumSensitiveInputBytes else {
            throw CLIError("Message input file is empty or exceeds the size limit.")
        }
        var data = try Data(contentsOf: URL(fileURLWithPath: path))
        defer { data.wipeCLIOutputBuffer() }
        guard let value = String(data: data, encoding: .utf8), !value.isEmpty else {
            throw CLIError("Message input file is not valid non-empty UTF-8 text.")
        }
        return value
    }

    private func required(_ options: ParsedOptions, _ name: String) throws -> String {
        guard let value = options.value(name), !value.isEmpty else {
            throw CLIError("Missing required option `\(name)`.")
        }
        return value
    }

    private func writeJSON<T: Encodable>(_ value: T) throws {
        var data = try NoctweaveCoder.encode(value)
        defer { data.wipeCLIOutputBuffer() }
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([0x0a]))
    }

    private func writeSensitiveJSON<T: Encodable>(_ value: T, to path: String) throws {
        var data = try NoctweaveCoder.encode(value)
        defer { data.wipeCLIOutputBuffer() }
        try writeSensitiveData(data, to: path)
    }

    private func writeSensitiveText(_ value: String, to path: String) throws {
        var data = Data(value.utf8)
        defer { data.wipeCLIOutputBuffer() }
        try writeSensitiveData(data, to: path)
    }

    private func writeSensitiveData(_ data: Data, to path: String) throws {
        let url = URL(fileURLWithPath: path)
        let directory = url.deletingLastPathComponent()
        let temporaryURL = directory.appendingPathComponent(
            ".\(url.lastPathComponent).\(UUID().uuidString.lowercased()).tmp"
        )
        let descriptor = temporaryURL.path.withCString { temporaryPath in
            open(temporaryPath, O_WRONLY | O_CREAT | O_EXCL, mode_t(0o600))
        }
        guard descriptor >= 0 else {
            throw CLIError("Could not create the private output file.")
        }
        var descriptorIsOpen = true
        defer {
            if descriptorIsOpen { _ = close(descriptor) }
            temporaryURL.path.withCString { _ = unlink($0) }
        }

        try data.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            var written = 0
            while written < rawBuffer.count {
                let result = write(
                    descriptor,
                    baseAddress.advanced(by: written),
                    rawBuffer.count - written
                )
                if result < 0, errno == EINTR { continue }
                guard result > 0 else {
                    throw CLIError("Could not write the private output file.")
                }
                written += result
            }
        }
        guard fsync(descriptor) == 0, close(descriptor) == 0 else {
            descriptorIsOpen = false
            throw CLIError("Could not durably close the private output file.")
        }
        descriptorIsOpen = false
        let renameResult = temporaryURL.path.withCString { temporaryPath in
            url.path.withCString { destinationPath in
                rename(temporaryPath, destinationPath)
            }
        }
        guard renameResult == 0 else {
            throw CLIError("Could not atomically install the private output file.")
        }
    }

    private func printHelp() {
        FileHandle.standardOutput.writeLine("""
        NoctweaveCLI — pairwise-private Noctweave 1.0 architecture

          init --display-name <local-label> [--state path] [--plaintext true]
          status [--state path] [--plaintext true]
          relationships [--state path] [--plaintext true]
          prepare-participant --relay <https|wss|tls URL> --out <private-file> [--relationship-pseudonym label]
          pairing-invitation --offer-out <private-file> --invitation-out <share-file> [--lifetime seconds]
          pair-offer --offer-file <private-file> --participant-file <private-file> --relay <URL> [--wait-seconds n] [--poll-ms n]
          pair-accept --invitation-file <share-file> --participant-file <private-file> --relay <URL> [--wait-seconds n] [--poll-ms n]
          send --relationship <uuid> --text-file <private-file>
          sync --relationship <uuid> [--max packets]
          maintain (--all true | --relationship <uuid>)
          relationship-policy --relationship <uuid> [--consent pendingRequest|accepted|blocked] [--mute-until <RFC3339|none>] [--delivery-receipts bool] [--read-receipts bool]
          continuity-policy --relationship <uuid> --mode disabled|sendOnly|receiveOnly|bidirectional
          continuity-offer --relationship <uuid> --invitation-file <share-file>
          continuity-invitation --relationship <uuid> --event <uuid> --out <share-file>
          safety-number --relationship <uuid>
          block --relationship <uuid>
          mark-read --relationship <uuid> --event <uuid>
          retry-deliveries --relationship <uuid>
          discard-delivery --relationship <uuid> --intent <uuid>
          resume-rollovers --relationship <uuid>
          finalize-routes --relationship <uuid>
          discard-rollover --relationship <uuid> --route-id <base64>
          burn-persona --confirm BURN --replacement-name <local-label>
          endpoint --relay <url|host:port>
          health --relay <url|host:port> [--auth-file path] [--timeout seconds]
          info --relay <url|host:port> [--auth-file path] [--timeout seconds]
          raw --relay <url|host:port> --request '<json|@path>'

        Personas are local containers. Pairing creates independent, unlinkable
        relationship identities and opaque relay routes. Personas never become
        network identifiers. `pair-offer` and `pair-accept` are live commands;
        if either process is interrupted, let the opaque rendezvous expire and
        create a fresh invitation instead of exporting live session keys. Files
        containing private or bearer material are atomically installed with
        mode 0600 and are never emitted directly to standard output. Message
        plaintext is read from a file so it does not appear in process arguments.
        """)
    }
}

private struct PairingOfferFile: Codable {
    let pending: PendingRendezvousOfferV2
    let invitation: ContactPairingInvitationV2
}

private struct PairingInvitationOutput: Codable {
    let offerFile: String
    let invitationFile: String
    let expiresAt: Date
}

private struct PairingCompletionOutput: Codable {
    let relationshipID: UUID
    let rendezvousCleanup: String
}

private struct RelationshipBlockOutput: Codable {
    let relationshipID: UUID
    let tornDownRouteIDs: [OpaqueReceiveRouteIDV2]
}

private struct ContinuityPolicyOutput: Codable {
    let relationshipID: UUID
    let mode: RelationshipContinuityPolicyV2
}

private struct ContinuityInvitationOutput: Codable {
    let relationshipID: UUID
    let eventID: UUID
    let invitationFile: String
    let expiresAt: Date
}

private struct RelationshipSafetyNumberOutput: Codable {
    let relationshipID: UUID
    let safetyNumber: String
}

private struct DeliveryRetryOutput: Codable {
    let relationshipID: UUID
    let acceptedDeliveryCount: Int
}

private struct DiscardOutput: Codable {
    let relationshipID: UUID
    let discardedKind: String
    let discardedIdentifier: String
}

private struct DiscardRolloverOutput: Codable {
    let relationshipID: UUID
    let routeID: OpaqueReceiveRouteIDV2
    let routeSetPublication: HeadlessPublicationResult?
}

private struct OpaqueRouteIDInput: Codable {
    let rawValue: Data
}

private struct PersonaStatusOutput: Codable {
    let id: UUID
    let displayName: String
    let createdAt: Date
    let relationships: [RelationshipStatusOutput]
    let groupIDs: [UUID]

    init(_ persona: PersonaProfileV1) {
        id = persona.id
        displayName = persona.displayName
        createdAt = persona.createdAt
        relationships = persona.relationships.map(RelationshipStatusOutput.init)
        groupIDs = persona.groupRuntimes.map(\.groupId)
    }
}

private struct RelationshipStatusOutput: Codable {
    let id: UUID
    let conversationID: String
    let createdAt: Date
    let localPolicy: RelationshipLocalPolicyV2
    let continuityPolicy: RelationshipContinuityPolicyV2
    let eventCount: Int
    let pendingDeliveryCount: Int
    let pendingRolloverCount: Int
    let pendingAttachmentUploadCount: Int
    let activeIntentCount: Int
    let failedIntentCount: Int
    let transportQuarantineCount: Int
    let controlQuarantineCount: Int

    init(_ relationship: PairwiseRelationshipV2) {
        id = relationship.id
        conversationID = relationship.conversationID
        createdAt = relationship.createdAt
        localPolicy = relationship.localPolicy
        continuityPolicy = relationship.continuityPolicy
        eventCount = relationship.events.count
        pendingDeliveryCount = relationship.pendingDeliveries.count
        pendingRolloverCount = relationship.pendingRouteRollovers.count
        pendingAttachmentUploadCount = relationship.pendingAttachmentUploads.count
        activeIntentCount = relationship.protocolIntents.filter {
            !$0.state.isTerminal
        }.count
        failedIntentCount = relationship.protocolIntents.filter {
            $0.state == .permanentFailure
        }.count
        transportQuarantineCount = relationship.transportQuarantine.count
        controlQuarantineCount = relationship.controlQuarantine.count
    }
}

private struct SendStatusOutput: Codable {
    let relationshipID: UUID
    let eventID: UUID
    let clientTransactionID: UUID
    let acceptedDeliveryCount: Int
    let pendingDeliveryCount: Int
    let failedDeliveryCount: Int
    let nextRetryNotBefore: Date?

    init(relationshipID: UUID, result: HeadlessSendResult) {
        self.relationshipID = relationshipID
        eventID = result.event.id
        clientTransactionID = result.event.clientTransactionId
        acceptedDeliveryCount = result.acceptedDeliveryCount
        pendingDeliveryCount = result.pendingDeliveryCount
        failedDeliveryCount = result.failedDeliveryCount
        nextRetryNotBefore = result.nextRetryNotBefore
    }
}

private struct SyncStatusOutput: Codable {
    let relationshipID: UUID
    let receivedEvents: [EventStatusOutput]
    let synchronizedRouteCount: Int
    let routesWithAdvancedCursor: Int
    let hasMore: Bool

    init(relationshipID: UUID, result: [HeadlessSyncResult]) {
        self.relationshipID = relationshipID
        var seen = Set<UUID>()
        receivedEvents = result.flatMap(\.receivedEvents).compactMap { event in
            guard seen.insert(event.id).inserted else { return nil }
            return EventStatusOutput(event)
        }
        synchronizedRouteCount = result.count
        routesWithAdvancedCursor = result.filter { $0.committedCursor != nil }.count
        hasMore = result.contains(where: \.hasMore)
    }
}

private struct EventStatusOutput: Codable {
    let id: UUID
    let clientTransactionID: UUID
    let kind: ConversationEventKind
    let contentType: ContentTypeId
    let createdAt: Date

    init(_ event: ConversationEvent) {
        id = event.id
        clientTransactionID = event.clientTransactionId
        kind = event.kind
        contentType = event.content.type
        createdAt = event.createdAt
    }
}

private struct ParsedOptions {
    private let values: [String: String]

    init(_ arguments: [String]) throws {
        var parsed: [String: String] = [:]
        var index = 0
        while index < arguments.count {
            let key = arguments[index]
            guard key.hasPrefix("--"), parsed[key] == nil else {
                throw CLIError("Invalid or duplicate option: \(key)")
            }
            guard index + 1 < arguments.count else {
                throw CLIError("Option requires a value: \(key)")
            }
            parsed[key] = arguments[index + 1]
            index += 2
        }
        values = parsed
    }

    func value(_ key: String) -> String? { values[key] }

    func int(_ key: String) throws -> Int? {
        guard let raw = value(key) else { return nil }
        guard let value = Int(raw) else { throw CLIError("Invalid integer for `\(key)`.") }
        return value
    }

    func double(_ key: String) throws -> Double? {
        guard let raw = value(key) else { return nil }
        guard let value = Double(raw), value.isFinite else {
            throw CLIError("Invalid number for `\(key)`.")
        }
        return value
    }

    func bool(_ key: String) throws -> Bool? {
        guard let raw = value(key)?.lowercased() else { return nil }
        switch raw {
        case "true", "1", "yes": return true
        case "false", "0", "no": return false
        default: throw CLIError("Invalid boolean for `\(key)`.")
        }
    }
}

private struct CLIError: Error {
    let message: String
    let exitCode: Int

    init(_ message: String, exitCode: Int = 1) {
        self.message = message
        self.exitCode = exitCode
    }
}

private extension FileHandle {
    func writeLine(_ value: String) {
        write(Data((value + "\n").utf8))
    }
}

private extension Data {
    mutating func wipeCLIOutputBuffer() {
        withUnsafeMutableBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            memset(baseAddress, 0, rawBuffer.count)
        }
        removeAll(keepingCapacity: false)
    }
}
