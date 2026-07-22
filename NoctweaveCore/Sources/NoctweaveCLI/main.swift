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
        if let allowed = Self.allowedOptions(for: command) {
            try options.requireOnly(allowed)
        }
        switch command {
        case "help", "--help", "-h":
            printHelp()
        case "init":
            try await initialize(options)
        case "status":
            try await status(options)
        case "attachment-download-prepare":
            try await prepareAttachmentDownload(options)
        case "attachment-download-fetch":
            try await fetchAttachmentDownload(options)
        case "relationships":
            let client = try await headlessClient(options)
            try writeJSON(await client.activePersona().relationships.map(
                RelationshipStatusOutput.init
            ))
        case "groups":
            try await listGroups(options)
        case "group-status":
            try await groupStatus(options)
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
        case "group-create":
            try await createGroup(options)
        case "group-send":
            try await sendGroupText(options)
        case "group-sync":
            try await syncGroup(options)
        case "group-maintain":
            try await maintainGroup(options)
        case "group-resume":
            try await resumeGroupOperation(options)
        case "group-invite-request":
            try await makeGroupInvitationRequest(options)
        case "group-admission-prepare":
            try await prepareGroupAdmissionResponse(options)
        case "group-admission-resume":
            try await resumeGroupAdmissionResponse(options)
        case "group-admissions":
            try await listPendingGroupAdmissions(options)
        case "group-add-member":
            try await addGroupMember(options)
        case "group-join-accept":
            try await acceptGroupJoin(options)
        case "group-delete":
            try await deleteGroup(options)
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
        case "erase-local-state":
            try await eraseLocalState(options)
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

    /// One command owns every option it accepts. This check runs before the
    /// command dispatch so a misspelled or cross-command option can never be
    /// silently ignored after local state or relay effects have begun.
    private static func allowedOptions(for command: String) -> Set<String>? {
        switch command {
        case "help", "--help", "-h":
            return []
        case "init":
            return [
                "--display-name", "--relay", "--relay-name",
                "--accept-privacy-policy", "--accept-terms-of-use",
                "--state", "--plaintext",
            ]
        case "status", "relationships", "groups", "group-admissions":
            return ["--state", "--plaintext"]
        case "attachment-download-prepare":
            return ["--relationship", "--descriptor-file", "--relay", "--out", "--state", "--plaintext"]
        case "attachment-download-fetch":
            return ["--relationship", "--download", "--out", "--state", "--plaintext"]
        case "group-status":
            return ["--group", "--state", "--plaintext"]
        case "prepare-participant":
            return [
                "--relay", "--out", "--relationship-pseudonym", "--state", "--plaintext",
            ]
        case "pairing-invitation":
            return [
                "--offer-out", "--invitation-out", "--lifetime", "--state", "--plaintext",
            ]
        case "pair-offer":
            return [
                "--offer-file", "--participant-file", "--relay", "--wait-seconds",
                "--poll-ms", "--state", "--plaintext",
            ]
        case "pair-accept":
            return [
                "--invitation-file", "--participant-file", "--relay", "--wait-seconds",
                "--poll-ms", "--state", "--plaintext",
            ]
        case "send":
            return ["--relationship", "--text-file", "--state", "--plaintext"]
        case "sync":
            return ["--relationship", "--max", "--state", "--plaintext"]
        case "maintain":
            return ["--all", "--relationship", "--state", "--plaintext"]
        case "group-create":
            return ["--group", "--relay", "--state", "--plaintext"]
        case "group-send":
            return ["--group", "--text-file", "--state", "--plaintext"]
        case "group-sync":
            return ["--group", "--max", "--pages", "--state", "--plaintext"]
        case "group-maintain":
            return ["--group", "--all", "--state", "--plaintext"]
        case "group-resume":
            return ["--group", "--operation", "--state", "--plaintext"]
        case "group-invite-request":
            return ["--group", "--out", "--lifetime", "--state", "--plaintext"]
        case "group-admission-prepare":
            return [
                "--invitation-file", "--relay", "--response-out", "--state", "--plaintext",
            ]
        case "group-admission-resume":
            return [
                "--admission", "--invitation-file", "--response-out", "--state", "--plaintext",
            ]
        case "group-add-member":
            return [
                "--group", "--invitation-file", "--response-file", "--join-out", "--role",
                "--state", "--plaintext",
            ]
        case "group-join-accept":
            return ["--admission", "--join-file", "--state", "--plaintext"]
        case "group-delete":
            return ["--group", "--confirm", "--reason-file", "--state", "--plaintext"]
        case "relationship-policy":
            return [
                "--relationship", "--consent", "--mute-until", "--delivery-receipts",
                "--read-receipts", "--state", "--plaintext",
            ]
        case "continuity-policy":
            return ["--relationship", "--mode", "--state", "--plaintext"]
        case "continuity-offer":
            return ["--relationship", "--invitation-file", "--state", "--plaintext"]
        case "continuity-invitation":
            return ["--relationship", "--event", "--out", "--state", "--plaintext"]
        case "safety-number", "block":
            return ["--relationship", "--state", "--plaintext"]
        case "mark-read":
            return ["--relationship", "--event", "--state", "--plaintext"]
        case "retry-deliveries", "resume-rollovers", "finalize-routes":
            return ["--relationship", "--state", "--plaintext"]
        case "discard-delivery":
            return ["--relationship", "--intent", "--state", "--plaintext"]
        case "discard-rollover":
            return ["--relationship", "--route-id", "--state", "--plaintext"]
        case "burn-persona":
            return ["--confirm", "--replacement-name", "--state", "--plaintext"]
        case "erase-local-state":
            return ["--confirm", "--state", "--plaintext"]
        case "endpoint":
            return ["--relay"]
        case "health", "info":
            return ["--relay", "--auth-file", "--timeout"]
        case "raw":
            return ["--relay", "--request", "--auth-file", "--timeout"]
        default:
            return nil
        }
    }

    private func initialize(_ options: ParsedOptions) async throws {
        let name = try required(options, "--display-name")
        guard try options.bool("--accept-privacy-policy") == true else {
            throw CLIError(
                "`init` requires `--accept-privacy-policy true`; review the current privacy policy before continuing."
            )
        }
        guard try options.bool("--accept-terms-of-use") == true else {
            throw CLIError(
                "`init` requires `--accept-terms-of-use true`; review the current terms of use before continuing."
            )
        }
        let relay: LocalRelayPreference?
        if let relayValue = options.value("--relay") {
            let endpoint = try RelayEndpointParser.parse(relayValue)
            relay = LocalRelayPreference(
                name: options.value("--relay-name") ?? "Initial relay",
                endpoint: endpoint
            )
        } else if options.value("--relay-name") != nil {
            throw CLIError("`--relay-name` requires `--relay`.")
        } else {
            relay = nil
        }
        let store = try stateStore(options)
        if try await store.load() != nil {
            throw CLIError("State already exists.")
        }
        var state = try ClientState.initialLocalState(
            displayName: name,
            relayPreferences: relay.map { [$0] } ?? [],
            preferredRelayPreferenceID: relay?.id
        )
        try state.completeOnboarding(
            privacyPolicyAccepted: true,
            termsOfUseAccepted: true
        )
        try await store.save(state, replacing: nil)
        try writeJSON(PersonaStatusOutput(state.activePersona))
    }

    private func status(_ options: ParsedOptions) async throws {
        let client = try await headlessClient(options)
        try writeJSON(PersonaStatusOutput(await client.activePersona()))
    }

    private func prepareAttachmentDownload(_ options: ParsedOptions) async throws {
        let output = try required(options, "--out")
        try validateSensitiveOutputPath(output, options: options)
        let descriptor = try readSensitiveJSON(
            AttachmentDescriptor.self,
            from: try required(options, "--descriptor-file")
        )
        let client = try await headlessClient(options)
        let pending = try await client.prepareAttachmentDownload(
            descriptor,
            relay: try endpoint(options),
            relationshipID: try relationshipIdentifier(options)
        )
        try writeSensitiveJSON(pending, to: output)
        try writeJSON(AttachmentDownloadJournalOutput(
            relationshipID: pending.relationshipID,
            downloadID: pending.id,
            attachmentID: pending.descriptor.id,
            output: output
        ))
    }

    private func fetchAttachmentDownload(_ options: ParsedOptions) async throws {
        let output = try required(options, "--out")
        try validateSensitiveOutputPath(output, options: options)
        let result = try await headlessClient(options).fetchAttachmentDownload(
            downloadID: try uuidOption(options, "--download"),
            relationshipID: try relationshipIdentifier(options)
        )
        try writeSensitiveJSON(result, to: output)
        try writeJSON(AttachmentDownloadFetchOutput(
            relationshipID: result.relationshipID,
            downloadID: result.downloadID,
            attachmentID: result.attachmentID,
            chunkIndex: result.chunkIndex,
            complete: result.complete,
            accepted: result.accepted,
            output: output
        ))
    }

    private func prepareParticipant(_ options: ParsedOptions) async throws {
        let output = try required(options, "--out")
        try validateSensitiveOutputPath(output, options: options)
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
        try validateSensitiveOutputPath(
            offerOutput,
            options: options,
            distinctFrom: [invitationOutput]
        )
        try validateSensitiveOutputPath(
            invitationOutput,
            options: options,
            distinctFrom: [offerOutput]
        )
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

    private func listGroups(_ options: ParsedOptions) async throws {
        try options.requireOnly(["--state", "--plaintext"])
        let persona = await (try headlessClient(options)).activePersona()
        try writeJSON(persona.groupRuntimes
            .sorted { $0.groupId.uuidString < $1.groupId.uuidString }
            .map(GroupStatusOutput.init))
    }

    private func groupStatus(_ options: ParsedOptions) async throws {
        try options.requireOnly(["--group", "--state", "--plaintext"])
        let groupID = try uuidOption(options, "--group")
        let persona = await (try headlessClient(options)).activePersona()
        guard let group = persona.groupRuntimes.first(where: { $0.groupId == groupID }) else {
            throw CLIError("Group is not present in this local state.")
        }
        try writeJSON(GroupStatusOutput(group))
    }

    private func createGroup(_ options: ParsedOptions) async throws {
        try options.requireOnly(["--group", "--relay", "--state", "--plaintext"])
        // The caller supplies the logical ID so a retry after an interrupted
        // create can address the exact durable operation instead of minting a
        // second group.
        let groupID = try uuidOption(options, "--group")
        let created = try await headlessClient(options).createGroup(
            groupID: groupID,
            relay: try endpoint(options)
        )
        try writeJSON(GroupCreationStatusOutput(created))
        try requireCompleteGroupEffect(
            created.receiveRoute.announcementComplete,
            disposition: .pendingRetry,
            operation: "group creation route announcement"
        )
    }

    private func sendGroupText(_ options: ParsedOptions) async throws {
        try options.requireOnly(["--group", "--text-file", "--state", "--plaintext"])
        let groupID = try uuidOption(options, "--group")
        let text = try readPrivateMessageText(
            from: try required(options, "--text-file")
        )
        let result = try await headlessClient(options).sendGroupText(
            groupID: groupID,
            text: text
        )
        try writeJSON(GroupSendStatusOutput(result))
        try requireCompleteGroupEffect(
            result.complete,
            disposition: result.disposition,
            operation: "group message publication"
        )
    }

    private func syncGroup(_ options: ParsedOptions) async throws {
        try options.requireOnly([
            "--group", "--max", "--pages", "--state", "--plaintext"
        ])
        let groupID = try uuidOption(options, "--group")
        let maximum = try options.int("--max") ?? 128
        guard let limit = UInt16(exactly: maximum), (1...1_024).contains(maximum) else {
            throw CLIError("Group sync maximum must be between 1 and 1024 packets per route.")
        }
        let maximumPages = try options.int("--pages") ?? 8
        guard (1...64).contains(maximumPages) else {
            throw CLIError("Group sync pages must be between 1 and 64.")
        }
        let client = try await headlessClient(options)
        var pages: [[GroupInboundSyncResultV2]] = []
        for _ in 0..<maximumPages {
            let page = try await client.syncGroup(
                groupID: groupID,
                maximumPackets: limit
            )
            pages.append(page)
            guard page.contains(where: \.hasMore) else { break }
        }
        try writeJSON(GroupSyncStatusOutput(groupID: groupID, pages: pages))
    }

    private func maintainGroup(_ options: ParsedOptions) async throws {
        try options.requireOnly(["--group", "--all", "--state", "--plaintext"])
        let client = try await headlessClient(options)
        if try options.bool("--all") == true {
            guard options.value("--group") == nil else {
                throw CLIError("Use either `--all true` or `--group`, not both.")
            }
            let groupIDs = await client.activePersona().groupRuntimes
                .map(\.groupId)
                .sorted { $0.uuidString < $1.uuidString }
            var results: [HeadlessGroupMaintenanceReportV2] = []
            results.reserveCapacity(groupIDs.count)
            for groupID in groupIDs {
                results.append(try await client.maintainGroup(groupID: groupID))
            }
            let reports = results.map(GroupMaintenanceStatusOutput.init)
            try writeJSON(reports)
            if reports.contains(where: \.requiresFollowUp) {
                try requireCompleteGroupEffect(
                    false,
                    disposition: combinedMaintenanceDisposition(results),
                    operation: "one or more group maintenance operations"
                )
            }
            return
        }
        guard options.value("--all") == nil else {
            throw CLIError("`--all` must be true when supplied.")
        }
        let result = try await client.maintainGroup(
            groupID: try uuidOption(options, "--group")
        )
        try writeJSON(GroupMaintenanceStatusOutput(result))
        if result.requiresFollowUp {
            try requireCompleteGroupEffect(
                false,
                disposition: maintenanceDisposition(result),
                operation: "group maintenance"
            )
        }
    }

    private func resumeGroupOperation(_ options: ParsedOptions) async throws {
        try options.requireOnly([
            "--group", "--operation", "--state", "--plaintext"
        ])
        let result = try await headlessClient(options).resumeGroupTransport(
            groupID: try uuidOption(options, "--group"),
            operationID: try uuidOption(options, "--operation")
        )
        try writeJSON(result)
        try requireCompleteGroupEffect(
            result.complete,
            disposition: result.disposition,
            operation: "group transport resume"
        )
    }

    private func requireCompleteGroupEffect(
        _ complete: Bool,
        disposition: HeadlessGroupTransportDispositionV2,
        operation: String
    ) throws {
        guard !complete else { return }
        let exitCode: Int
        switch disposition {
        case .complete, .pendingRetry:
            exitCode = 75 // EX_TEMPFAIL
        case .authorizationRecoveryRequired:
            exitCode = 77 // EX_NOPERM
        case .relayRejected:
            exitCode = 69 // EX_UNAVAILABLE
        case .invalidRelayResponse:
            exitCode = 76 // EX_PROTOCOL
        }
        throw CLIError(
            "The \(operation) is durably recorded but incomplete (\(disposition.rawValue)); run the corresponding maintain or resume command.",
            exitCode: exitCode
        )
    }

    private func maintenanceDisposition(
        _ report: HeadlessGroupMaintenanceReportV2
    ) -> HeadlessGroupTransportDispositionV2 {
        if report.resumedReceiveRoute?.announcementComplete == false {
            return .pendingRetry
        }
        return strongestGroupDisposition(
            report.transportResults.filter { !$0.complete }.map(\.disposition)
        )
    }

    private func combinedMaintenanceDisposition(
        _ reports: [HeadlessGroupMaintenanceReportV2]
    ) -> HeadlessGroupTransportDispositionV2 {
        let routePending = reports.contains {
            $0.resumedReceiveRoute?.announcementComplete == false
        }
        let dispositions = reports.flatMap {
            $0.transportResults.filter { !$0.complete }.map(\.disposition)
        }
        if routePending, dispositions.isEmpty { return .pendingRetry }
        return strongestGroupDisposition(dispositions)
    }

    private func strongestGroupDisposition(
        _ dispositions: [HeadlessGroupTransportDispositionV2]
    ) -> HeadlessGroupTransportDispositionV2 {
        if dispositions.contains(.authorizationRecoveryRequired) {
            return .authorizationRecoveryRequired
        }
        if dispositions.contains(.invalidRelayResponse) {
            return .invalidRelayResponse
        }
        if dispositions.contains(.relayRejected) { return .relayRejected }
        return .pendingRetry
    }

    /// Produces a short-lived, one-use request that must be transferred over
    /// an already authenticated and encrypted channel chosen by the operator.
    /// This local artifact is not an account, device invitation, or identity.
    private func makeGroupInvitationRequest(_ options: ParsedOptions) async throws {
        try options.requireOnly([
            "--group", "--out", "--lifetime", "--state", "--plaintext"
        ])
        let lifetime = try options.int("--lifetime") ?? 3_600
        guard (60...43_200).contains(lifetime) else {
            throw CLIError("Group invitation lifetime must be between 60 and 43200 seconds.")
        }
        let groupID = try uuidOption(options, "--group")
        let client = try await headlessClient(options)
        let runtime = try await client.openGroupRuntime(groupID: groupID)
        let snapshot = await runtime.snapshot()
        guard let localRole = snapshot.signedState.members.first(where: {
            $0.id == snapshot.localCredential.memberHandle && $0.removedEpoch == nil
        })?.role,
              snapshot.signedState.permissions.allows(
                  .manageInvitations,
                  for: localRole
              ) else {
            throw CLIError("The local group credential cannot manage invitations.")
        }
        guard snapshot.deletionState == nil,
              snapshot.localRemoval == nil,
              let stateDigest = snapshot.signedState.digest else {
            throw CLIError("The group cannot issue an invitation in its current state.")
        }
        let issuedAt = pairingTimestamp()
        let invitation = try GroupAdmissionInvitationFile.create(
            groupID: groupID,
            baseEpoch: snapshot.signedState.epoch,
            baseStateDigest: stateDigest,
            issuedAt: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(TimeInterval(lifetime))
        )
        let path = try required(options, "--out")
        try validateSensitiveOutputPath(path, options: options)
        try writeSensitiveJSON(invitation, to: path)
        try writeJSON(GroupInvitationRequestOutput(
            groupID: groupID,
            requestID: invitation.requestID,
            invitationFile: path,
            expiresAt: invitation.expiresAt,
            transferRequirement: GroupArtifactTransferRequirement.authenticatedEncryptedChannel
        ))
    }

    private func prepareGroupAdmissionResponse(_ options: ParsedOptions) async throws {
        try options.requireOnly([
            "--invitation-file", "--relay", "--response-out", "--state", "--plaintext"
        ])
        try validateSensitiveOutputPath(
            try required(options, "--response-out"),
            options: options,
            distinctFrom: [try required(options, "--invitation-file")]
        )
        let invitation = try readCurrentGroupInvitation(options)
        let client = try await headlessClient(options)
        let prepared = try await client.prepareGroupAdmission(
            groupID: invitation.groupID,
            invitationBindingDigest: invitation.invitationBindingDigest,
            relay: try endpoint(options),
            expiresAt: invitation.expiresAt,
            createdAt: pairingTimestamp()
        )
        let route = try await client.resumeGroupAdmissionRoute(
            admissionID: prepared.admissionID,
            at: pairingTimestamp()
        )
        try writeGroupAdmissionResponse(
            invitation: invitation,
            admissionID: prepared.admissionID,
            route: route,
            options: options
        )
    }

    private func resumeGroupAdmissionResponse(_ options: ParsedOptions) async throws {
        try options.requireOnly([
            "--admission", "--invitation-file", "--response-out", "--state", "--plaintext"
        ])
        try validateSensitiveOutputPath(
            try required(options, "--response-out"),
            options: options,
            distinctFrom: [try required(options, "--invitation-file")]
        )
        let invitation = try readCurrentGroupInvitation(options)
        let admissionID = try uuidOption(options, "--admission")
        let client = try await headlessClient(options)
        let pending = try await pendingGroupAdmission(
            admissionID,
            invitation: invitation,
            client: client
        )
        guard pending.activeRoute == nil || pending.advertisedRouteSet != nil else {
            throw CLIError("The saved admission route is inconsistent.")
        }
        let route = try await client.resumeGroupAdmissionRoute(
            admissionID: admissionID,
            at: pairingTimestamp()
        )
        try writeGroupAdmissionResponse(
            invitation: invitation,
            admissionID: admissionID,
            route: route,
            options: options
        )
    }

    private func listPendingGroupAdmissions(_ options: ParsedOptions) async throws {
        try options.requireOnly(["--state", "--plaintext"])
        let client = try await headlessClient(options)
        try writeJSON(await client.pendingGroupAdmissionProgress().sorted {
            $0.admissionID.uuidString < $1.admissionID.uuidString
        })
    }

    private func addGroupMember(_ options: ParsedOptions) async throws {
        try options.requireOnly([
            "--group", "--invitation-file", "--response-file", "--join-out",
            "--role", "--state", "--plaintext"
        ])
        try validateSensitiveOutputPath(
            try required(options, "--join-out"),
            options: options,
            distinctFrom: [
                try required(options, "--invitation-file"),
                try required(options, "--response-file"),
            ]
        )
        let groupID = try uuidOption(options, "--group")
        let invitation = try readSensitiveJSON(
            GroupAdmissionInvitationFile.self,
            from: try required(options, "--invitation-file")
        )
        try requireCurrent(invitation)
        guard invitation.groupID == groupID else {
            throw CLIError("The invitation request is for a different group.")
        }
        let response = try readSensitiveJSON(
            GroupAdmissionResponseFile.self,
            from: try required(options, "--response-file")
        )
        guard response.matches(invitation) else {
            throw CLIError("The admission response is not bound to this invitation request.")
        }
        let roleRaw = options.value("--role") ?? GroupRole.member.rawValue
        guard let role = GroupRole(rawValue: roleRaw), role != .owner else {
            throw CLIError("A new group member role must be `member` or `admin`.")
        }
        let client = try await headlessClient(options)
        let runtime = try await client.openGroupRuntime(groupID: groupID)
        let snapshot = await runtime.snapshot()
        guard snapshot.signedState.epoch == invitation.baseEpoch,
              snapshot.signedState.digest == invitation.baseStateDigest else {
            throw CLIError("The invitation base state is stale; issue a fresh invitation request.")
        }
        let prepared = try await client.prepareGroupMemberAddition(
            groupID: groupID,
            admission: response.admission,
            initialRouteSet: response.routeSet,
            role: role,
            anchorExpiresAt: invitation.expiresAt,
            idempotencyKey: try groupArtifactDigest(GroupIdempotencyPayload(
                domain: "noctweave.cli.group-add-member.v1",
                bindingDigest: response.responseBindingDigest
            )),
            createdAt: pairingTimestamp()
        )
        let package = try GroupJoinPackageFile.create(
            invitation: invitation,
            prepared: prepared
        )
        let outputPath = try required(options, "--join-out")
        // Install the exact recovery artifact before attempting relay delivery.
        try writeSensitiveJSON(package, to: outputPath)
        let transport: HeadlessGroupTransportResumeResultV2?
        if let operation = prepared.transportOperation {
            transport = try await client.resumeGroupTransport(
                groupID: groupID,
                operationID: operation.id
            )
        } else {
            transport = nil
        }
        try writeJSON(GroupMemberAdditionOutput(
            groupID: groupID,
            requestID: invitation.requestID,
            joinFile: outputPath,
            operationID: prepared.transportOperation?.id,
            transportComplete: transport?.complete ?? prepared.complete,
            disposition: transport?.disposition
                ?? (prepared.complete ? .complete : .pendingRetry),
            transferRequirement: GroupArtifactTransferRequirement.authenticatedEncryptedChannel
        ))
        try requireCompleteGroupEffect(
            transport?.complete ?? prepared.complete,
            disposition: transport?.disposition
                ?? (prepared.complete ? .complete : .pendingRetry),
            operation: "group member-addition publication"
        )
    }

    private func acceptGroupJoin(_ options: ParsedOptions) async throws {
        try options.requireOnly([
            "--admission", "--join-file", "--state", "--plaintext"
        ])
        let admissionID = try uuidOption(options, "--admission")
        let package = try readSensitiveJSON(
            GroupJoinPackageFile.self,
            from: try required(options, "--join-file")
        )
        try requireCurrent(package)
        let client = try await headlessClient(options)
        let persona = await client.activePersona()
        if let existing = persona.groupRuntimes.first(where: {
            $0.groupId == package.groupID
                && $0.originJoinAnchorID == package.anchor.id
                && $0.localCredential.credentialHandle
                    == package.anchor.destinationCredentialHandle
                && $0.localCredential.memberHandle
                    == package.anchor.destinationMemberHandle
        }) {
            try writeJSON(GroupJoinAcceptanceOutput(
                groupID: existing.groupId,
                admissionID: nil,
                joined: true,
                alreadyJoined: true,
                routeAnnouncementComplete: existing.inboundTransport
                    .pendingRouteAnnouncementID == nil
            ))
            try requireCompleteGroupEffect(
                existing.inboundTransport.pendingRouteAnnouncementID == nil,
                disposition: .pendingRetry,
                operation: "joined group route announcement"
            )
            return
        }
        let pending = try await pendingGroupAdmission(
            admissionID,
            groupID: package.groupID,
            bindingDigest: package.invitationBindingDigest,
            client: client
        )
        guard pending.admission.credentialHandle
                == package.anchor.destinationCredentialHandle,
              pending.admission.memberHandle == package.anchor.destinationMemberHandle else {
            throw CLIError("The join package targets a different saved group admission.")
        }
        _ = try await client.pinGroupJoinAnchor(
            admissionID: admissionID,
            anchor: package.anchor,
            invitationBindingDigest: package.invitationBindingDigest,
            observedAt: pairingTimestamp()
        )
        for announcement in package.existingMemberRouteAnnouncements {
            _ = try await client.acceptGroupAdmissionRouteAnnouncement(
                admissionID: admissionID,
                announcement: announcement,
                observedAt: pairingTimestamp()
            )
        }
        _ = try await client.acceptGroupAdmissionTransition(
            admissionID: admissionID,
            transition: package.transition,
            observedAt: pairingTimestamp()
        )
        let completed = try await client.acceptGroupAdmissionWelcome(
            admissionID: admissionID,
            welcome: package.welcome,
            observedAt: pairingTimestamp()
        )
        guard completed.completed else {
            throw CLIError("The join package was accepted but admission is still incomplete.")
        }
        let maintenance = try await client.maintainGroup(groupID: package.groupID)
        try writeJSON(GroupJoinAcceptanceOutput(
            groupID: package.groupID,
            admissionID: admissionID,
            joined: true,
            alreadyJoined: false,
            routeAnnouncementComplete: !maintenance.requiresFollowUp
        ))
        try requireCompleteGroupEffect(
            !maintenance.requiresFollowUp,
            disposition: maintenanceDisposition(maintenance),
            operation: "joined group route announcement"
        )
    }

    private func deleteGroup(_ options: ParsedOptions) async throws {
        try options.requireOnly([
            "--group", "--confirm", "--reason-file", "--state", "--plaintext"
        ])
        let groupID = try uuidOption(options, "--group")
        let reasonDigest: Data?
        if let reasonPath = options.value("--reason-file") {
            reasonDigest = try groupArtifactDigest(GroupDeletionReasonPayload(
                domain: "noctweave.cli.group-deletion-reason.v1",
                reason: readSensitiveText(from: reasonPath)
            ))
        } else {
            reasonDigest = nil
        }
        let client = try await headlessClient(options)
        let runtime = try await client.openGroupRuntime(groupID: groupID)
        let snapshot = await runtime.snapshot()
        guard let stateDigest = snapshot.signedState.digest else {
            throw CLIError("The current group state cannot be authenticated.")
        }
        let expectedConfirmation = "DELETE-GROUP:\(groupID.uuidString.lowercased()):\(shortHex(stateDigest))"
        guard options.value("--confirm") == expectedConfirmation else {
            throw CLIError(
                "Group deletion requires `--confirm \(expectedConfirmation)` for the current authenticated state."
            )
        }
        let prepared = try await client.prepareGroupDeletion(
            groupID: groupID,
            reasonDigest: reasonDigest,
            idempotencyKey: try groupArtifactDigest(GroupDeletionIdempotencyPayload(
                domain: "noctweave.cli.group-delete.v1",
                groupID: groupID,
                stateDigest: stateDigest,
                reasonDigest: reasonDigest
            )),
            createdAt: pairingTimestamp()
        )
        let transport: HeadlessGroupTransportResumeResultV2?
        if let operation = prepared.transportOperation {
            transport = try await client.resumeGroupTransport(
                groupID: groupID,
                operationID: operation.id
            )
        } else {
            transport = nil
        }
        try writeJSON(GroupDeletionOutput(
            groupID: groupID,
            tombstoneID: prepared.tombstone.id,
            operationID: prepared.transportOperation?.id,
            complete: transport?.complete ?? prepared.complete,
            disposition: transport?.disposition
                ?? (prepared.complete ? .complete : .pendingRetry)
        ))
        try requireCompleteGroupEffect(
            transport?.complete ?? prepared.complete,
            disposition: transport?.disposition
                ?? (prepared.complete ? .complete : .pendingRetry),
            operation: "group deletion publication"
        )
    }

    private func readCurrentGroupInvitation(
        _ options: ParsedOptions
    ) throws -> GroupAdmissionInvitationFile {
        let invitation = try readSensitiveJSON(
            GroupAdmissionInvitationFile.self,
            from: try required(options, "--invitation-file")
        )
        try requireCurrent(invitation)
        return invitation
    }

    private func requireCurrent(_ invitation: GroupAdmissionInvitationFile) throws {
        let now = Date()
        guard invitation.issuedAt.addingTimeInterval(-300) <= now,
              now < invitation.expiresAt else {
            throw CLIError("The group invitation request is not currently valid.")
        }
    }

    private func requireCurrent(_ package: GroupJoinPackageFile) throws {
        let now = Date()
        guard package.anchor.issuedAt.addingTimeInterval(-300) <= now,
              now < package.anchor.expiresAt else {
            throw CLIError("The group join package is not currently valid.")
        }
    }

    private func pendingGroupAdmission(
        _ admissionID: UUID,
        invitation: GroupAdmissionInvitationFile,
        client: HeadlessMessagingClient
    ) async throws -> PendingGroupAdmissionV2 {
        try await pendingGroupAdmission(
            admissionID,
            groupID: invitation.groupID,
            bindingDigest: invitation.invitationBindingDigest,
            client: client
        )
    }

    private func pendingGroupAdmission(
        _ admissionID: UUID,
        groupID: UUID,
        bindingDigest: Data,
        client: HeadlessMessagingClient
    ) async throws -> PendingGroupAdmissionV2 {
        let persona = await client.activePersona()
        guard let pending = persona.pendingGroupAdmissions.first(where: {
            $0.id == admissionID
        }) else {
            throw CLIError("The saved group admission was not found.")
        }
        guard pending.groupID == groupID,
              pending.invitationBindingDigest == bindingDigest else {
            throw CLIError("The saved group admission is bound to a different invitation.")
        }
        return pending
    }

    private func writeGroupAdmissionResponse(
        invitation: GroupAdmissionInvitationFile,
        admissionID: UUID,
        route: HeadlessGroupAdmissionRouteResultV2,
        options: ParsedOptions
    ) throws {
        guard route.groupID == invitation.groupID else {
            throw CLIError("The saved admission is for a different group.")
        }
        let response = try GroupAdmissionResponseFile.create(
            invitation: invitation,
            admission: route.admission,
            routeSet: route.routeSet
        )
        let path = try required(options, "--response-out")
        try writeSensitiveJSON(response, to: path)
        try writeJSON(GroupAdmissionResponseOutput(
            groupID: route.groupID,
            admissionID: admissionID,
            requestID: invitation.requestID,
            responseFile: path,
            transferRequirement: GroupArtifactTransferRequirement.authenticatedEncryptedChannel
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
        try validateSensitiveOutputPath(output, options: options)
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

    private func eraseLocalState(_ options: ParsedOptions) async throws {
        try options.requireOnly(["--confirm", "--state", "--plaintext"])
        let stateURL = try stateFileURL(options)
        let expectedConfirmation = "ERASE:\(shortSHA256Hex(Data(stateURL.path.utf8)))"
        guard options.value("--confirm") == expectedConfirmation else {
            throw CLIError(
                "Local-state erasure requires `--confirm \(expectedConfirmation)` for this canonical state path."
            )
        }
        let store = try stateStore(options)
        // Deliberately do not load or decode state first. Encrypted stores
        // advance their independent, identity-free erasure tombstone.
        try await store.eraseAllLocalState()
        try writeJSON(LocalStateErasureOutput(
            erased: true,
            scope: "local-database-only",
            distinction: "burn-persona keeps the database and replaces only its active local persona"
        ))
    }

    private func headlessClient(_ options: ParsedOptions) async throws -> HeadlessMessagingClient {
        let store = try stateStore(options)
        guard let state = try await store.load() else {
            throw CLIError("No state exists. Run `NoctweaveCLI init` first.")
        }
        return try HeadlessMessagingClient(stateStore: store, initialState: state)
    }

    private func stateStore(_ options: ParsedOptions) throws -> ClientStateStore {
        let plaintext = try options.bool("--plaintext") ?? false
        return ClientStateStore(
            fileURL: try stateFileURL(options),
            protection: plaintext ? .insecurePlaintextForTesting : .encrypted
        )
    }

    private func stateFileURL(_ options: ParsedOptions) throws -> URL {
        if let path = options.value("--state") {
            return canonicalFileURL(path)
        }
        guard let applicationSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            throw CLIError("The local application-support directory is unavailable.")
        }
        return applicationSupport
            .appendingPathComponent("NoctweaveCLI", isDirectory: true)
            .appendingPathComponent("client-state.json", isDirectory: false)
            .standardizedFileURL
    }

    private func validateSensitiveOutputPath(
        _ path: String,
        options: ParsedOptions,
        distinctFrom otherPaths: [String] = []
    ) throws {
        let output = canonicalFileURL(path)
        let state = try stateFileURL(options)
        let reserved = [
            state,
            state.appendingPathExtension("pending"),
            state.appendingPathExtension("lock"),
        ] + otherPaths.map(canonicalFileURL)
        guard !reserved.contains(output) else {
            throw CLIError(
                "A sensitive output path must not replace local state, a state sidecar, or an input artifact."
            )
        }
    }

    private func canonicalFileURL(_ path: String) -> URL {
        let fileURL = URL(fileURLWithPath: path).standardizedFileURL
        if let physical = physicalPath(fileURL.path) {
            return URL(fileURLWithPath: physical, isDirectory: false)
        }
        let parent = fileURL.deletingLastPathComponent()
        if let physicalParent = physicalPath(parent.path) {
            return URL(fileURLWithPath: physicalParent, isDirectory: true)
                .appendingPathComponent(fileURL.lastPathComponent, isDirectory: false)
        }
        return fileURL
    }

    private func physicalPath(_ path: String) -> String? {
        guard let resolved = path.withCString({ realpath($0, nil) }) else {
            return nil
        }
        defer { free(resolved) }
        return String(cString: resolved)
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
        guard encoded.utf8.count == 44 else {
            throw CLIError("`--route-id` must be a base64-encoded 32-byte opaque route ID.")
        }
        guard let rawValue = Data(base64Encoded: encoded), rawValue.count == 32 else {
            throw CLIError("`--route-id` must be a base64-encoded 32-byte opaque route ID.")
        }
        return try NoctweaveCoder.decode(
            OpaqueReceiveRouteIDV2.self,
            from: NoctweaveCoder.encode(OpaqueRouteIDInput(rawValue: rawValue))
        )
    }

    private func shortSHA256Hex(_ data: Data) -> String {
        String(AttachmentBlobDigest.sha256Hex(data).prefix(16))
    }

    private func shortHex(_ data: Data) -> String {
        String(data.map { String(format: "%02x", $0) }.joined().prefix(16))
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
            data = try readBoundedRegularFile(
                at: String(raw.dropFirst()),
                maximumBytes: Self.maximumRawRequestBytes,
                allowEmpty: false,
                label: "Relay request"
            )
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
        var data = try readBoundedRegularFile(
            at: path,
            maximumBytes: 4_096,
            allowEmpty: false,
            label: "Relay authentication"
        )
        defer { data.wipeCLIOutputBuffer() }
        guard let decoded = String(data: data, encoding: .utf8) else {
            throw CLIError("Relay authentication file is not valid UTF-8 text.")
        }
        let value = decoded.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { throw CLIError("Relay authentication file is empty.") }
        return value
    }

    private func readSensitiveJSON<T: Decodable>(
        _ type: T.Type,
        from path: String
    ) throws -> T {
        var data = try readBoundedRegularFile(
            at: path,
            maximumBytes: Self.maximumSensitiveInputBytes,
            allowEmpty: false,
            label: "Sensitive input"
        )
        defer { data.wipeCLIOutputBuffer() }
        return try NoctweaveCoder.decode(type, from: data)
    }

    private func readSensitiveText(from path: String) throws -> String {
        var data = try readBoundedRegularFile(
            at: path,
            maximumBytes: Self.maximumSensitiveInputBytes,
            allowEmpty: false,
            label: "Sensitive input"
        )
        defer { data.wipeCLIOutputBuffer() }
        guard let value = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines),
              !value.isEmpty else {
            throw CLIError("Sensitive input file is not valid UTF-8 text.")
        }
        return value
    }

    private func readPrivateMessageText(from path: String) throws -> String {
        var data = try readBoundedRegularFile(
            at: path,
            maximumBytes: Self.maximumSensitiveInputBytes,
            allowEmpty: false,
            label: "Message input"
        )
        defer { data.wipeCLIOutputBuffer() }
        guard let value = String(data: data, encoding: .utf8), !value.isEmpty else {
            throw CLIError("Message input file is not valid non-empty UTF-8 text.")
        }
        return value
    }

    /// Opens the final component with O_NOFOLLOW and reads only a regular file
    /// through that descriptor. Both the descriptor size and the bytes actually
    /// read are bounded, so FIFO, symlink, growth, and stat/read races fail closed.
    private func readBoundedRegularFile(
        at path: String,
        maximumBytes: Int,
        allowEmpty: Bool,
        label: String
    ) throws -> Data {
        let location = try openSecureParentDirectory(for: path, label: label)
        defer { _ = close(location.directoryDescriptor) }
        let descriptor = location.name.withCString { name in
            openat(
                location.directoryDescriptor,
                name,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
            )
        }
        guard descriptor >= 0 else {
            throw CLIError("\(label) file could not be opened as a non-symlink.")
        }
        defer { _ = close(descriptor) }
        return try readBoundedRegularDescriptor(
            descriptor,
            maximumBytes: maximumBytes,
            allowEmpty: allowEmpty,
            requirePrivateMode: false,
            label: label
        )
    }

    private func readBoundedRegularDescriptor(
        _ descriptor: Int32,
        maximumBytes: Int,
        allowEmpty: Bool,
        requirePrivateMode: Bool,
        label: String
    ) throws -> Data {
        var before = stat()
        guard fstat(descriptor, &before) == 0,
              (before.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              before.st_size >= 0,
              UInt64(before.st_size) <= UInt64(maximumBytes) else {
            throw CLIError("\(label) must be a bounded regular file.")
        }
        if requirePrivateMode {
            guard before.st_uid == geteuid(),
                  (before.st_mode & mode_t(0o777)) == mode_t(0o600) else {
                throw CLIError("\(label) must be owned by this user with mode 0600.")
            }
        }

        var data = Data()
        data.reserveCapacity(Int(before.st_size))
        var buffer = [UInt8](
            repeating: 0,
            count: min(64 * 1_024, maximumBytes + 1)
        )
        defer { buffer.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            memset(base, 0, raw.count)
        } }

        while true {
            let remaining = maximumBytes + 1 - data.count
            guard remaining > 0 else {
                throw CLIError("\(label) exceeds the size limit.")
            }
            let requested = min(buffer.count, remaining)
            let count = buffer.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return 0 }
                return read(descriptor, base, requested)
            }
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else {
                throw CLIError("\(label) could not be read.")
            }
            if count == 0 { break }
            data.append(contentsOf: buffer[0..<count])
            guard data.count <= maximumBytes else {
                throw CLIError("\(label) exceeds the size limit.")
            }
        }

        var after = stat()
        guard fstat(descriptor, &after) == 0,
              after.st_size == before.st_size,
              data.count == Int(after.st_size),
              allowEmpty || !data.isEmpty else {
            throw CLIError("\(label) changed while being read or is empty.")
        }
        return data
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
        guard !data.isEmpty, data.count <= Self.maximumSensitiveInputBytes else {
            throw CLIError("Sensitive output is empty or exceeds the size limit.")
        }
        let location = try openSecureParentDirectory(
            for: path,
            label: "Sensitive output"
        )
        defer { _ = close(location.directoryDescriptor) }

        if try requireExistingSensitiveOutputMatches(
            data,
            directoryDescriptor: location.directoryDescriptor,
            name: location.name
        ) {
            return
        }

        let temporaryName = ".\(location.name).\(UUID().uuidString.lowercased()).tmp"
        let descriptor = temporaryName.withCString { temporaryPath in
            openat(
                location.directoryDescriptor,
                temporaryPath,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                mode_t(0o600)
            )
        }
        guard descriptor >= 0 else {
            throw CLIError("Could not create the private output file.")
        }
        var descriptorIsOpen = true
        var temporaryExists = true
        defer {
            if descriptorIsOpen { _ = close(descriptor) }
            if temporaryExists {
                temporaryName.withCString {
                    _ = unlinkat(location.directoryDescriptor, $0, 0)
                }
            }
        }
        guard fchmod(descriptor, mode_t(0o600)) == 0 else {
            throw CLIError("Could not secure the private output file permissions.")
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
        guard fsync(descriptor) == 0 else {
            throw CLIError("Could not durably flush the private output file.")
        }
        let closeResult = close(descriptor)
        descriptorIsOpen = false
        guard closeResult == 0 else {
            throw CLIError("Could not durably close the private output file.")
        }

        let linkResult = temporaryName.withCString { temporaryPath in
            location.name.withCString { destinationName in
                linkat(
                    location.directoryDescriptor,
                    temporaryPath,
                    location.directoryDescriptor,
                    destinationName,
                    0
                )
            }
        }
        if linkResult != 0, errno == EEXIST {
            guard try requireExistingSensitiveOutputMatches(
                data,
                directoryDescriptor: location.directoryDescriptor,
                name: location.name
            ) else {
                throw CLIError("The private output destination raced with another writer.")
            }
        } else if linkResult != 0 {
            throw CLIError(
                "Could not atomically install the private output file without replacing data."
            )
        }

        let unlinkResult = temporaryName.withCString {
            unlinkat(location.directoryDescriptor, $0, 0)
        }
        guard unlinkResult == 0 else {
            throw CLIError(
                "The private output was installed but its temporary link could not be removed."
            )
        }
        temporaryExists = false
        guard fsync(location.directoryDescriptor) == 0 else {
            throw CLIError("Could not durably synchronize the private output directory.")
        }
    }

    /// Returns true only when an already-present destination is the exact
    /// private artifact being retried. It never replaces unrelated bytes.
    private func requireExistingSensitiveOutputMatches(
        _ expected: Data,
        directoryDescriptor: Int32,
        name: String
    ) throws -> Bool {
        let descriptor = name.withCString {
            openat(
                directoryDescriptor,
                $0,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
            )
        }
        if descriptor < 0, errno == ENOENT { return false }
        guard descriptor >= 0 else {
            throw CLIError(
                "The private output destination is a symlink or cannot be safely opened."
            )
        }
        defer { _ = close(descriptor) }
        var existing = try readBoundedRegularDescriptor(
            descriptor,
            maximumBytes: Self.maximumSensitiveInputBytes,
            allowEmpty: false,
            requirePrivateMode: true,
            label: "Existing sensitive output"
        )
        defer { existing.wipeCLIOutputBuffer() }
        guard existing == expected else {
            throw CLIError(
                "The private output destination already exists with different content; choose another path."
            )
        }
        return true
    }

    /// Resolves the parent once, then walks the physical absolute path with
    /// O_NOFOLLOW directory descriptors. The final component is used only via
    /// openat/linkat, keeping path replacement out of the check/use window.
    private func openSecureParentDirectory(
        for path: String,
        label: String
    ) throws -> (directoryDescriptor: Int32, name: String) {
        let fileURL = URL(fileURLWithPath: path).standardizedFileURL
        let name = fileURL.lastPathComponent
        guard !name.isEmpty, name != ".", name != ".." else {
            throw CLIError("\(label) path must name a file.")
        }
        let parentPath = fileURL.deletingLastPathComponent().path
        let resolvedParent = parentPath.withCString { realpath($0, nil) }
        guard let resolvedParent else {
            throw CLIError("\(label) parent directory does not exist.")
        }
        defer { free(resolvedParent) }
        // Avoid Foundation's macOS firmlink normalization here: it can map
        // `/private/tmp` back to the `/tmp` symlink after realpath resolved it.
        let components = String(cString: resolvedParent)
            .split(separator: "/", omittingEmptySubsequences: true)
            .map(String.init)
        var descriptor = "/".withCString {
            open($0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw CLIError("\(label) parent directory could not be opened.")
        }
        for component in components {
            let next = component.withCString {
                openat(
                    descriptor,
                    $0,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
                )
            }
            guard next >= 0 else {
                let failure = String(cString: strerror(errno))
                _ = close(descriptor)
                throw CLIError(
                    "\(label) parent directory component `\(component)` could not be safely opened: \(failure)."
                )
            }
            _ = close(descriptor)
            descriptor = next
        }
        return (descriptor, name)
    }

    private func printHelp() {
        FileHandle.standardOutput.writeLine("""
        NoctweaveCLI — pairwise-private Noctweave 1.0 architecture

          init --display-name <local-label> --accept-privacy-policy true --accept-terms-of-use true [--relay <url|host:port>] [--relay-name <local-label>] [--state path] [--plaintext true]
          status [--state path] [--plaintext true]
          attachment-download-prepare --relationship <uuid> --descriptor-file <private-file> --relay <url|host:port> --out <private-file>
          attachment-download-fetch --relationship <uuid> --download <uuid> --out <private-file>
          relationships [--state path] [--plaintext true]
          groups [--state path] [--plaintext true]
          group-status --group <uuid>
          prepare-participant --relay <https|wss|tls URL> --out <private-file> [--relationship-pseudonym label]
          pairing-invitation --offer-out <private-file> --invitation-out <share-file> [--lifetime seconds]
          pair-offer --offer-file <private-file> --participant-file <private-file> --relay <URL> [--wait-seconds n] [--poll-ms n]
          pair-accept --invitation-file <share-file> --participant-file <private-file> --relay <URL> [--wait-seconds n] [--poll-ms n]
          send --relationship <uuid> --text-file <private-file>
          sync --relationship <uuid> [--max packets]
          maintain (--all true | --relationship <uuid>)
          group-create --group <stable-retry-uuid> --relay <url|host:port>
          group-send --group <uuid> --text-file <private-file>
          group-sync --group <uuid> [--max packets-per-route] [--pages 1...64]
          group-maintain (--all true | --group <uuid>)
          group-resume --group <uuid> --operation <uuid>
          group-invite-request --group <uuid> --out <private-file> [--lifetime seconds]
          group-admission-prepare --invitation-file <private-file> --relay <url|host:port> --response-out <private-file>
          group-admission-resume --admission <uuid> --invitation-file <private-file> --response-out <private-file>
          group-admissions
          group-add-member --group <uuid> --invitation-file <private-file> --response-file <private-file> --join-out <private-file> [--role member|admin]
          group-join-accept --admission <uuid> --join-file <private-file>
          group-delete --group <uuid> --confirm DELETE-GROUP:<uuid>:<state-hash> [--reason-file <private-file>]
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
          erase-local-state --confirm ERASE:<canonical-state-path-hash>
          endpoint --relay <url|host:port>
          health --relay <url|host:port> [--auth-file path] [--timeout seconds]
          info --relay <url|host:port> [--auth-file path] [--timeout seconds]
          raw --relay <url|host:port> --request '<json|@path>'

        Personas are local containers. Pairing creates independent, unlinkable
        relationship identities and opaque relay routes. Group commands mint
        separate group-only credentials and never promote a persona or pairwise
        key into group authority. Personas never become
        network identifiers. `pair-offer` and `pair-accept` are live commands;
        if either process is interrupted, let the opaque rendezvous expire and
        create a fresh invitation instead of exporting live session keys. Files
        containing private or bearer material are bounded, atomically installed
        without clobbering unrelated files, durably directory-synchronized with
        mode 0600, and never emitted directly to standard output. An identical
        existing artifact is accepted only as an idempotent retry. Group
        invitation, admission-response, and join-package files must travel only
        over an independently authenticated and encrypted channel; they do not
        establish persona, account, device, or cross-group authority. Message
        plaintext is read from a file so it does not appear in process arguments.
        `--plaintext true` is an insecure test-only state-store mode. `burn-persona`
        keeps the local database while replacing one local persona. Destructive
        group/local-state commands print their exact target-bound confirmation
        token when the supplied value is absent or stale. `erase-local-state`
        intentionally erases the entire local database.
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

private enum GroupArtifactTransferRequirement: String, Codable {
    case authenticatedEncryptedChannel = "manual-authenticated-encrypted-channel"
}

private struct GroupInvitationRequestOutput: Codable {
    let groupID: UUID
    let requestID: UUID
    let invitationFile: String
    let expiresAt: Date
    let transferRequirement: GroupArtifactTransferRequirement
}

private struct GroupAdmissionResponseOutput: Codable {
    let groupID: UUID
    let admissionID: UUID
    let requestID: UUID
    let responseFile: String
    let transferRequirement: GroupArtifactTransferRequirement
}

private struct GroupMemberAdditionOutput: Codable {
    let groupID: UUID
    let requestID: UUID
    let joinFile: String
    let operationID: UUID?
    let transportComplete: Bool
    let disposition: HeadlessGroupTransportDispositionV2
    let transferRequirement: GroupArtifactTransferRequirement
}

private struct GroupJoinAcceptanceOutput: Codable {
    let groupID: UUID
    /// Present only when this invocation authenticated a saved admission.
    /// A replay against an already-installed group must not echo an arbitrary
    /// caller-supplied admission identifier as if it had been verified.
    let admissionID: UUID?
    let joined: Bool
    let alreadyJoined: Bool
    let routeAnnouncementComplete: Bool
}

private struct GroupDeletionOutput: Codable {
    let groupID: UUID
    let tombstoneID: UUID
    let operationID: UUID?
    let complete: Bool
    let disposition: HeadlessGroupTransportDispositionV2
}

private struct LocalStateErasureOutput: Codable {
    let erased: Bool
    let scope: String
    let distinction: String
}

private struct GroupStatusOutput: Codable {
    let groupID: UUID
    let epoch: UInt64
    let localMemberHandle: GroupScopedMemberHandleV2
    let localCredentialHandle: GroupScopedCredentialHandleV2
    let localRole: GroupRole?
    let memberCount: Int
    let activeCredentialCount: Int
    let eventCount: Int
    let pendingApplicationCount: Int
    let incompleteTransportCount: Int
    let activeReceiveRouteCount: Int
    let receiveRoutePending: Bool
    let peerRouteCount: Int
    let transportQuarantineCount: Int
    let epochForkQuarantineCount: Int
    let locallyRemoved: Bool
    let deleted: Bool

    init(_ group: GroupRuntimeRecord) {
        groupID = group.groupId
        epoch = group.signedState.epoch
        localMemberHandle = group.localCredential.memberHandle
        localCredentialHandle = group.localCredential.credentialHandle
        localRole = group.signedState.members.first {
            $0.id == group.localCredential.memberHandle && $0.removedEpoch == nil
        }?.role
        memberCount = group.signedState.members.filter { $0.removedEpoch == nil }.count
        activeCredentialCount = group.signedState.activeCredentials.count
        eventCount = group.events.count
        pendingApplicationCount = group.pendingApplicationPublications.count
        incompleteTransportCount = group.outboundTransportOperations.filter {
            !$0.isComplete
        }.count
        activeReceiveRouteCount = group.inboundTransport.localRoutes.filter {
            $0.advertisedState == .active || $0.advertisedState == .draining
        }.count
        receiveRoutePending = group.inboundTransport.pendingRoute != nil
        peerRouteCount = group.peerRouteCache.entries.count
        transportQuarantineCount = group.inboundTransport.quarantines.count
        epochForkQuarantineCount = group.quarantinedForks.count
            + group.peerForkQuarantines.count
        locallyRemoved = group.localRemoval != nil
        deleted = group.deletionState != nil
    }
}

/// Strict local handoff artifact. It derives a one-use binding digest from
/// the exact invitation fields; it is not self-authenticating and therefore
/// must remain inside the caller's authenticated, encrypted transfer channel.
private struct GroupAdmissionInvitationFile: Codable {
    static let currentVersion = 1

    let version: Int
    let requestID: UUID
    let groupID: UUID
    let baseEpoch: UInt64
    let baseStateDigest: Data
    let invitationBindingDigest: Data
    let issuedAt: Date
    let expiresAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case requestID
        case groupID
        case baseEpoch
        case baseStateDigest
        case invitationBindingDigest
        case issuedAt
        case expiresAt
    }

    private init(
        version: Int,
        requestID: UUID,
        groupID: UUID,
        baseEpoch: UInt64,
        baseStateDigest: Data,
        invitationBindingDigest: Data,
        issuedAt: Date,
        expiresAt: Date
    ) {
        self.version = version
        self.requestID = requestID
        self.groupID = groupID
        self.baseEpoch = baseEpoch
        self.baseStateDigest = baseStateDigest
        self.invitationBindingDigest = invitationBindingDigest
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
    }

    static func create(
        groupID: UUID,
        baseEpoch: UInt64,
        baseStateDigest: Data,
        issuedAt: Date,
        expiresAt: Date
    ) throws -> Self {
        let requestID = UUID()
        let binding = try groupArtifactDigest(GroupInvitationBindingPayload(
            domain: "noctweave.cli.group-admission-invitation.v1",
            version: currentVersion,
            requestID: requestID,
            groupID: groupID,
            baseEpoch: baseEpoch,
            baseStateDigest: baseStateDigest,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        ))
        return try Self(
            version: currentVersion,
            requestID: requestID,
            groupID: groupID,
            baseEpoch: baseEpoch,
            baseStateDigest: baseStateDigest,
            invitationBindingDigest: binding,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        ).validated()
    }

    init(from decoder: Decoder) throws {
        try requireExactGroupArtifactKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            requestID: try values.decode(UUID.self, forKey: .requestID),
            groupID: try values.decode(UUID.self, forKey: .groupID),
            baseEpoch: try values.decode(UInt64.self, forKey: .baseEpoch),
            baseStateDigest: try values.decode(Data.self, forKey: .baseStateDigest),
            invitationBindingDigest: try values.decode(
                Data.self,
                forKey: .invitationBindingDigest
            ),
            issuedAt: try values.decode(Date.self, forKey: .issuedAt),
            expiresAt: try values.decode(Date.self, forKey: .expiresAt)
        )
        _ = try validated(codingPath: decoder.codingPath)
    }

    private func validated(codingPath: [CodingKey] = []) throws -> Self {
        let expected = try groupArtifactDigest(GroupInvitationBindingPayload(
            domain: "noctweave.cli.group-admission-invitation.v1",
            version: version,
            requestID: requestID,
            groupID: groupID,
            baseEpoch: baseEpoch,
            baseStateDigest: baseStateDigest,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        ))
        guard version == Self.currentVersion,
              baseEpoch > 0,
              baseStateDigest.count == 32,
              invitationBindingDigest.count == 32,
              invitationBindingDigest == expected,
              issuedAt.timeIntervalSince1970.isFinite,
              expiresAt.timeIntervalSince1970.isFinite,
              issuedAt < expiresAt,
              expiresAt.timeIntervalSince(issuedAt) <= 43_200 else {
            throw groupArtifactDecodingError(
                codingPath: codingPath,
                description: "Invalid group admission invitation artifact"
            )
        }
        return self
    }
}

private struct GroupAdmissionResponseFile: Codable {
    static let currentVersion = 1

    let version: Int
    let requestID: UUID
    let groupID: UUID
    let invitationBindingDigest: Data
    let responseBindingDigest: Data
    let admission: GroupCredentialAdmissionV2
    let routeSet: SignedGroupOpaqueRouteSetV2

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case requestID
        case groupID
        case invitationBindingDigest
        case responseBindingDigest
        case admission
        case routeSet
    }

    private init(
        version: Int,
        requestID: UUID,
        groupID: UUID,
        invitationBindingDigest: Data,
        responseBindingDigest: Data,
        admission: GroupCredentialAdmissionV2,
        routeSet: SignedGroupOpaqueRouteSetV2
    ) {
        self.version = version
        self.requestID = requestID
        self.groupID = groupID
        self.invitationBindingDigest = invitationBindingDigest
        self.responseBindingDigest = responseBindingDigest
        self.admission = admission
        self.routeSet = routeSet
    }

    static func create(
        invitation: GroupAdmissionInvitationFile,
        admission: GroupCredentialAdmissionV2,
        routeSet: SignedGroupOpaqueRouteSetV2
    ) throws -> Self {
        let digest = try groupArtifactDigest(GroupAdmissionResponseBindingPayload(
            domain: "noctweave.cli.group-admission-response.v1",
            version: currentVersion,
            requestID: invitation.requestID,
            groupID: invitation.groupID,
            invitationBindingDigest: invitation.invitationBindingDigest,
            admission: admission,
            routeSet: routeSet
        ))
        return try Self(
            version: currentVersion,
            requestID: invitation.requestID,
            groupID: invitation.groupID,
            invitationBindingDigest: invitation.invitationBindingDigest,
            responseBindingDigest: digest,
            admission: admission,
            routeSet: routeSet
        ).validated()
    }

    init(from decoder: Decoder) throws {
        try requireExactGroupArtifactKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            requestID: try values.decode(UUID.self, forKey: .requestID),
            groupID: try values.decode(UUID.self, forKey: .groupID),
            invitationBindingDigest: try values.decode(
                Data.self,
                forKey: .invitationBindingDigest
            ),
            responseBindingDigest: try values.decode(
                Data.self,
                forKey: .responseBindingDigest
            ),
            admission: try values.decode(GroupCredentialAdmissionV2.self, forKey: .admission),
            routeSet: try values.decode(SignedGroupOpaqueRouteSetV2.self, forKey: .routeSet)
        )
        _ = try validated(codingPath: decoder.codingPath)
    }

    func matches(_ invitation: GroupAdmissionInvitationFile) -> Bool {
        requestID == invitation.requestID
            && groupID == invitation.groupID
            && invitationBindingDigest == invitation.invitationBindingDigest
    }

    private func validated(codingPath: [CodingKey] = []) throws -> Self {
        let expected = try groupArtifactDigest(GroupAdmissionResponseBindingPayload(
            domain: "noctweave.cli.group-admission-response.v1",
            version: version,
            requestID: requestID,
            groupID: groupID,
            invitationBindingDigest: invitationBindingDigest,
            admission: admission,
            routeSet: routeSet
        ))
        guard version == Self.currentVersion,
              invitationBindingDigest.count == 32,
              responseBindingDigest.count == 32,
              responseBindingDigest == expected,
              admission.groupId == groupID,
              admission.digest == routeSet.ownerAdmissionDigest,
              routeSet.groupID == groupID,
              routeSet.ownerCredentialHandle == admission.credentialHandle,
              routeSet.verify(ownerSigningPublicKey: admission.groupSigningPublicKey) else {
            throw groupArtifactDecodingError(
                codingPath: codingPath,
                description: "Invalid group admission response artifact"
            )
        }
        return self
    }
}

private struct GroupJoinPackageFile: Codable {
    static let currentVersion = 1

    let version: Int
    let requestID: UUID
    let groupID: UUID
    let invitationBindingDigest: Data
    let packageBindingDigest: Data
    let anchor: GroupJoinAnchorV2
    let transition: GroupEpochTransitionEnvelopeV2
    let welcome: SignedGroupWelcomeV2
    let existingMemberRouteAnnouncements: [SignedGroupRouteSetAnnouncementV2]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case requestID
        case groupID
        case invitationBindingDigest
        case packageBindingDigest
        case anchor
        case transition
        case welcome
        case existingMemberRouteAnnouncements
    }

    private init(
        version: Int,
        requestID: UUID,
        groupID: UUID,
        invitationBindingDigest: Data,
        packageBindingDigest: Data,
        anchor: GroupJoinAnchorV2,
        transition: GroupEpochTransitionEnvelopeV2,
        welcome: SignedGroupWelcomeV2,
        existingMemberRouteAnnouncements: [SignedGroupRouteSetAnnouncementV2]
    ) {
        self.version = version
        self.requestID = requestID
        self.groupID = groupID
        self.invitationBindingDigest = invitationBindingDigest
        self.packageBindingDigest = packageBindingDigest
        self.anchor = anchor
        self.transition = transition
        self.welcome = welcome
        self.existingMemberRouteAnnouncements = existingMemberRouteAnnouncements
    }

    static func create(
        invitation: GroupAdmissionInvitationFile,
        prepared: HeadlessPreparedGroupMemberAdditionV2
    ) throws -> Self {
        let digest = try groupArtifactDigest(GroupJoinPackageBindingPayload(
            domain: "noctweave.cli.group-join-package.v1",
            version: currentVersion,
            requestID: invitation.requestID,
            groupID: invitation.groupID,
            invitationBindingDigest: invitation.invitationBindingDigest,
            anchor: prepared.anchor,
            transition: prepared.transition,
            welcome: prepared.welcome,
            existingMemberRouteAnnouncements: prepared.existingMemberRouteAnnouncements
        ))
        return try Self(
            version: currentVersion,
            requestID: invitation.requestID,
            groupID: invitation.groupID,
            invitationBindingDigest: invitation.invitationBindingDigest,
            packageBindingDigest: digest,
            anchor: prepared.anchor,
            transition: prepared.transition,
            welcome: prepared.welcome,
            existingMemberRouteAnnouncements: prepared.existingMemberRouteAnnouncements
        ).validated()
    }

    init(from decoder: Decoder) throws {
        try requireExactGroupArtifactKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            requestID: try values.decode(UUID.self, forKey: .requestID),
            groupID: try values.decode(UUID.self, forKey: .groupID),
            invitationBindingDigest: try values.decode(
                Data.self,
                forKey: .invitationBindingDigest
            ),
            packageBindingDigest: try values.decode(Data.self, forKey: .packageBindingDigest),
            anchor: try values.decode(GroupJoinAnchorV2.self, forKey: .anchor),
            transition: try values.decode(
                GroupEpochTransitionEnvelopeV2.self,
                forKey: .transition
            ),
            welcome: try values.decode(SignedGroupWelcomeV2.self, forKey: .welcome),
            existingMemberRouteAnnouncements: try values.decode(
                [SignedGroupRouteSetAnnouncementV2].self,
                forKey: .existingMemberRouteAnnouncements
            )
        )
        _ = try validated(codingPath: decoder.codingPath)
    }

    private func validated(codingPath: [CodingKey] = []) throws -> Self {
        let expected = try groupArtifactDigest(GroupJoinPackageBindingPayload(
            domain: "noctweave.cli.group-join-package.v1",
            version: version,
            requestID: requestID,
            groupID: groupID,
            invitationBindingDigest: invitationBindingDigest,
            anchor: anchor,
            transition: transition,
            welcome: welcome,
            existingMemberRouteAnnouncements: existingMemberRouteAnnouncements
        ))
        guard version == Self.currentVersion,
              invitationBindingDigest.count == 32,
              packageBindingDigest.count == 32,
              packageBindingDigest == expected,
              anchor.baseState.groupId == groupID,
              transition.commit.groupId == groupID,
              transition.nextState.groupId == groupID,
              welcome.groupId == groupID,
              welcome.destinationCredentialHandle == anchor.destinationCredentialHandle,
              existingMemberRouteAnnouncements.allSatisfy({ $0.groupID == groupID }),
              Set(existingMemberRouteAnnouncements.map {
                  $0.routeSet.ownerCredentialHandle
              }).count == existingMemberRouteAnnouncements.count else {
            throw groupArtifactDecodingError(
                codingPath: codingPath,
                description: "Invalid group join package artifact"
            )
        }
        return self
    }
}

private struct GroupInvitationBindingPayload: Encodable {
    let domain: String
    let version: Int
    let requestID: UUID
    let groupID: UUID
    let baseEpoch: UInt64
    let baseStateDigest: Data
    let issuedAt: Date
    let expiresAt: Date
}

private struct GroupAdmissionResponseBindingPayload: Encodable {
    let domain: String
    let version: Int
    let requestID: UUID
    let groupID: UUID
    let invitationBindingDigest: Data
    let admission: GroupCredentialAdmissionV2
    let routeSet: SignedGroupOpaqueRouteSetV2
}

private struct GroupJoinPackageBindingPayload: Encodable {
    let domain: String
    let version: Int
    let requestID: UUID
    let groupID: UUID
    let invitationBindingDigest: Data
    let anchor: GroupJoinAnchorV2
    let transition: GroupEpochTransitionEnvelopeV2
    let welcome: SignedGroupWelcomeV2
    let existingMemberRouteAnnouncements: [SignedGroupRouteSetAnnouncementV2]
}

private struct GroupIdempotencyPayload: Encodable {
    let domain: String
    let bindingDigest: Data
}

private struct GroupDeletionReasonPayload: Encodable {
    let domain: String
    let reason: String
}

private struct GroupDeletionIdempotencyPayload: Encodable {
    let domain: String
    let groupID: UUID
    let stateDigest: Data
    let reasonDigest: Data?
}

private struct GroupArtifactCodingKey: CodingKey {
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

private func requireExactGroupArtifactKeys<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _ type: Key.Type
) throws where Key.AllCases: Collection {
    let strict = try decoder.container(keyedBy: GroupArtifactCodingKey.self)
    guard Set(strict.allKeys.map(\.stringValue))
            == Set(type.allCases.map(\.stringValue)) else {
        throw groupArtifactDecodingError(
            codingPath: decoder.codingPath,
            description: "Group artifact fields must match exactly"
        )
    }
}

private func groupArtifactDecodingError(
    codingPath: [CodingKey],
    description: String
) -> DecodingError {
    .dataCorrupted(.init(codingPath: codingPath, debugDescription: description))
}

private func groupArtifactDigest<T: Encodable>(_ value: T) throws -> Data {
    let canonical = try NoctweaveCanonicalJSON.encode(value)
    let hex = AttachmentBlobDigest.sha256Hex(canonical)
    guard hex.utf8.count == 64 else {
        throw CLIError("Could not compute the group artifact binding digest.")
    }
    var result = Data()
    result.reserveCapacity(32)
    var index = hex.startIndex
    for _ in 0..<32 {
        let next = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<next], radix: 16) else {
            throw CLIError("Could not compute the group artifact binding digest.")
        }
        result.append(byte)
        index = next
    }
    return result
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

private struct AttachmentDownloadJournalOutput: Codable {
    let relationshipID: UUID
    let downloadID: UUID
    let attachmentID: UUID
    let output: String
}

private struct AttachmentDownloadFetchOutput: Codable {
    let relationshipID: UUID
    let downloadID: UUID
    let attachmentID: UUID
    let chunkIndex: Int?
    let complete: Bool
    let accepted: Bool
    let output: String
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

private struct GroupSendStatusOutput: Codable {
    let groupID: UUID
    let eventID: UUID
    let clientTransactionID: UUID
    let operationID: UUID?
    let complete: Bool
    let disposition: HeadlessGroupTransportDispositionV2

    init(_ result: HeadlessGroupTextSendResultV2) {
        groupID = result.groupID
        eventID = result.event.id
        clientTransactionID = result.event.clientTransactionID
        operationID = result.operationID
        complete = result.complete
        disposition = result.disposition
    }
}

private struct GroupCreationStatusOutput: Codable {
    let groupID: UUID
    let ownerMemberHandle: GroupScopedMemberHandleV2
    let ownerCredentialHandle: GroupScopedCredentialHandleV2
    let epoch: UInt64
    let routeRevision: UInt64
    let routeAnnouncementComplete: Bool

    init(_ result: HeadlessGroupCreationResultV2) {
        groupID = result.groupID
        ownerMemberHandle = result.ownerMemberHandle
        ownerCredentialHandle = result.ownerCredentialHandle
        epoch = result.signedState.epoch
        routeRevision = result.receiveRoute.routeSet.revision
        routeAnnouncementComplete = result.receiveRoute.announcementComplete
    }
}

private struct GroupMaintenanceStatusOutput: Codable {
    let groupID: UUID
    let observedAt: Date
    let resumedReceiveRoute: Bool
    let resumedTransportCount: Int
    let incompleteTransportCount: Int
    let finalizedExpiredRoutes: Bool
    let requiresFollowUp: Bool

    init(_ result: HeadlessGroupMaintenanceReportV2) {
        groupID = result.groupID
        observedAt = result.observedAt
        resumedReceiveRoute = result.resumedReceiveRoute != nil
        resumedTransportCount = result.transportResults.count
        incompleteTransportCount = result.transportResults.filter { !$0.complete }.count
        finalizedExpiredRoutes = result.finalizedRouteSet != nil
        requiresFollowUp = result.requiresFollowUp
    }
}

private struct GroupSyncStatusOutput: Codable {
    let groupID: UUID
    let receivedEvents: [GroupEventStatusOutput]
    let synchronizedRouteCount: Int
    let pageCount: Int
    let hasMore: Bool

    init(groupID: UUID, pages: [[GroupInboundSyncResultV2]]) {
        self.groupID = groupID
        let result = pages.flatMap { $0 }
        var seen = Set<UUID>()
        receivedEvents = result.flatMap(\.receivedEvents).compactMap { event in
            guard seen.insert(event.id).inserted else { return nil }
            return GroupEventStatusOutput(event)
        }
        synchronizedRouteCount = Set(result.map(\.routeID)).count
        pageCount = pages.count
        hasMore = pages.last?.contains(where: \.hasMore) ?? false
    }
}

private struct GroupEventStatusOutput: Codable {
    let id: UUID
    let clientTransactionID: UUID
    let kind: GroupConversationEventKindV2
    let contentType: ContentTypeId
    let createdAt: Date

    init(_ event: GroupConversationEventV2) {
        id = event.id
        clientTransactionID = event.clientTransactionID
        kind = event.kind
        contentType = event.content.type
        createdAt = event.createdAt
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

    func requireOnly(_ allowed: Set<String>) throws {
        let unknown = Set(values.keys).subtracting(allowed)
        guard unknown.isEmpty else {
            throw CLIError("Unsupported option for this command: \(unknown.sorted().joined(separator: ", "))")
        }
    }

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
