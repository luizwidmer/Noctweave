import Foundation

public enum RelayPairingPreflightError: Error, Equatable, LocalizedError {
    case confidentialTransportRequired
    case healthRejected(String)
    case invalidHealthResponse
    case infoRejected(String)
    case invalidInfoResponse
    case coordinatorUnsupported
    case opaqueRouteUnsupported
    case rendezvousTransportUnsupported
    case authenticationRequired
    case opaqueRouteProbeRejected(String)
    case invalidOpaqueRouteProbeResponse
    case rendezvousProbeRejected(String)
    case invalidRendezvousProbeResponse

    public var errorDescription: String? {
        switch self {
        case .confidentialTransportRequired:
            return "Pairing requires HTTPS, WSS, TLS, or a loopback relay. Plain remote transports cannot carry route capabilities safely."
        case .healthRejected(let message):
            return "The relay health check was rejected: \(message)"
        case .invalidHealthResponse:
            return "The endpoint did not return a valid Noctweave health response."
        case .infoRejected(let message):
            return "The relay information check was rejected: \(message)"
        case .invalidInfoResponse:
            return "The endpoint did not return compatible Noctweave relay information."
        case .coordinatorUnsupported:
            return "Coordinator nodes do not carry pairing or user traffic. Choose a standard relay."
        case .opaqueRouteUnsupported:
            return "This relay does not advertise the opaque-route service required for conversations."
        case .rendezvousTransportUnsupported:
            return "This relay does not allow one-use pairing rendezvous. The operator must enable nw.rendezvous-transport v2."
        case .authenticationRequired:
            return "This relay requires its access password before pairing can be checked."
        case .opaqueRouteProbeRejected(let message):
            return "The relay rejected a temporary message-route probe: \(message)"
        case .invalidOpaqueRouteProbeResponse:
            return "The relay advertised message routes but did not complete the temporary route probe."
        case .rendezvousProbeRejected(let message):
            return "The relay rejected a temporary pairing probe: \(message)"
        case .invalidRendezvousProbeResponse:
            return "The relay advertised pairing support but did not complete the temporary rendezvous probe."
        }
    }
}

public enum RelayPairingRequirement: String, Equatable, Sendable {
    /// Each participant provisions its own relationship route, while the
    /// authenticated pairing transcript travels directly by QR or file.
    case opaqueRouteOnly

    /// Both participants use one relay's bounded one-use rendezvous lanes.
    case rendezvous
}

public struct RelayPairingReadiness: Equatable {
    public let endpoint: RelayEndpoint
    public let relayInfo: RelayInfo
    public let requirement: RelayPairingRequirement

    public init(
        endpoint: RelayEndpoint,
        relayInfo: RelayInfo,
        requirement: RelayPairingRequirement
    ) {
        self.endpoint = endpoint
        self.relayInfo = relayInfo
        self.requirement = requirement
    }
}

/// Verifies that a relay is reachable and can perform the exact bounded route
/// operations required by the selected contact-pairing path.
public enum RelayPairingPreflight {
    public static func check(
        client: RelayClient,
        timeout: TimeInterval = 4,
        requirement: RelayPairingRequirement = .rendezvous,
        performRuntimeProbe: Bool = true
    ) async throws -> RelayPairingReadiness {
        guard client.endpoint.isConfidentialCapabilityTransportV2 else {
            throw RelayPairingPreflightError.confidentialTransportRequired
        }

        let healthRequest = RelayRequest.health()
        let health = try await client.send(healthRequest, timeout: timeout)
        guard health.isResponse(to: healthRequest) else {
            throw RelayPairingPreflightError.invalidHealthResponse
        }
        guard health.status == .success else {
            throw RelayPairingPreflightError.healthRejected(
                health.error?.message ?? "Unknown relay error"
            )
        }
        guard case .empty? = health.successBody else {
            throw RelayPairingPreflightError.invalidHealthResponse
        }

        let infoRequest = RelayRequest.info()
        let response = try await client.send(infoRequest, timeout: timeout)
        guard response.isResponse(to: infoRequest) else {
            throw RelayPairingPreflightError.invalidInfoResponse
        }
        guard response.status == .success else {
            throw RelayPairingPreflightError.infoRejected(
                response.error?.message ?? "Unknown relay error"
            )
        }
        guard case .relayInfo(let info)? = response.successBody else {
            throw RelayPairingPreflightError.invalidInfoResponse
        }
        try validate(
            endpoint: client.endpoint,
            relayInfo: info,
            authToken: client.authToken,
            requirement: requirement
        )

        if performRuntimeProbe {
            try await verifyOpaqueRouteRuntime(client: client, timeout: timeout)
            if requirement == .rendezvous {
                try await verifyRendezvousRuntime(client: client, timeout: timeout)
            }
        }
        return RelayPairingReadiness(
            endpoint: client.endpoint,
            relayInfo: info,
            requirement: requirement
        )
    }

    static func validate(
        endpoint: RelayEndpoint,
        relayInfo: RelayInfo,
        authToken: String?,
        requirement: RelayPairingRequirement
    ) throws {
        guard endpoint.isConfidentialCapabilityTransportV2 else {
            throw RelayPairingPreflightError.confidentialTransportRequired
        }
        guard relayInfo.kind != .coordinator else {
            throw RelayPairingPreflightError.coordinatorUnsupported
        }
        guard relayInfo.protocolCapabilities?.supports(
            module: "nw.opaque-route",
            version: 2
        ) == true else {
            throw RelayPairingPreflightError.opaqueRouteUnsupported
        }
        if requirement == .rendezvous {
            guard relayInfo.protocolCapabilities?.supports(
                module: "nw.rendezvous-transport",
                version: 2
            ) == true else {
                throw RelayPairingPreflightError.rendezvousTransportUnsupported
            }
        }
        if relayInfo.requiresPassword == true,
           authToken?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false {
            throw RelayPairingPreflightError.authenticationRequired
        }
    }

    private static func verifyOpaqueRouteRuntime(
        client: RelayClient,
        timeout: TimeInterval
    ) async throws {
        let now = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
        let capabilities = try OpaqueRouteClientCapabilityMaterialV2()
        let lease = try OpaqueRouteLeaseV2(
            issuedAt: now,
            expiresAt: now.addingTimeInterval(6 * 60 * 60),
            policy: OpaqueRoutePolicyV2(
                paddingBucket: .bytes4096,
                retentionBucket: .sixHours,
                quotaBucket: .packets256
            )
        )
        let create = try capabilities.makeCreateRequest(
            lease: lease,
            idempotencyKey: .generate()
        )
        var createdRoute: OpaqueReceiveRouteV2?

        do {
            let response = try await client.send(
                .createOpaqueRouteV2(
                    CreateOpaqueRouteRelayRequestV2(
                        request: create,
                        renewCapability: capabilities.renewCapability
                    )
                ),
                timeout: timeout
            )
            guard response.status == .success else {
                if response.error?.code == .authenticationRequired {
                    throw RelayPairingPreflightError.authenticationRequired
                }
                throw RelayPairingPreflightError.opaqueRouteProbeRejected(
                    response.error?.message ?? "Unknown relay error"
                )
            }
            guard case .opaqueRoute(let route)? = response.successBody,
                  route.routeID == capabilities.routeID else {
                throw RelayPairingPreflightError.invalidOpaqueRouteProbeResponse
            }
            createdRoute = route
            let teardown = try capabilities.makeTeardownRequest(
                current: route,
                authorizedAt: Date(),
                idempotencyKey: .generate()
            )
            let deletion = try await client.send(
                .teardownOpaqueRouteV2(
                    TeardownOpaqueRouteRelayRequestV2(
                        request: teardown,
                        teardownCapability: capabilities.teardownCapability
                    )
                ),
                timeout: timeout
            )
            try requireOpaqueRouteProbeSuccess(
                deletion,
                expectedRouteID: capabilities.routeID
            )
            createdRoute = nil
        } catch {
            if let createdRoute,
               let teardown = try? capabilities.makeTeardownRequest(
                   current: createdRoute,
                   authorizedAt: Date(),
                   idempotencyKey: .generate()
               ) {
                _ = try? await client.send(
                    .teardownOpaqueRouteV2(
                        TeardownOpaqueRouteRelayRequestV2(
                            request: teardown,
                            teardownCapability: capabilities.teardownCapability
                        )
                    ),
                    timeout: timeout
                )
            }
            throw error
        }
    }

    private static func verifyRendezvousRuntime(
        client: RelayClient,
        timeout: TimeInterval
    ) async throws {
        let now = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
        let expiresAt = now.addingTimeInterval(60)
        let pending = try PendingRendezvousOfferV2.create(
            transportCapability: .generate(expiresAt: expiresAt),
            createdAt: now
        )
        let adapter = try RendezvousRelayAdapterV2(offer: pending.offer)
        var registered = false

        do {
            let registration = try await client.send(
                .registerRendezvousTransportV2(adapter.registrationRequest),
                timeout: timeout
            )
            try requireProbeSuccess(registration)
            registered = true

            for request in adapter.deletionRequests() {
                let deletion = try await client.send(
                    .deleteRendezvousTransportV2(request),
                    timeout: timeout
                )
                try requireProbeSuccess(deletion)
            }
        } catch {
            if registered {
                for request in adapter.deletionRequests() {
                    _ = try? await client.send(
                        .deleteRendezvousTransportV2(request),
                        timeout: timeout
                    )
                }
            }
            throw error
        }
    }

    private static func requireProbeSuccess(_ response: RelayResponse) throws {
        guard response.status == .success else {
            if response.error?.code == .authenticationRequired {
                throw RelayPairingPreflightError.authenticationRequired
            }
            throw RelayPairingPreflightError.rendezvousProbeRejected(
                response.error?.message ?? "Unknown relay error"
            )
        }
        guard case .empty? = response.successBody else {
            throw RelayPairingPreflightError.invalidRendezvousProbeResponse
        }
    }

    private static func requireOpaqueRouteProbeSuccess(
        _ response: RelayResponse,
        expectedRouteID: OpaqueReceiveRouteIDV2
    ) throws {
        guard response.status == .success else {
            if response.error?.code == .authenticationRequired {
                throw RelayPairingPreflightError.authenticationRequired
            }
            throw RelayPairingPreflightError.opaqueRouteProbeRejected(
                response.error?.message ?? "Unknown relay error"
            )
        }
        guard case .opaqueRoute(let route)? = response.successBody,
              route.routeID == expectedRouteID,
              route.status == .tornDown else {
            throw RelayPairingPreflightError.invalidOpaqueRouteProbeResponse
        }
    }
}
