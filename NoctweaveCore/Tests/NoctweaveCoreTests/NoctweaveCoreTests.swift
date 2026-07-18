import Foundation
import CryptoKit
import SQLite3
import XCTest
@testable import NoctweaveCore

final class NoctweaveCoreTests: XCTestCase {
    func testMetadataMinimizerBucketsVisibleTimestamps() {
        let precise = Date(timeIntervalSince1970: 1_765_400_123)

        XCTAssertEqual(
            MetadataMinimizer.bucketedTimestamp(precise, bucketSeconds: 300),
            Date(timeIntervalSince1970: 1_765_400_100)
        )
        XCTAssertEqual(MetadataMinimizer.bucketedTimestamp(precise, bucketSeconds: 1), precise)
        XCTAssertEqual(MetadataMinimizer.bucketedTimestamp(precise, bucketSeconds: nil), precise)
    }

    func testHiddenRetrievalPlannerBuildsDeterministicCoverQuery() throws {
        let records = ["msg-4", "msg-1", "msg-3", "msg-2", "msg-5"]
        let secret = Data("client-local-cover-secret".utf8)

        let first = try HiddenRetrievalPlanner.makeCoverQuery(
            bucketId: "bucket-2026-06-25T10:00",
            availableRecordIds: records,
            targetRecordId: "msg-3",
            coverSetSize: 3,
            secret: secret
        )
        let second = try HiddenRetrievalPlanner.makeCoverQuery(
            bucketId: "bucket-2026-06-25T10:00",
            availableRecordIds: records.reversed(),
            targetRecordId: "msg-3",
            coverSetSize: 3,
            secret: secret
        )

        XCTAssertEqual(first, second)
        XCTAssertEqual(first.bucketId, "bucket-2026-06-25T10:00")
        XCTAssertEqual(first.requestedRecordIds.count, 3)
        XCTAssertTrue(first.requestedRecordIds.contains("msg-3"))
        XCTAssertNotNil(first.targetOffset)
        XCTAssertEqual(first.requestedRecordIds, first.requestedRecordIds.sorted())
    }

    func testRelayClientDoesNotFallbackAcrossConfiguredTransports() async throws {
        let port = UInt16.random(in: 42_000...44_999)
        let rawTCPEndpoint = RelayEndpoint(host: "127.0.0.1", port: port, transport: .tcp)
        let httpEndpoint = RelayEndpoint(host: "127.0.0.1", port: port, transport: .http)
        let server = RelayServer(store: RelayStore())
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 250_000_000)

        let tcpResponse = try await RelayClient(endpoint: rawTCPEndpoint).send(.health(), timeout: 2)
        XCTAssertEqual(tcpResponse.status, .success)
        guard case .empty? = tcpResponse.successBody else {
            return XCTFail("Expected empty health response")
        }

        do {
            _ = try await RelayClient(endpoint: httpEndpoint).send(.health(), timeout: 2)
            XCTFail("HTTP-configured clients must not silently retry raw TCP.")
        } catch {
            // Expected: the server is raw TCP only, so the HTTP request must fail
            // instead of being retried over a different transport.
        }
    }

    func testRelayClientTLSObservationIsNilForPlaintextTransport() async throws {
        let port = UInt16.random(in: 42_000...44_999)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port, transport: .tcp)
        let server = RelayServer(store: RelayStore())
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 250_000_000)

        let observation = try await RelayClient(endpoint: endpoint).sendObservingTLS(.health(), timeout: 2)
        XCTAssertEqual(observation.response.status, .success)
        XCTAssertNil(observation.leafCertificateSHA256)
    }

    func testLiveTLSObservationAndPinEnforcementWhenConfigured() async throws {
        guard let value = ProcessInfo.processInfo.environment["NOCTWEAVE_LIVE_TLS_RELAY"],
              !value.isEmpty else {
            throw XCTSkip("Set NOCTWEAVE_LIVE_TLS_RELAY to run the live TLS pin test.")
        }
        var endpoint = try RelayEndpointParser.parse(value)
        guard endpoint.useTLS else {
            XCTFail("NOCTWEAVE_LIVE_TLS_RELAY must use TLS.")
            return
        }

        let observation = try await RelayClient(endpoint: endpoint).sendObservingTLS(.info(), timeout: 8)
        guard case .relayInfo? = observation.response.successBody else {
            return XCTFail("Expected relay info response")
        }
        let fingerprint = try XCTUnwrap(observation.leafCertificateSHA256)
        XCTAssertEqual(fingerprint.count, 32)

        endpoint.tlsCertificateFingerprintSHA256 = fingerprint
        let pinnedResponse = try await RelayClient(endpoint: endpoint).send(.info(), timeout: 8)
        guard case .relayInfo? = pinnedResponse.successBody else {
            return XCTFail("Expected relay info response")
        }

        endpoint.tlsCertificateFingerprintSHA256 = Data(repeating: 0xFF, count: 32)
        do {
            _ = try await RelayClient(endpoint: endpoint).send(.info(), timeout: 8)
            XCTFail("A mismatched TLS certificate pin must fail closed.")
        } catch {
            // Expected.
        }
    }

    func testRelayClientRejectsUnsafeConfigurationBeforeNetworking() async throws {
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: 9)

        for timeout in [TimeInterval.nan, .infinity, 0, 301] {
            do {
                _ = try await RelayClient(endpoint: endpoint).send(.health(), timeout: timeout)
                XCTFail("Expected invalid timeout to be rejected")
            } catch RelayNetworkError.invalidTimeout {
                // Expected.
            } catch {
                XCTFail("Unexpected error: \(error)")
            }
        }

        do {
            _ = try await RelayClient(
                endpoint: endpoint,
                authToken: String(repeating: "x", count: RelayClient.maxAuthenticationBytes + 1)
            ).send(.health())
            XCTFail("Expected oversized authentication material to be rejected")
        } catch RelayNetworkError.invalidAuthentication {
            // Expected.
        }
    }

    func testRelayClientAcceptsBoundedDeploymentPolicy() throws {
        let policy = try RelayClientPolicy(
            maximumResponseBytes: 2 * 1_024 * 1_024,
            maximumRequestBytes: 1 * 1_024 * 1_024,
            timeout: 30
        )
        let client = RelayClient(
            endpoint: RelayEndpoint(host: "relay.example", port: 443, useTLS: true, transport: .http),
            policy: policy
        )

        XCTAssertEqual(client.policy.maximumResponseBytes, 2 * 1_024 * 1_024)
        XCTAssertEqual(client.policy.maximumRequestBytes, 1 * 1_024 * 1_024)
        XCTAssertEqual(client.policy.timeout, 30)
    }

    func testRelayClientPolicyRejectsValuesAboveSafetyCeilings() {
        XCTAssertThrowsError(
            try RelayClientPolicy(
                maximumResponseBytes: RelayClientPolicy.absoluteMaximumResponseBytes + 1
            )
        ) { error in
            XCTAssertEqual(error as? RelayClientPolicyError, .invalidMaximumResponseBytes)
        }
        XCTAssertThrowsError(
            try RelayClientPolicy(
                maximumRequestBytes: RelayClientPolicy.absoluteMaximumRequestBytes + 1
            )
        ) { error in
            XCTAssertEqual(error as? RelayClientPolicyError, .invalidMaximumRequestBytes)
        }
        XCTAssertThrowsError(
            try RelayClientPolicy(timeout: RelayClientPolicy.absoluteMaximumTimeout + 1)
        ) { error in
            XCTAssertEqual(error as? RelayClientPolicyError, .invalidTimeout)
        }
    }

    func testRelayHTTPResponseSummaryDoesNotEchoBodyText() {
        let cloudflareLikeBody = Data("Cloudflare error code: 1010 token=secret-value".utf8)
        let regularBody = Data("upstream failure token=secret-value".utf8)

        XCTAssertEqual(
            RelayClient.responseSummary(cloudflareLikeBody),
            "<redacted Cloudflare error page, \(cloudflareLikeBody.count) bytes>"
        )
        XCTAssertEqual(
            RelayClient.responseSummary(regularBody),
            "<redacted \(regularBody.count) bytes>"
        )
        XCTAssertFalse(RelayClient.responseSummary(cloudflareLikeBody).contains("secret-value"))
        XCTAssertFalse(RelayClient.responseSummary(regularBody).contains("secret-value"))
    }

    func testHiddenRetrievalPlannerExtractsTargetFromCoverResponse() throws {
        let plan = try HiddenRetrievalPlanner.makeCoverQuery(
            bucketId: "bucket-a",
            availableRecordIds: ["a", "b", "c", "d"],
            targetRecordId: "c",
            coverSetSize: 4,
            secret: Data("secret".utf8)
        )
        let response = [
            "a": Data("decoy-a".utf8),
            "b": Data("decoy-b".utf8),
            "c": Data("target".utf8),
            "d": Data("decoy-d".utf8)
        ]

        XCTAssertEqual(
            try HiddenRetrievalPlanner.extractTarget(from: response, using: plan),
            Data("target".utf8)
        )
    }

    func testHiddenRetrievalPlannerRejectsIncompleteCoverResponse() throws {
        let plan = try HiddenRetrievalPlanner.makeCoverQuery(
            bucketId: "bucket-a",
            availableRecordIds: ["a", "b", "c", "d"],
            targetRecordId: "c",
            coverSetSize: 4,
            secret: Data("secret".utf8)
        )
        let response = [
            "c": Data("target".utf8)
        ]

        XCTAssertThrowsError(try HiddenRetrievalPlanner.extractTarget(from: response, using: plan)) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .incompleteCoverResponse)
        }
    }

    func testHiddenRetrievalPlannerRejectsMalformedPublicQueryPlans() throws {
        let response = [
            "a": Data("decoy-a".utf8),
            "b": Data("decoy-b".utf8),
            "c": Data("target".utf8)
        ]
        let missingTarget = HiddenRetrievalQueryPlan(
            bucketId: "bucket-a",
            requestedRecordIds: ["a", "b"],
            targetRecordId: "c"
        )
        let duplicateTarget = HiddenRetrievalQueryPlan(
            bucketId: "bucket-a",
            requestedRecordIds: ["a", "c", "c"],
            targetRecordId: "c"
        )
        let targetOnly = HiddenRetrievalQueryPlan(
            bucketId: "bucket-a",
            requestedRecordIds: ["c"],
            targetRecordId: "c"
        )
        let emptyBucket = HiddenRetrievalQueryPlan(
            bucketId: " ",
            requestedRecordIds: ["a", "c"],
            targetRecordId: "c"
        )
        let emptyTarget = HiddenRetrievalQueryPlan(
            bucketId: "bucket-a",
            requestedRecordIds: ["a", "b"],
            targetRecordId: " "
        )
        let emptyRequestedRecord = HiddenRetrievalQueryPlan(
            bucketId: "bucket-a",
            requestedRecordIds: ["a", " "],
            targetRecordId: "a"
        )
        let extraResponseRecords = HiddenRetrievalQueryPlan(
            bucketId: "bucket-a",
            requestedRecordIds: ["a", "c"],
            targetRecordId: "c"
        )

        for plan in [missingTarget, duplicateTarget, targetOnly, emptyBucket, emptyTarget, emptyRequestedRecord] {
            XCTAssertThrowsError(try HiddenRetrievalPlanner.extractTarget(from: response, using: plan)) { error in
                XCTAssertEqual(error as? HiddenRetrievalError, .malformedPublicPlan)
            }
            XCTAssertNil(HiddenRetrievalPlanner.targetIfValid(from: response, using: plan))
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.extractTarget(from: response, using: extraResponseRecords)
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .unexpectedResponseRecords)
        }
    }

    func testHiddenRetrievalPlannerRejectsInvalidQueries() throws {
        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: " ",
                availableRecordIds: ["a", "b"],
                targetRecordId: "a",
                coverSetSize: 2,
                secret: Data()
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidBucketId)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: ["a", "b"],
                targetRecordId: " ",
                coverSetSize: 2,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidTargetRecordId)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: ["a", " "],
                targetRecordId: "a",
                coverSetSize: 2,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidRecordId)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: ["a", "b"],
                targetRecordId: "a",
                coverSetSize: 2,
                secret: Data()
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidSecret)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: ["a"],
                targetRecordId: "a",
                coverSetSize: 0,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidCoverSetSize)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: ["a", "b", "c"],
                targetRecordId: "a",
                coverSetSize: 3,
                secret: Data("secret".utf8),
                maximumCoverSetSize: 2
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .coverSetTooLarge)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: ["a", "b"],
                targetRecordId: "a",
                coverSetSize: 1,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidCoverSetSize)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: [],
                targetRecordId: "a",
                coverSetSize: 2,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .emptyBucket)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: ["a", "b"],
                targetRecordId: "c",
                coverSetSize: 2,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .targetMissing)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: ["a", "b"],
                targetRecordId: "a",
                coverSetSize: 3,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .insufficientBucketRecords)
        }
    }

    func testHiddenRetrievalPlannerCanonicalizesBucketAndRecordIds() throws {
        let plan = try HiddenRetrievalPlanner.makeCoverQuery(
            bucketId: " bucket-a ",
            availableRecordIds: [" a ", "b", "c"],
            targetRecordId: " a ",
            coverSetSize: 2,
            secret: Data("secret".utf8)
        )

        XCTAssertEqual(plan.bucketId, "bucket-a")
        XCTAssertEqual(plan.targetRecordId, "a")
        XCTAssertTrue(plan.requestedRecordIds.contains("a"))
        XCTAssertFalse(plan.requestedRecordIds.contains(" a "))
    }

    func testHiddenRetrievalPlannerBuildsReplicatedXORPIRQuery() throws {
        let plan = try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
            bucketId: " bucket-pir ",
            orderedRecordIds: [" a ", "b", "c", "d"],
            targetRecordId: " c ",
            replicaCount: 3,
            secret: Data("client-local-pir-secret".utf8)
        )

        XCTAssertEqual(plan.bucketId, "bucket-pir")
        XCTAssertEqual(plan.orderedRecordIds, ["a", "b", "c", "d"])
        XCTAssertEqual(plan.targetRecordId, "c")
        XCTAssertEqual(plan.targetIndex, 2)
        XCTAssertEqual(plan.shares.map(\.replicaIndex), [0, 1, 2])
        XCTAssertTrue(plan.shares.allSatisfy { $0.recordCount == 4 })

        let records = [
            Data("record-a-16bytes".utf8),
            Data("record-b-16bytes".utf8),
            Data("record-c-16bytes".utf8),
            Data("record-d-16bytes".utf8)
        ]
        let responses = try plan.shares.map {
            try HiddenRetrievalPlanner.evaluateReplicatedXORPIRShare(records: records, share: $0)
        }

        XCTAssertEqual(
            try HiddenRetrievalPlanner.recoverReplicatedXORPIRTarget(from: responses, using: plan),
            records[2]
        )
    }

    func testHiddenRetrievalPlannerReplicatedXORPIRDoesNotSendTargetOnlyShares() throws {
        let plan = try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
            bucketId: "bucket-pir",
            orderedRecordIds: ["a", "b", "c", "d", "e"],
            targetRecordId: "d",
            replicaCount: 2,
            secret: Data("client-local-pir-secret".utf8)
        )

        let unitTarget = testBitset(recordCount: plan.orderedRecordIds.count, enabledIndex: plan.targetIndex)
        XCTAssertTrue(plan.shares.allSatisfy { $0.selectionBits != unitTarget })

        let combined = plan.shares
            .map(\.selectionBits)
            .reduce(Data(repeating: 0, count: unitTarget.count), xorTestData)
        XCTAssertEqual(combined, unitTarget)
    }

    func testHiddenRetrievalPlannerBuildsPaddedReplicatedXORPIRQuery() throws {
        let plan = try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
            bucketId: "bucket-pir",
            orderedRecordIds: ["a", "b", "c"],
            targetRecordId: "b",
            replicaCount: 3,
            secret: Data("client-local-padded-pir-secret".utf8),
            paddedRecordCount: 16
        )

        XCTAssertEqual(plan.orderedRecordIds.count, 3)
        XCTAssertEqual(plan.shares.map(\.recordCount), [16, 16, 16])
        XCTAssertTrue(plan.shares.allSatisfy { $0.selectionBits.count == 2 })

        let records = [
            Data("record-a-16bytes".utf8),
            Data("record-b-16bytes".utf8),
            Data("record-c-16bytes".utf8)
        ]
        let responses = try plan.shares.map {
            try HiddenRetrievalPlanner.evaluateReplicatedXORPIRShare(records: records, share: $0)
        }

        XCTAssertEqual(
            try HiddenRetrievalPlanner.recoverReplicatedXORPIRTarget(from: responses, using: plan),
            records[1]
        )

        let unitTarget = testBitset(recordCount: 16, enabledIndex: plan.targetIndex)
        let combined = plan.shares
            .map(\.selectionBits)
            .reduce(Data(repeating: 0, count: unitTarget.count), xorTestData)
        XCTAssertEqual(combined, unitTarget)
    }

    func testHiddenRetrievalPlannerBuildsFixedSizeReplicatedXORPIRResponses() throws {
        let plan = try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
            bucketId: "bucket-pir",
            orderedRecordIds: ["a", "b", "c"],
            targetRecordId: "c",
            replicaCount: 3,
            secret: Data("client-local-fixed-response-pir-secret".utf8),
            paddedRecordCount: 16
        )
        let records = [
            Data("record-a".utf8),
            Data("record-b".utf8),
            Data("record-c".utf8)
        ]
        let fixedResponseSize = 32

        let responses = try plan.shares.map {
            try HiddenRetrievalPlanner.evaluateReplicatedXORPIRShare(
                records: records,
                share: $0,
                fixedResponseSize: fixedResponseSize
            )
        }

        XCTAssertTrue(responses.allSatisfy { $0.payload.count == fixedResponseSize })
        var expected = records[2]
        expected.append(Data(repeating: 0, count: fixedResponseSize - expected.count))
        XCTAssertEqual(
            try HiddenRetrievalPlanner.recoverReplicatedXORPIRTarget(
                from: responses,
                using: plan,
                fixedResponseSize: fixedResponseSize
            ),
            expected
        )
    }

    func testHiddenRetrievalPlannerRejectsMalformedReplicatedXORPIRInputs() throws {
        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
                bucketId: "bucket-pir",
                orderedRecordIds: ["a", "b"],
                targetRecordId: "a",
                replicaCount: 1,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidReplicaCount)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
                bucketId: "bucket-pir",
                orderedRecordIds: ["a", "a"],
                targetRecordId: "a",
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidRecordCount)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
                bucketId: "bucket-pir",
                orderedRecordIds: ["a", "b", "c"],
                targetRecordId: "a",
                secret: Data("secret".utf8),
                paddedRecordCount: 2
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidRecordCount)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.evaluateReplicatedXORPIRShare(
                records: [Data("short".utf8), Data("longer".utf8)],
                share: HiddenRetrievalPIRQueryShare(
                    replicaIndex: 0,
                    recordCount: 2,
                    selectionBits: Data([0b0000_0011])
                )
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidRecordSize)
        }

        let plan = try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
            bucketId: "bucket-pir",
            orderedRecordIds: ["a", "b"],
            targetRecordId: "a",
            secret: Data("secret".utf8)
        )
        let response = HiddenRetrievalPIRResponseShare(replicaIndex: 0, payload: Data("target".utf8))
        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.recoverReplicatedXORPIRTarget(from: [response], using: plan)
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .malformedPIRResponse)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.evaluateReplicatedXORPIRShare(
                records: [Data("record-a".utf8), Data("record-b".utf8)],
                share: plan.shares[0],
                fixedResponseSize: 4
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidRecordSize)
        }

        let completeResponses = try plan.shares.map {
            try HiddenRetrievalPlanner.evaluateReplicatedXORPIRShare(
                records: [Data("record-a".utf8), Data("record-b".utf8)],
                share: $0,
                fixedResponseSize: 16
            )
        }
        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.recoverReplicatedXORPIRTarget(
                from: completeResponses,
                using: plan,
                fixedResponseSize: 32
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidRecordSize)
        }
    }

    func testHiddenRetrievalPlannerRejectsMalformedReplicatedXORPIRPlans() throws {
        let plan = try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
            bucketId: "bucket-pir",
            orderedRecordIds: ["a", "b", "c"],
            targetRecordId: "b",
            replicaCount: 3,
            secret: Data("client-local-pir-plan-secret".utf8),
            paddedRecordCount: 8
        )
        let records = [
            Data("record-a".utf8),
            Data("record-b".utf8),
            Data("record-c".utf8)
        ]
        let responses = try plan.shares.map {
            try HiddenRetrievalPlanner.evaluateReplicatedXORPIRShare(records: records, share: $0)
        }

        let duplicateReplicaPlan = HiddenRetrievalPIRQueryPlan(
            bucketId: plan.bucketId,
            orderedRecordIds: plan.orderedRecordIds,
            targetRecordId: plan.targetRecordId,
            targetIndex: plan.targetIndex,
            shares: [
                plan.shares[0],
                HiddenRetrievalPIRQueryShare(
                    replicaIndex: 0,
                    recordCount: plan.shares[1].recordCount,
                    selectionBits: plan.shares[1].selectionBits
                ),
                plan.shares[2]
            ]
        )
        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.recoverReplicatedXORPIRTarget(from: responses, using: duplicateReplicaPlan)
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .malformedPIRShare)
        }

        let wrongTargetPlan = HiddenRetrievalPIRQueryPlan(
            bucketId: plan.bucketId,
            orderedRecordIds: plan.orderedRecordIds,
            targetRecordId: "c",
            targetIndex: plan.targetIndex,
            shares: plan.shares
        )
        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.recoverReplicatedXORPIRTarget(from: responses, using: wrongTargetPlan)
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .targetMissing)
        }

        let zeroedSharePlan = HiddenRetrievalPIRQueryPlan(
            bucketId: plan.bucketId,
            orderedRecordIds: plan.orderedRecordIds,
            targetRecordId: plan.targetRecordId,
            targetIndex: plan.targetIndex,
            shares: [
                HiddenRetrievalPIRQueryShare(
                    replicaIndex: 0,
                    recordCount: plan.shares[0].recordCount,
                    selectionBits: Data(repeating: 0, count: plan.shares[0].selectionBits.count)
                ),
                plan.shares[1],
                plan.shares[2]
            ]
        )
        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.recoverReplicatedXORPIRTarget(from: responses, using: zeroedSharePlan)
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .malformedPIRShare)
        }
    }

    func testRelayInfoAdvertisesOptionalHiddenRetrievalSupport() throws {
        let info = RelayConfiguration(
            hiddenRetrieval: HiddenRetrievalSupport(
                defaultCoverSetSize: 64,
                maxCoverSetSize: 16
            )
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))

        XCTAssertEqual(info.hiddenRetrieval?.mode, .coverQuery)
        XCTAssertEqual(info.hiddenRetrieval?.defaultCoverSetSize, 16)
        XCTAssertEqual(info.hiddenRetrieval?.maxCoverSetSize, 16)

        let encoded = try NoctweaveCoder.encode(info)
        let decoded = try NoctweaveCoder.decode(RelayInfo.self, from: encoded)

        XCTAssertEqual(decoded.hiddenRetrieval, info.hiddenRetrieval)
    }

    func testHiddenRetrievalSupportAdvertisesReplicatedXORPIRMode() throws {
        let info = RelayConfiguration(
            hiddenRetrieval: HiddenRetrievalSupport(
                mode: .replicatedXorPIR,
                defaultCoverSetSize: 8,
                maxCoverSetSize: 32,
                replicatedXorPIRReplicas: [
                    HiddenRetrievalPIRReplica(
                        replicaId: "replica-a",
                        operatorId: "operator-a",
                        endpoint: RelayEndpoint(host: "pir-a.example", port: 443, useTLS: true, transport: .http)
                    ),
                    HiddenRetrievalPIRReplica(
                        replicaId: "replica-b",
                        operatorId: "operator-b",
                        endpoint: RelayEndpoint(host: "pir-b.example", port: 443, useTLS: true, transport: .http)
                    )
                ]
            )
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))

        XCTAssertEqual(info.hiddenRetrieval?.mode, .replicatedXorPIR)
        XCTAssertTrue(HiddenRetrievalPIRReplicaSetValidator.isUsable(info.hiddenRetrieval))
        XCTAssertEqual(try HiddenRetrievalPIRReplicaSetValidator.validate(info.hiddenRetrieval).count, 2)

        let encoded = try NoctweaveCoder.encode(info)
        let decoded = try NoctweaveCoder.decode(RelayInfo.self, from: encoded)

        XCTAssertEqual(decoded.hiddenRetrieval?.mode, .replicatedXorPIR)
        XCTAssertEqual(decoded.hiddenRetrieval?.replicatedXorPIRReplicas, info.hiddenRetrieval?.replicatedXorPIRReplicas)
    }

    func testHiddenRetrievalSupportDoesNotAdvertiseTargetOnlyPlans() {
        let support = HiddenRetrievalSupport(defaultCoverSetSize: 1, maxCoverSetSize: 1)

        XCTAssertEqual(support.defaultCoverSetSize, 2)
        XCTAssertEqual(support.maxCoverSetSize, 2)
    }

    func testHiddenRetrievalReplicaSetValidatorRejectsMisleadingReplicatedPIRMetadata() {
        XCTAssertEqual(
            HiddenRetrievalPIRReplicaSetValidator.issues(for: nil),
            [.hiddenRetrievalUnavailable]
        )
        XCTAssertEqual(
            HiddenRetrievalPIRReplicaSetValidator.issues(for: HiddenRetrievalSupport()),
            [.unsupportedMode]
        )

        let duplicatedSingleOperator = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            replicatedXorPIRReplicas: [
                HiddenRetrievalPIRReplica(
                    replicaId: "same",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir.example", port: 443, useTLS: true, transport: .http)
                ),
                HiddenRetrievalPIRReplica(
                    replicaId: "same",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir.example", port: 443, useTLS: true, transport: .http)
                )
            ]
        )
        let issues = HiddenRetrievalPIRReplicaSetValidator.issues(for: duplicatedSingleOperator)

        XCTAssertTrue(issues.contains(.duplicateReplicaId))
        XCTAssertTrue(issues.contains(.duplicateOperatorId))
        XCTAssertTrue(issues.contains(.duplicateEndpoint))
        XCTAssertThrowsError(try HiddenRetrievalPIRReplicaSetValidator.validate(duplicatedSingleOperator)) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidReplicaSet)
        }

        let noTLS = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            replicatedXorPIRReplicas: [
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir-a.example", port: 80, useTLS: false, transport: .http)
                ),
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-b",
                    operatorId: "operator-b",
                    endpoint: RelayEndpoint(host: "pir-b.example", port: 443, useTLS: true, transport: .http)
                )
            ]
        )

        XCTAssertTrue(HiddenRetrievalPIRReplicaSetValidator.issues(for: noTLS).contains(.insecureEndpoint))
        XCTAssertTrue(HiddenRetrievalPIRReplicaSetValidator.isUsable(noTLS, requireTLS: false))

        let sameHostDifferentPorts = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            replicatedXorPIRReplicas: [
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir-shared.example", port: 443, useTLS: true, transport: .http)
                ),
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-b",
                    operatorId: "operator-b",
                    endpoint: RelayEndpoint(host: "PIR-SHARED.example", port: 8443, useTLS: true, transport: .http)
                )
            ]
        )
        let sameHostIssues = HiddenRetrievalPIRReplicaSetValidator.issues(for: sameHostDifferentPorts)
        XCTAssertTrue(sameHostIssues.contains(.duplicateHost))
        XCTAssertFalse(sameHostIssues.contains(.duplicateEndpoint))
    }

    func testRelayInfoSuppressesWeakReplicatedPIRAdvertisement() {
        let weakReplicas = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            replicatedXorPIRReplicas: [
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir-shared.example", port: 443, useTLS: true, transport: .http)
                ),
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-b",
                    operatorId: "operator-b",
                    endpoint: RelayEndpoint(host: "pir-shared.example", port: 8443, useTLS: true, transport: .http)
                )
            ]
        )
        let weakInfo = RelayConfiguration(hiddenRetrieval: weakReplicas).makeInfo()
        XCTAssertNil(weakInfo.hiddenRetrieval)

        let coverQueryInfo = RelayConfiguration(
            hiddenRetrieval: HiddenRetrievalSupport(mode: .coverQuery)
        ).makeInfo()
        XCTAssertEqual(coverQueryInfo.hiddenRetrieval?.mode, .coverQuery)
    }

    func testHiddenRetrievalPIROperationalValidatorRequiresPaddingAndFixedResponses() {
        let support = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            replicatedXorPIRReplicas: [
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir-a.example.org", port: 443, useTLS: true, transport: .http)
                ),
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-b",
                    operatorId: "operator-b",
                    endpoint: RelayEndpoint(host: "pir-b.example.org", port: 443, useTLS: true, transport: .http)
                )
            ]
        )

        let weak = HiddenRetrievalPIROperationalProfile(
            support: support,
            paddedRecordCount: 16,
            fixedResponseSize: nil
        )
        XCTAssertEqual(
            HiddenRetrievalPIROperationalValidator.issues(for: weak),
            [.missingFixedResponseSize, .paddedRecordCountTooSmall]
        )
        XCTAssertFalse(HiddenRetrievalPIROperationalValidator.isOperationallyUsable(weak))

        let operational = HiddenRetrievalPIROperationalProfile(
            support: support,
            paddedRecordCount: 256,
            fixedResponseSize: 2_048
        )
        XCTAssertTrue(HiddenRetrievalPIROperationalValidator.issues(for: operational).isEmpty)
        XCTAssertTrue(HiddenRetrievalPIROperationalValidator.isOperationallyUsable(operational))
        XCTAssertNoThrow(try HiddenRetrievalPIROperationalValidator.validate(operational))
    }

    func testHiddenRetrievalPIROperationalValidatorRejectsWeakReplicaSets() {
        let weakSupport = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            replicatedXorPIRReplicas: [
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir.example.org", port: 443, useTLS: true, transport: .http)
                ),
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-b",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir.example.org", port: 8443, useTLS: true, transport: .http)
                )
            ]
        )
        let profile = HiddenRetrievalPIROperationalProfile(
            support: weakSupport,
            paddedRecordCount: 256,
            fixedResponseSize: 2_048
        )

        XCTAssertEqual(
            HiddenRetrievalPIROperationalValidator.issues(for: profile),
            [.invalidReplicaSet]
        )
        XCTAssertThrowsError(try HiddenRetrievalPIROperationalValidator.validate(profile)) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidReplicaSet)
        }
    }

    func testHiddenRetrievalPIRPromotionRequiresFreshDeploymentEvidence() {
        let now = Date(timeIntervalSince1970: 10_000)
        let replicaAEndpoint = RelayEndpoint(host: "pir-a.example.org", port: 443, useTLS: true, transport: .http)
        let replicaBEndpoint = RelayEndpoint(host: "pir-b.example.org", port: 443, useTLS: true, transport: .http)
        let support = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            replicatedXorPIRReplicas: [
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: replicaAEndpoint
                ),
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-b",
                    operatorId: "operator-b",
                    endpoint: replicaBEndpoint
                )
            ]
        )
        let profile = HiddenRetrievalPIROperationalProfile(
            support: support,
            paddedRecordCount: 256,
            fixedResponseSize: 2_048
        )

        XCTAssertEqual(
            HiddenRetrievalPIRPromotionValidator.issues(for: profile, evidence: nil, now: now),
            [.missingDeploymentEvidence]
        )

        let staleAndWeakEvidence = HiddenRetrievalPIRDeploymentEvidence(
            collectedAt: now,
            replicaEvidence: [
                HiddenRetrievalPIRReplicaDeploymentEvidence(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: replicaAEndpoint,
                    checkedAt: now.addingTimeInterval(-90_000),
                    isAvailable: true,
                    nonCollusionAttestationDigest: "same-attestation"
                ),
                HiddenRetrievalPIRReplicaDeploymentEvidence(
                    replicaId: "replica-b",
                    operatorId: "operator-b",
                    endpoint: replicaBEndpoint,
                    checkedAt: now,
                    isAvailable: false,
                    nonCollusionAttestationDigest: "same-attestation"
                )
            ]
        )
        XCTAssertEqual(
            HiddenRetrievalPIRPromotionValidator.issues(
                for: profile,
                evidence: staleAndWeakEvidence,
                now: now
            ),
            [
                .duplicateNonCollusionAttestation,
                .staleReplicaEvidence,
                .unavailableReplicaEvidence
            ]
        )

        let validEvidence = HiddenRetrievalPIRDeploymentEvidence(
            collectedAt: now,
            replicaEvidence: [
                HiddenRetrievalPIRReplicaDeploymentEvidence(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: replicaAEndpoint,
                    checkedAt: now.addingTimeInterval(-60),
                    isAvailable: true,
                    nonCollusionAttestationDigest: "operator-a-attestation-digest"
                ),
                HiddenRetrievalPIRReplicaDeploymentEvidence(
                    replicaId: "replica-b",
                    operatorId: "operator-b",
                    endpoint: replicaBEndpoint,
                    checkedAt: now.addingTimeInterval(-120),
                    isAvailable: true,
                    nonCollusionAttestationDigest: "operator-b-attestation-digest"
                )
            ]
        )
        XCTAssertTrue(
            HiddenRetrievalPIRPromotionValidator.issues(
                for: profile,
                evidence: validEvidence,
                now: now
            ).isEmpty
        )
        XCTAssertTrue(HiddenRetrievalPIRPromotionValidator.isPromotable(profile, evidence: validEvidence, now: now))
        XCTAssertNoThrow(try HiddenRetrievalPIRPromotionValidator.validate(profile, evidence: validEvidence, now: now))
    }

    func testHiddenRetrievalPIRPromotionRejectsMismatchedDeploymentEvidence() {
        let now = Date(timeIntervalSince1970: 12_000)
        let support = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            replicatedXorPIRReplicas: [
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir-a.example.org", port: 443, useTLS: true, transport: .http)
                ),
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-b",
                    operatorId: "operator-b",
                    endpoint: RelayEndpoint(host: "pir-b.example.org", port: 443, useTLS: true, transport: .http)
                )
            ]
        )
        let profile = HiddenRetrievalPIROperationalProfile(
            support: support,
            paddedRecordCount: 256,
            fixedResponseSize: 2_048
        )
        let evidence = HiddenRetrievalPIRDeploymentEvidence(
            collectedAt: now,
            replicaEvidence: [
                HiddenRetrievalPIRReplicaDeploymentEvidence(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir-a.example.org", port: 443, useTLS: true, transport: .http),
                    checkedAt: now,
                    isAvailable: true,
                    nonCollusionAttestationDigest: "attestation-a"
                ),
                HiddenRetrievalPIRReplicaDeploymentEvidence(
                    replicaId: "replica-a",
                    operatorId: "operator-b",
                    endpoint: RelayEndpoint(host: "pir-b.evil.example.org", port: 443, useTLS: true, transport: .http),
                    checkedAt: now,
                    isAvailable: true,
                    nonCollusionAttestationDigest: ""
                )
            ]
        )

        XCTAssertEqual(
            HiddenRetrievalPIRPromotionValidator.issues(for: profile, evidence: evidence, now: now),
            [
                .duplicateReplicaEvidence,
                .missingNonCollusionAttestation,
                .operatorEvidenceMismatch,
                .replicaEvidenceMismatch
            ]
        )
    }

    func testRelayConfigurationBoundsOperatorControlledCollectionsAndCounts() {
        let endpoints = (0..<300).map { index in
            RelayEndpoint(host: "relay-\(index).example.org", port: 443, useTLS: true, transport: .http)
        }
        let configuration = RelayConfiguration(
            temporalBucketSeconds: Int.max,
            temporalBucketScheduleSeconds: Array(1...100),
            attachmentDefaultTTLSeconds: Int.max,
            attachmentMaxTTLSeconds: Int.max,
            federationCoordinatorEndpoints: endpoints,
            coordinatorHeartbeatSeconds: Int.max,
            coordinatorDirectoryMaxStalenessSeconds: Int.max,
            relayPeerExchangeLimit: Int.max,
            openFederationDHTMaxRecords: Int.max,
            openFederationDHTMaxRecordsPerHost: Int.max,
            openFederationDHTMaxQueryRecords: Int.max,
            coordinatorDirectorySigningPrivateKey: Data(repeating: 1, count: 16_385),
            curatedCoordinatorQuorum: Int.max,
            federationAllowList: endpoints
        )

        XCTAssertEqual(configuration.temporalBucketSeconds, 86_400)
        XCTAssertEqual(configuration.temporalBucketScheduleSeconds?.count, 16)
        XCTAssertEqual(configuration.attachmentDefaultTTLSeconds, 2_592_000)
        XCTAssertEqual(configuration.attachmentMaxTTLSeconds, 2_592_000)
        XCTAssertEqual(configuration.federationCoordinatorEndpoints?.count, 16)
        XCTAssertEqual(configuration.coordinatorHeartbeatSeconds, 3_600)
        XCTAssertEqual(configuration.coordinatorDirectoryMaxStalenessSeconds, 86_400)
        XCTAssertEqual(configuration.relayPeerExchangeLimit, 128)
        XCTAssertEqual(configuration.openFederationDHTMaxRecords, 256)
        XCTAssertEqual(configuration.openFederationDHTMaxRecordsPerHost, 16)
        XCTAssertEqual(configuration.openFederationDHTMaxQueryRecords, 512)
        XCTAssertNil(configuration.coordinatorDirectorySigningPrivateKey)
        XCTAssertEqual(configuration.curatedCoordinatorQuorum, 16)
        XCTAssertEqual(configuration.federationAllowList.count, 256)
    }

    func testRatchetRecoveryPolicyClassifiesRecoverableFailures() throws {
        XCTAssertEqual(RatchetRecoveryPolicy.decision(for: CryptoError.invalidPayload), .recover)
        XCTAssertEqual(RatchetRecoveryPolicy.decision(for: CryptoError.counterOutOfOrder), .recover)
        XCTAssertEqual(RatchetRecoveryPolicy.decision(for: CryptoError.counterWindowExceeded), .recover)
        XCTAssertEqual(RatchetRecoveryPolicy.decision(for: CryptoError.counterReplay), .acknowledge)
        XCTAssertEqual(RatchetRecoveryPolicy.decision(for: CryptoError.invalidSignature), .acknowledge)
        XCTAssertEqual(RatchetRecoveryPolicy.decision(for: CryptoError.operationFailed), .retryLater)

        let key = SymmetricKey(size: .bits256)
        let wrongKey = SymmetricKey(size: .bits256)
        let sealed = try AES.GCM.seal(Data("message".utf8), using: key)
        XCTAssertThrowsError(try AES.GCM.open(sealed, using: wrongKey)) { error in
            XCTAssertEqual(RatchetRecoveryPolicy.decision(for: error), .recover)
        }
    }

    func testPublicRelayEndpointPolicyRejectsIPv6TransitionPrivateTargets() {
        let endpoints = [
            RelayEndpoint(host: "64:ff9b::7f00:1", port: 443, useTLS: true),
            RelayEndpoint(host: "64:ff9b::0a00:1", port: 443, useTLS: true),
            RelayEndpoint(host: "2002:0a00:0001::1", port: 443, useTLS: true),
            RelayEndpoint(host: "2001:0000:4136:e378:8000:63bf:3fff:fdd2", port: 443, useTLS: true),
            RelayEndpoint(host: "::7f00:1", port: 443, useTLS: true),
            RelayEndpoint(host: "100::1", port: 443, useTLS: true),
            RelayEndpoint(host: "fec0::1", port: 443, useTLS: true),
            RelayEndpoint(host: "3fff::1", port: 443, useTLS: true)
        ]

        for endpoint in endpoints {
            XCTAssertFalse(
                PublicRelayEndpointPolicy.permits(endpoint),
                "Expected public endpoint policy to reject \(endpoint.host)"
            )
        }
    }

    func testOpenFederationDHTRecordValidatesSignedRelayAdvertisement() throws {
        let signingKey = SigningKeyPair()
        let endpoint = RelayEndpoint(
            host: "relay.example.org",
            port: 443,
            useTLS: true,
            transport: .websocket
        )
        let record = try OpenFederationDHTRecord.signed(
            endpoint: endpoint,
            federationName: "Example Open Net",
            signingKey: signingKey
        )

        XCTAssertNoThrow(
            try record.validate(
                expectedFederationName: "example open net",
                requirePublicEndpoint: false
            )
        )
        XCTAssertEqual(record.signatureAlgorithm, OpenFederationDHTRecord.signatureAlgorithm)
        XCTAssertEqual(
            record.relayIdentityDigest,
            OpenFederationDHTRecord.relayIdentityDigest(publicKey: signingKey.publicKeyData)
        )
    }

    func testOpenFederationDHTRecordRejectsTamperedEndpoint() throws {
        let signingKey = SigningKeyPair()
        let record = try OpenFederationDHTRecord.signed(
            endpoint: RelayEndpoint(host: "relay.example.org", port: 443, useTLS: true, transport: .websocket),
            federationName: "poison-test",
            signingKey: signingKey
        )
        let tampered = OpenFederationDHTRecord(
            namespace: record.namespace,
            relayIdentityDigest: record.relayIdentityDigest,
            endpoint: RelayEndpoint(host: "evil.example.org", port: 443, useTLS: true, transport: .websocket),
            federationName: record.federationName,
            issuedAt: record.issuedAt,
            expiresAt: record.expiresAt,
            relaySigningPublicKey: record.relaySigningPublicKey,
            signature: record.signature
        )

        XCTAssertThrowsError(
            try tampered.validate(expectedFederationName: "poison-test", requirePublicEndpoint: false)
        ) { error in
            XCTAssertEqual(error as? OpenFederationDHTRecordError, .invalidSignature)
        }

        let wrongVersion = OpenFederationDHTRecord(
            version: 99,
            namespace: record.namespace,
            relayIdentityDigest: record.relayIdentityDigest,
            endpoint: record.endpoint,
            federationName: record.federationName,
            issuedAt: record.issuedAt,
            expiresAt: record.expiresAt,
            relaySigningPublicKey: record.relaySigningPublicKey,
            signature: record.signature
        )
        XCTAssertThrowsError(
            try wrongVersion.validate(expectedFederationName: "poison-test", requirePublicEndpoint: false)
        ) { error in
            XCTAssertEqual(error as? OpenFederationDHTRecordError, .unsupportedVersion)
        }

        let mislabeled = OpenFederationDHTRecord(
            namespace: record.namespace,
            relayIdentityDigest: record.relayIdentityDigest,
            endpoint: record.endpoint,
            federationName: "other-federation",
            issuedAt: record.issuedAt,
            expiresAt: record.expiresAt,
            relaySigningPublicKey: record.relaySigningPublicKey,
            signature: record.signature
        )
        XCTAssertThrowsError(
            try mislabeled.validate(expectedFederationName: "poison-test", requirePublicEndpoint: false)
        ) { error in
            XCTAssertEqual(error as? OpenFederationDHTRecordError, .federationNameMismatch)
        }
    }

    func testOpenFederationDHTRecordRejectsNamespaceMismatch() throws {
        let record = try OpenFederationDHTRecord.signed(
            endpoint: RelayEndpoint(host: "relay.example.org", port: 443, useTLS: true, transport: .websocket),
            federationName: "one-open-net",
            signingKey: SigningKeyPair()
        )

        XCTAssertThrowsError(
            try record.validate(expectedFederationName: "other-open-net", requirePublicEndpoint: false)
        ) { error in
            XCTAssertEqual(error as? OpenFederationDHTRecordError, .namespaceMismatch)
        }
    }

    func testOpenFederationDHTRecordRejectsExpiredAndOverlongRecords() throws {
        let signingKey = SigningKeyPair()
        let endpoint = RelayEndpoint(host: "relay.example.org", port: 443, useTLS: true, transport: .websocket)
        let expired = try OpenFederationDHTRecord.signed(
            endpoint: endpoint,
            federationName: "expiry-test",
            signingKey: signingKey,
            issuedAt: Date(timeIntervalSince1970: 100),
            lifetimeSeconds: 60
        )
        XCTAssertThrowsError(
            try expired.validate(expectedFederationName: "expiry-test", now: Date(), requirePublicEndpoint: false)
        ) { error in
            XCTAssertEqual(error as? OpenFederationDHTRecordError, .expired)
        }

        let overlong = OpenFederationDHTRecord(
            namespace: OpenFederationDHTRecord.namespace(federationName: "expiry-test"),
            relayIdentityDigest: OpenFederationDHTRecord.relayIdentityDigest(publicKey: signingKey.publicKeyData),
            endpoint: endpoint,
            federationName: "expiry-test",
            issuedAt: Date(timeIntervalSince1970: 100),
            expiresAt: Date(timeIntervalSince1970: 10_000),
            relaySigningPublicKey: signingKey.publicKeyData,
            signature: Data()
        )
        let signedOverlong = OpenFederationDHTRecord(
            namespace: overlong.namespace,
            relayIdentityDigest: overlong.relayIdentityDigest,
            endpoint: overlong.endpoint,
            federationName: overlong.federationName,
            issuedAt: overlong.issuedAt,
            expiresAt: overlong.expiresAt,
            relaySigningPublicKey: overlong.relaySigningPublicKey,
            signature: try signingKey.sign(NoctweaveCoder.encode(
                [
                    "endpoint": "force-invalid-signature-for-overlong-record"
                ],
                sortedKeys: true
            ))
        )
        XCTAssertThrowsError(
            try signedOverlong.validate(
                expectedFederationName: "expiry-test",
                now: Date(timeIntervalSince1970: 200),
                requirePublicEndpoint: false
            )
        ) { error in
            XCTAssertEqual(error as? OpenFederationDHTRecordError, .invalidLifetime)
        }
    }

    func testOpenFederationDHTRecordRequiresSecureHttpOrWebSocketEndpoint() throws {
        let record = try OpenFederationDHTRecord.signed(
            endpoint: RelayEndpoint(host: "relay.example.org", port: 9339, useTLS: false, transport: .tcp),
            federationName: "secure-only",
            signingKey: SigningKeyPair()
        )

        XCTAssertThrowsError(
            try record.validate(expectedFederationName: "secure-only", requirePublicEndpoint: false)
        ) { error in
            XCTAssertEqual(error as? OpenFederationDHTRecordError, .insecureEndpoint)
        }
    }

    func testOpenFederationDHTDiscoveryIsFeatureGated() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let record = try makeDHTRecord(host: "relay.example.org", federationName: "gated-net", issuedAt: now)
        var cache = OpenFederationDHTCandidateCache(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: false,
                federationName: "gated-net",
                requirePublicEndpoint: false
            )
        )

        let result = cache.ingest([record], now: now)

        XCTAssertTrue(result.accepted.isEmpty)
        XCTAssertEqual(result.rejected.map(\.reason), [.discoveryDisabled])
        XCTAssertEqual(cache.count, 0)
    }

    func testOpenFederationDHTDiscoveryAcceptsValidatedSignedRecords() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let record = try makeDHTRecord(host: "relay-a.example.org", federationName: "open-net", issuedAt: now)
        var cache = OpenFederationDHTCandidateCache(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: "open-net",
                requirePublicEndpoint: false
            )
        )

        let result = cache.ingest([record], now: now)
        let nodes = cache.federationNodes(now: now)

        XCTAssertEqual(result.accepted, [record])
        XCTAssertTrue(result.rejected.isEmpty)
        XCTAssertEqual(nodes.count, 1)
        XCTAssertEqual(nodes[0].endpoint, record.endpoint)
        XCTAssertEqual(nodes[0].relayInfo.federation.mode, .open)
        XCTAssertEqual(nodes[0].relayInfo.federation.name, "open-net")
    }

    func testOpenFederationDHTDiscoveryRejectsPoisonedRecords() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let valid = try makeDHTRecord(host: "relay-a.example.org", federationName: "open-net", issuedAt: now)
        let wrongFederation = try makeDHTRecord(host: "relay-b.example.org", federationName: "other-net", issuedAt: now)
        let tampered = OpenFederationDHTRecord(
            namespace: valid.namespace,
            relayIdentityDigest: valid.relayIdentityDigest,
            endpoint: RelayEndpoint(host: "poison.example.org", port: 443, useTLS: true, transport: .websocket),
            federationName: valid.federationName,
            issuedAt: valid.issuedAt,
            expiresAt: valid.expiresAt,
            relaySigningPublicKey: valid.relaySigningPublicKey,
            signature: valid.signature
        )
        let insecure = try makeDHTRecord(
            endpoint: RelayEndpoint(host: "plain.example.org", port: 80, useTLS: false, transport: .http),
            federationName: "open-net",
            issuedAt: now
        )
        var cache = OpenFederationDHTCandidateCache(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: "open-net",
                requirePublicEndpoint: false
            )
        )

        let result = cache.ingest([valid, wrongFederation, tampered, insecure], now: now)

        XCTAssertEqual(result.accepted, [valid])
        XCTAssertEqual(
            result.rejected.map(\.reason),
            [
                .validationFailed(.namespaceMismatch),
                .validationFailed(.invalidSignature),
                .validationFailed(.insecureEndpoint)
            ]
        )
        XCTAssertEqual(cache.records(now: now), [valid])
    }

    func testOpenFederationDHTDiscoveryCapsHostFloods() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let records = try (0..<5).map { index in
            try makeDHTRecord(host: "crowded.example.org", federationName: "open-net", issuedAt: now.addingTimeInterval(Double(index)))
        }
        var cache = OpenFederationDHTCandidateCache(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: "open-net",
                requirePublicEndpoint: false,
                maxRecords: 10,
                maxRecordsPerHost: 2
            )
        )

        let result = cache.ingest(records, now: now)

        XCTAssertEqual(result.accepted.count, 2)
        XCTAssertEqual(result.rejected.map(\.reason), [.hostLimitExceeded, .hostLimitExceeded, .hostLimitExceeded])
        XCTAssertEqual(cache.records(now: now).count, 2)
    }

    func testOpenFederationDHTDiscoveryAppliesHostCapToRelayIdentityHostMoves() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let movingKey = SigningKeyPair()
        let original = try makeDHTRecord(
            host: "original.example.org",
            federationName: "open-net",
            signingKey: movingKey,
            issuedAt: now
        )
        let crowded = try makeDHTRecord(
            host: "crowded.example.org",
            federationName: "open-net",
            issuedAt: now.addingTimeInterval(1)
        )
        let movedIntoCrowdedHost = try makeDHTRecord(
            host: "crowded.example.org",
            federationName: "open-net",
            signingKey: movingKey,
            issuedAt: now.addingTimeInterval(2)
        )
        var cache = OpenFederationDHTCandidateCache(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: "open-net",
                requirePublicEndpoint: false,
                maxRecords: 10,
                maxRecordsPerHost: 1
            )
        )

        let initial = cache.ingest([original, crowded], now: now)
        XCTAssertEqual(initial.accepted.count, 2)

        let move = cache.ingest([movedIntoCrowdedHost], now: now.addingTimeInterval(2))

        XCTAssertTrue(move.accepted.isEmpty)
        XCTAssertEqual(move.rejected.map(\.reason), [.hostLimitExceeded])
        XCTAssertEqual(
            Set(cache.records(now: now).map(\.endpoint.host)),
            ["original.example.org", "crowded.example.org"]
        )
    }

    func testOpenFederationDHTDiscoveryCapsTotalRecords() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let records = try (0..<5).map { index in
            try makeDHTRecord(
                host: "relay-\(index).example.org",
                federationName: "open-net",
                issuedAt: now.addingTimeInterval(Double(index)),
                lifetimeSeconds: 300 + Double(index)
            )
        }
        var cache = OpenFederationDHTCandidateCache(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: "open-net",
                requirePublicEndpoint: false,
                maxRecords: 3,
                maxRecordsPerHost: 2
            )
        )

        _ = cache.ingest(records, now: now)
        let keptHosts = cache.records(now: now).map(\.endpoint.host)

        XCTAssertEqual(cache.count, 3)
        XCTAssertEqual(keptHosts, ["relay-4.example.org", "relay-3.example.org", "relay-2.example.org"])
    }

    func testOpenFederationDHTDiscoveryHandlesChurnAndStaleRecords() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let signingKey = SigningKeyPair()
        let older = try makeDHTRecord(
            host: "relay.example.org",
            federationName: "open-net",
            signingKey: signingKey,
            issuedAt: now,
            lifetimeSeconds: 120
        )
        let newer = try makeDHTRecord(
            host: "relay-new.example.org",
            federationName: "open-net",
            signingKey: signingKey,
            issuedAt: now.addingTimeInterval(60),
            lifetimeSeconds: 300
        )
        var cache = OpenFederationDHTCandidateCache(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: "open-net",
                requirePublicEndpoint: false
            )
        )

        XCTAssertEqual(cache.ingest([newer, older], now: now.addingTimeInterval(60)).rejected.map(\.reason), [.staleDuplicate])
        XCTAssertEqual(cache.records(now: now.addingTimeInterval(60)), [newer])

        cache.evictExpired(now: newer.expiresAt.addingTimeInterval(1))
        XCTAssertTrue(cache.records(now: newer.expiresAt.addingTimeInterval(1)).isEmpty)
    }

    func testOpenFederationDHTDiscoveryEnginePublishesAndQueriesBehindFeatureFlag() async throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let federationName = "open-net"
        let namespace = OpenFederationDHTRecord.namespace(federationName: federationName)
        let localEndpoint = RelayEndpoint(host: "local-relay.example.org", port: 443, useTLS: true, transport: .websocket)
        let localKey = SigningKeyPair()
        let remoteRecord = try makeDHTRecord(host: "remote-relay.example.org", federationName: federationName, issuedAt: now)
        let transport = MockOpenFederationDHTTransport(recordsByNamespace: [namespace: [remoteRecord]])
        var engine = OpenFederationDHTDiscoveryEngine(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: federationName,
                requirePublicEndpoint: false,
                maxRecords: 8,
                maxRecordsPerHost: 2,
                maxQueryRecords: 16
            )
        )

        let result = try await engine.refresh(
            transport: transport,
            localEndpoint: localEndpoint,
            signingKey: localKey,
            now: now
        )

        let publishedRecords = await transport.publishedRecords()
        let lastQueryLimit = await transport.lastQueryLimit()
        XCTAssertEqual(result.publishedRecord?.endpoint, localEndpoint)
        XCTAssertEqual(publishedRecords.count, 1)
        XCTAssertEqual(lastQueryLimit, 16)
        XCTAssertEqual(Set(result.nodes.map(\.endpoint.host)), ["local-relay.example.org", "remote-relay.example.org"])
    }

    func testRelayCanServeOpenFederationDHTRecordsWhenEnabled() async throws {
        let federationName = "relay-dht-net"
        let port: UInt16 = 39489
        let serverEndpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                federation: FederationDescriptor(mode: .open, name: federationName),
                relayPeerExchangeLimit: 7,
                openFederationDHTEnabled: true,
                openFederationDHTMaxRecords: 8,
                openFederationDHTMaxRecordsPerHost: 2,
                openFederationDHTMaxQueryRecords: 4,
                allowPrivateFederationEndpoints: true
            )
        )
        let started = expectation(description: "dht relay started")
        server.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2.0)

        let client = RelayClient(endpoint: serverEndpoint)
        let infoResponse = try await client.send(.info())
        guard case .relayInfo(let relayInfo)? = infoResponse.successBody else {
            return XCTFail("Expected relay info response")
        }
        XCTAssertEqual(relayInfo.openFederationDiscovery?.dhtNodeEnabled, true)
        XCTAssertEqual(relayInfo.openFederationDiscovery?.peerExchangeLimit, 7)

        let record = try makeDHTRecord(
            host: "relay-a.dht.example.org",
            federationName: federationName,
            issuedAt: Date()
        )
        let namespace = OpenFederationDHTRecord.namespace(federationName: federationName)
        let publishResponse = try await client.send(
            .publishOpenFederationDHTRecord(
                PublishOpenFederationDHTRecordRequest(namespace: namespace, record: record)
            )
        )
        guard case .empty? = publishResponse.successBody else {
            return XCTFail("Expected DHT publish success")
        }

        let listResponse = try await client.send(
            .listOpenFederationDHTRecords(
                ListOpenFederationDHTRecordsRequest(namespace: namespace, limit: 4)
            )
        )
        guard case .dhtRecords(let records)? = listResponse.successBody else {
            return XCTFail("Expected DHT record list")
        }
        XCTAssertEqual(records.map(\.endpoint.host), ["relay-a.dht.example.org"])
    }

    func testRelayRejectsOpenFederationDHTRoutesWhenDisabled() async throws {
        let federationName = "relay-dht-disabled-net"
        let port: UInt16 = 39490
        let serverEndpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                federation: FederationDescriptor(mode: .open, name: federationName),
                openFederationDHTEnabled: false,
                allowPrivateFederationEndpoints: true
            )
        )
        let started = expectation(description: "disabled dht relay started")
        server.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2.0)

        let record = try makeDHTRecord(
            host: "relay-disabled.dht.example.org",
            federationName: federationName,
            issuedAt: Date()
        )
        let response = try await RelayClient(endpoint: serverEndpoint).send(
            .publishOpenFederationDHTRecord(
                PublishOpenFederationDHTRecordRequest(
                    namespace: OpenFederationDHTRecord.namespace(federationName: federationName),
                    record: record
                )
            )
        )
        XCTAssertEqual(response.status, .error)
        XCTAssertTrue(response.error?.message.contains("DHT-enabled") == true)
    }

    func testOpenFederationDHTDiscoveryEngineDisabledDoesNotTouchTransport() async throws {
        let transport = MockOpenFederationDHTTransport()
        var engine = OpenFederationDHTDiscoveryEngine(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: false,
                federationName: "disabled-net",
                requirePublicEndpoint: false
            )
        )

        do {
            _ = try await engine.refresh(
                transport: transport,
                localEndpoint: RelayEndpoint(host: "relay.example.org", port: 443, useTLS: true, transport: .websocket),
                signingKey: SigningKeyPair(),
                now: Date(timeIntervalSince1970: 1_000)
            )
            XCTFail("Expected disabled DHT discovery to throw before transport access")
        } catch {
            XCTAssertEqual(error as? OpenFederationDHTDiscoveryError, .disabled)
        }

        let publishedRecords = await transport.publishedRecords()
        let queryCount = await transport.queryCount()
        XCTAssertTrue(publishedRecords.isEmpty)
        XCTAssertEqual(queryCount, 0)
    }

    func testOpenFederationDHTDiscoveryEngineRejectsInvalidLocalAdvertisementBeforePublish() async throws {
        let transport = MockOpenFederationDHTTransport()
        var engine = OpenFederationDHTDiscoveryEngine(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: "public-net",
                requirePublicEndpoint: true
            )
        )

        do {
            _ = try await engine.refresh(
                transport: transport,
                localEndpoint: RelayEndpoint(host: "127.0.0.1", port: 443, useTLS: true, transport: .websocket),
                signingKey: SigningKeyPair(),
                now: Date(timeIntervalSince1970: 1_000)
            )
            XCTFail("Expected non-public local advertisement to be rejected")
        } catch {
            XCTAssertEqual(
                error as? OpenFederationDHTDiscoveryError,
                .invalidLocalAdvertisement(.nonPublicEndpoint)
            )
        }

        let publishedRecords = await transport.publishedRecords()
        let queryCount = await transport.queryCount()
        XCTAssertTrue(publishedRecords.isEmpty)
        XCTAssertEqual(queryCount, 0)
    }

    func testOpenFederationDHTDiscoveryEngineHonorsTransportQueryLimit() async throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let federationName = "limited-net"
        let namespace = OpenFederationDHTRecord.namespace(federationName: federationName)
        let records = try (0..<5).map { index in
            try makeDHTRecord(host: "relay-\(index).example.org", federationName: federationName, issuedAt: now)
        }
        let transport = MockOpenFederationDHTTransport(recordsByNamespace: [namespace: records])
        var engine = OpenFederationDHTDiscoveryEngine(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: federationName,
                requirePublicEndpoint: false,
                maxRecords: 10,
                maxRecordsPerHost: 2,
                maxQueryRecords: 2
            )
        )

        let result = try await engine.refresh(
            transport: transport,
            localEndpoint: nil,
            signingKey: nil,
            now: now
        )

        let lastQueryLimit = await transport.lastQueryLimit()
        XCTAssertEqual(lastQueryLimit, 2)
        XCTAssertEqual(result.ingestResult.accepted.count, 2)
        XCTAssertEqual(Set(result.nodes.map(\.endpoint.host)), ["relay-0.example.org", "relay-1.example.org"])
    }

    func testOpenFederationDHTDiscoveryEngineFallsBackToCachedNodesWhenQueryFails() async throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let federationName = "resilient-net"
        let namespace = OpenFederationDHTRecord.namespace(federationName: federationName)
        let cachedRecord = try makeDHTRecord(
            host: "cached-relay.example.org",
            federationName: federationName,
            issuedAt: now
        )
        let transport = MockOpenFederationDHTTransport(recordsByNamespace: [namespace: [cachedRecord]])
        var engine = OpenFederationDHTDiscoveryEngine(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: federationName,
                requirePublicEndpoint: false,
                maxRecords: 8,
                maxRecordsPerHost: 2,
                maxQueryRecords: 16
            )
        )

        let warmResult = try await engine.refresh(
            transport: transport,
            localEndpoint: nil,
            signingKey: nil,
            now: now
        )
        XCTAssertEqual(warmResult.nodes.map(\.endpoint.host), ["cached-relay.example.org"])

        await transport.setQueryFailureEnabled(true)
        let fallbackResult = try await engine.refresh(
            transport: transport,
            localEndpoint: nil,
            signingKey: nil,
            now: now.addingTimeInterval(30)
        )

        XCTAssertTrue(fallbackResult.ingestResult.accepted.isEmpty)
        XCTAssertTrue(fallbackResult.ingestResult.rejected.isEmpty)
        XCTAssertEqual(fallbackResult.nodes.map(\.endpoint.host), ["cached-relay.example.org"])
        let queryCount = await transport.queryCount()
        XCTAssertEqual(queryCount, 2)
    }

    func testOpenFederationDHTDiscoveryEngineDropsExpiredCacheWhenQueryFails() async throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let federationName = "stale-cache-net"
        let namespace = OpenFederationDHTRecord.namespace(federationName: federationName)
        let cachedRecord = try makeDHTRecord(
            host: "short-lived-relay.example.org",
            federationName: federationName,
            issuedAt: now,
            lifetimeSeconds: 10
        )
        let transport = MockOpenFederationDHTTransport(recordsByNamespace: [namespace: [cachedRecord]])
        var engine = OpenFederationDHTDiscoveryEngine(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: federationName,
                requirePublicEndpoint: false,
                maxRecords: 8,
                maxRecordsPerHost: 2,
                maxQueryRecords: 16
            )
        )

        let warmResult = try await engine.refresh(
            transport: transport,
            localEndpoint: nil,
            signingKey: nil,
            now: now
        )
        XCTAssertEqual(warmResult.nodes.map(\.endpoint.host), ["short-lived-relay.example.org"])

        await transport.setQueryFailureEnabled(true)
        let fallbackResult = try await engine.refresh(
            transport: transport,
            localEndpoint: nil,
            signingKey: nil,
            now: cachedRecord.expiresAt.addingTimeInterval(OpenFederationDHTRecord.maxClockSkewSeconds + 1)
        )

        XCTAssertTrue(fallbackResult.ingestResult.accepted.isEmpty)
        XCTAssertTrue(fallbackResult.ingestResult.rejected.isEmpty)
        XCTAssertTrue(fallbackResult.nodes.isEmpty)
        let queryCount = await transport.queryCount()
        XCTAssertEqual(queryCount, 2)
    }

    func testOpenFederationDHTHTTPGatewayTransportPublishesWithAuthHeader() async throws {
        let namespace = OpenFederationDHTRecord.namespace(federationName: "gateway-net")
        let record = try makeDHTRecord(
            host: "relay.gateway.example.org",
            federationName: "gateway-net",
            issuedAt: Date(timeIntervalSince1970: 1_000)
        )
        let protocolHarness = DHTGatewayURLProtocolHarness()
        protocolHarness.handler = { request in
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.url?.path, "/mesh/v1/open-federation/dht/records")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer gateway-token")
            let body = try XCTUnwrap(DHTGatewayURLProtocolHarness.bodyData(from: request))
            let decoded = try NoctweaveCoder.decode(DHTGatewayPublishRequestProbe.self, from: body)
            XCTAssertEqual(decoded.namespace, namespace)
            XCTAssertEqual(decoded.record, record)
            return (200, Data())
        }
        let transport = try OpenFederationDHTHTTPGatewayTransport(
            baseURL: try XCTUnwrap(URL(string: "https://gateway.example.org/mesh")),
            session: protocolHarness.makeSession(),
            authToken: " gateway-token "
        )

        try await transport.publish(record, namespace: namespace)
        XCTAssertEqual(protocolHarness.requestCount, 1)
    }

    func testOpenFederationDHTHTTPGatewayTransportQueriesRecords() async throws {
        let namespace = OpenFederationDHTRecord.namespace(federationName: "gateway-net")
        let records = try (0..<3).map { index in
            try makeDHTRecord(
                host: "relay-\(index).gateway.example.org",
                federationName: "gateway-net",
                issuedAt: Date(timeIntervalSince1970: 1_000 + Double(index))
            )
        }
        let response = try NoctweaveCoder.encode(
            DHTGatewayQueryResponseProbe(records: records),
            sortedKeys: true
        )
        let protocolHarness = DHTGatewayURLProtocolHarness()
        protocolHarness.handler = { request in
            XCTAssertEqual(request.httpMethod, "GET")
            XCTAssertEqual(request.url?.path, "/v1/open-federation/dht/records")
            let components = try XCTUnwrap(URLComponents(url: try XCTUnwrap(request.url), resolvingAgainstBaseURL: false))
            let query = Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).map { ($0.name, $0.value ?? "") })
            XCTAssertEqual(query["namespace"], namespace)
            XCTAssertEqual(query["limit"], "2")
            return (200, response)
        }
        let transport = try OpenFederationDHTHTTPGatewayTransport(
            baseURL: try XCTUnwrap(URL(string: "https://gateway.example.org")),
            session: protocolHarness.makeSession()
        )

        let queried = try await transport.query(namespace: namespace, limit: 2)
        XCTAssertEqual(queried, Array(records.prefix(2)))
        XCTAssertEqual(protocolHarness.requestCount, 1)
    }

    func testOpenFederationDHTHTTPGatewayRefreshAppliesPoisoningAndFloodGuards() async throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let federationName = "gateway-net"
        let namespace = OpenFederationDHTRecord.namespace(federationName: federationName)
        let valid = try makeDHTRecord(host: "relay-a.gateway.example.org", federationName: federationName, issuedAt: now)
        let wrongFederation = try makeDHTRecord(host: "relay-b.gateway.example.org", federationName: "other-net", issuedAt: now)
        let tampered = OpenFederationDHTRecord(
            namespace: valid.namespace,
            relayIdentityDigest: valid.relayIdentityDigest,
            endpoint: RelayEndpoint(host: "poison.gateway.example.org", port: 443, useTLS: true, transport: .websocket),
            federationName: valid.federationName,
            issuedAt: valid.issuedAt,
            expiresAt: valid.expiresAt,
            relaySigningPublicKey: valid.relaySigningPublicKey,
            signature: valid.signature
        )
        let flooded = try (0..<3).map { index in
            try makeDHTRecord(
                host: "crowded.gateway.example.org",
                federationName: federationName,
                issuedAt: now.addingTimeInterval(Double(index + 1))
            )
        }
        let response = try NoctweaveCoder.encode(
            DHTGatewayQueryResponseProbe(records: [valid, wrongFederation, tampered] + flooded),
            sortedKeys: true
        )
        let protocolHarness = DHTGatewayURLProtocolHarness()
        protocolHarness.handler = { request in
            XCTAssertEqual(request.httpMethod, "GET")
            let components = try XCTUnwrap(URLComponents(url: try XCTUnwrap(request.url), resolvingAgainstBaseURL: false))
            let query = Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).map { ($0.name, $0.value ?? "") })
            XCTAssertEqual(query["namespace"], namespace)
            XCTAssertEqual(query["limit"], "12")
            return (200, response)
        }
        let transport = try OpenFederationDHTHTTPGatewayTransport(
            baseURL: try XCTUnwrap(URL(string: "https://gateway.example.org")),
            session: protocolHarness.makeSession()
        )
        var engine = OpenFederationDHTDiscoveryEngine(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: federationName,
                requirePublicEndpoint: false,
                maxRecords: 8,
                maxRecordsPerHost: 2,
                maxQueryRecords: 12
            )
        )

        let result = try await engine.refresh(
            transport: transport,
            localEndpoint: nil,
            signingKey: nil,
            now: now
        )

        XCTAssertEqual(result.ingestResult.accepted.count, 3)
        XCTAssertEqual(
            result.ingestResult.rejected.map(\.reason),
            [
                .validationFailed(.namespaceMismatch),
                .validationFailed(.invalidSignature),
                .hostLimitExceeded
            ]
        )
        XCTAssertEqual(result.nodes.count, 3)
        XCTAssertEqual(protocolHarness.requestCount, 1)
    }

    func testOpenFederationDHTHTTPGatewayTransportRejectsOversizedResponse() async throws {
        let protocolHarness = DHTGatewayURLProtocolHarness()
        protocolHarness.handler = { _ in
            (200, Data(repeating: 0x41, count: 2_048))
        }
        let transport = try OpenFederationDHTHTTPGatewayTransport(
            baseURL: try XCTUnwrap(URL(string: "https://gateway.example.org")),
            session: protocolHarness.makeSession(),
            maxResponseBytes: 1_024
        )

        do {
            _ = try await transport.query(namespace: "oversized", limit: 1)
            XCTFail("Expected oversized DHT gateway response to be rejected")
        } catch {
            XCTAssertEqual(error as? OpenFederationDHTGatewayTransportError, .responseTooLarge)
        }
    }

    func testOpenFederationDHTHTTPGatewayTransportRejectsURLCredentialsAndAmbientQuery() async throws {
        for rawURL in [
            "https://user:password@gateway.example.org",
            "https://gateway.example.org?redirect=https://attacker.example"
        ] {
            let transport = try OpenFederationDHTHTTPGatewayTransport(
                baseURL: try XCTUnwrap(URL(string: rawURL))
            )
            do {
                _ = try await transport.query(namespace: "bounded", limit: 1)
                XCTFail("Expected unsafe gateway URL to be rejected")
            } catch {
                XCTAssertEqual(error as? OpenFederationDHTGatewayTransportError, .invalidURL)
            }
        }
    }



    func testRelationshipSafetyNumberIsSymmetricAndAuthorityBound() throws {
        let alice = try RelationshipAuthorityV2.generate(
            relationshipPseudonym: "Alice in this relationship"
        )
        let bob = try RelationshipAuthorityV2.generate(
            relationshipPseudonym: "Bob in this relationship"
        )
        let mallory = try RelationshipAuthorityV2.generate(
            relationshipPseudonym: "Mallory in this relationship"
        )
        let aliceToBob = try RelationshipSafetyNumberV2.make(
            localAuthoritySigningPublicKey: alice.signingKey.publicKeyData,
            peerAuthoritySigningPublicKey: bob.signingKey.publicKeyData
        )
        let bobToAlice = try RelationshipSafetyNumberV2.make(
            localAuthoritySigningPublicKey: bob.signingKey.publicKeyData,
            peerAuthoritySigningPublicKey: alice.signingKey.publicKeyData
        )
        let aliceToMallory = try RelationshipSafetyNumberV2.make(
            localAuthoritySigningPublicKey: alice.signingKey.publicKeyData,
            peerAuthoritySigningPublicKey: mallory.signingKey.publicKeyData
        )

        XCTAssertEqual(aliceToBob, bobToAlice)
        XCTAssertNotEqual(aliceToBob, aliceToMallory)
        XCTAssertEqual(aliceToBob.split(separator: " ").count, 12)
    }

    func testOneTimePrekeySignatureRejectsRelaySubstitution() throws {
        let authority = try RelationshipAuthorityV2.generate(
            relationshipPseudonym: "Alice"
        )
        let prekeys = try PrekeyState.generate(authority: authority, oneTimeCount: 1)
        let bundle = try prekeys.bundle(authority: authority)
        let original = try XCTUnwrap(bundle.oneTimePrekeys.first)

        XCTAssertTrue(original.verify(using: authority.signingKey.publicKeyData))

        let substituted = OneTimePrekey(
            id: original.id,
            publicKey: AgreementKeyPair().publicKeyData,
            signature: original.signature
        )
        XCTAssertFalse(substituted.verify(using: authority.signingKey.publicKeyData))
    }

    func testUnsignedOneTimePrekeyDecodeFailsClosed() throws {
        struct UnsignedOneTimePrekey: Codable {
            let id: UUID
            let publicKey: Data
        }

        let unsigned = UnsignedOneTimePrekey(
            id: UUID(),
            publicKey: AgreementKeyPair().publicKeyData
        )
        let data = try NoctweaveCoder.encode(unsigned)

        XCTAssertThrowsError(try NoctweaveCoder.decode(OneTimePrekey.self, from: data))
    }













    func testPostQuantumOperationsRejectMalformedBufferLengths() throws {
        XCTAssertThrowsError(
            try SigningKeyPair(
                privateKeyData: Data([0x01]),
                publicKeyData: Data([0x02])
            )
        )
        XCTAssertFalse(
            SigningKeyPair.verify(
                signature: Data([0x01]),
                data: Data("message".utf8),
                publicKeyData: Data([0x02])
            )
        )
        XCTAssertThrowsError(
            try AgreementKeyPair.encapsulate(to: Data([0x01]))
        )

        let validAgreementKey = AgreementKeyPair()
        XCTAssertThrowsError(
            try validAgreementKey.decapsulate(ciphertext: Data([0x01]))
        )
    }

    func testPostQuantumKeyPairsRejectMismatchedAndMalformedDecodedKeys() throws {
        let signingA = try SigningKeyPair.generate()
        let signingB = try SigningKeyPair.generate()
        XCTAssertThrowsError(
            try SigningKeyPair(
                privateKeyData: signingA.privateKeyData,
                publicKeyData: signingB.publicKeyData
            )
        )

        let agreementA = try AgreementKeyPair.generate()
        let agreementB = try AgreementKeyPair.generate()
        XCTAssertThrowsError(
            try AgreementKeyPair(
                privateKeyData: agreementA.privateKeyData,
                publicKeyData: agreementB.publicKeyData
            )
        )

        let malformedSigning = try JSONSerialization.data(withJSONObject: [
            "privateKeyData": Data([0x01]).base64EncodedString(),
            "publicKeyData": signingA.publicKeyData.base64EncodedString()
        ])
        XCTAssertThrowsError(try NoctweaveCoder.decode(SigningKeyPair.self, from: malformedSigning))
    }

    func testPostQuantumSigningSupportsEmptyMessagesAndBoundsWork() throws {
        let signing = try SigningKeyPair.generate()
        let signature = try signing.sign(Data())
        XCTAssertTrue(
            SigningKeyPair.verify(
                signature: signature,
                data: Data(),
                publicKeyData: signing.publicKeyData
            )
        )
        XCTAssertThrowsError(try signing.sign(Data(repeating: 0x41, count: 512 * 1024 + 1))) { error in
            XCTAssertEqual(error as? CryptoError, .invalidPayload)
        }
    }

    func testRelayStoreAttachmentRoundTrip() async throws {
        let store = RelayStore()
        let attachmentId = UUID()
        let payload = EncryptedPayload(
            nonce: Data(repeating: 0xA5, count: 12),
            ciphertext: Data([2, 3]),
            tag: Data(repeating: 0x5A, count: 16)
        )

        _ = try await store.storeAttachment(
            attachmentId: attachmentId,
            chunkIndex: 0,
            payload: payload,
            ttlSeconds: 60
        )

        let fetched = try await store.fetchAttachment(attachmentId: attachmentId, chunkIndex: 0)
        XCTAssertEqual(fetched?.payload, payload)
    }

    func testRelayStoreBoundsAttachmentTTLAtStoreBoundary() async throws {
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }
        let requestedURL = tempDirectory.appendingPathComponent("relay_store.json")
        let sqliteURL = tempDirectory.appendingPathComponent("relay_store.sqlite")
        let store = RelayStore(storeURL: requestedURL, temporalBucketSeconds: 0)
        let payload = EncryptedPayload(
            nonce: Data(repeating: 0xA5, count: 12),
            ciphertext: Data([2, 3]),
            tag: Data(repeating: 0x5A, count: 16)
        )

        let longTTLAttachment = UUID()
        let longTTLStart = Date()
        _ = try await store.storeAttachment(
            attachmentId: longTTLAttachment,
            chunkIndex: 0,
            payload: payload,
            ttlSeconds: 10_000_000
        )
        let longTTLExpiry = try relayAttachmentExpiry(at: sqliteURL, attachmentId: longTTLAttachment)
        XCTAssertLessThanOrEqual(longTTLExpiry.timeIntervalSince(longTTLStart), 6 * 3600 + 5)

        let shortTTLAttachment = UUID()
        let shortTTLStart = Date()
        _ = try await store.storeAttachment(
            attachmentId: shortTTLAttachment,
            chunkIndex: 0,
            payload: payload,
            ttlSeconds: -1
        )
        let shortTTLExpiry = try relayAttachmentExpiry(at: sqliteURL, attachmentId: shortTTLAttachment)
        XCTAssertGreaterThanOrEqual(shortTTLExpiry.timeIntervalSince(shortTTLStart), 55)
    }

    func testRelayStoreCanOffloadAttachmentChunksToExternalBlobStore() async throws {
        let blobStore = TestAttachmentBlobStore()
        let store = RelayStore(attachmentBlobStore: blobStore)
        let attachmentId = UUID()
        let payload = EncryptedPayload(
            nonce: Data(repeating: 0xA5, count: 12),
            ciphertext: Data([2, 3, 4]),
            tag: Data(repeating: 0x5A, count: 16)
        )

        _ = try await store.storeAttachment(
            attachmentId: attachmentId,
            chunkIndex: 1,
            payload: payload,
            ttlSeconds: 60
        )

        let fetched = try await store.fetchAttachment(attachmentId: attachmentId, chunkIndex: 1)
        XCTAssertEqual(fetched?.payload, payload)
        XCTAssertEqual(blobStore.putCount, 1)
        XCTAssertEqual(blobStore.records.values.first?.backend, "test-blob")
    }

    func testRelayStoreRejectsCorruptExternalAttachmentBlob() async throws {
        let blobStore = TestAttachmentBlobStore()
        let store = RelayStore(attachmentBlobStore: blobStore)
        let attachmentId = UUID()
        let payload = EncryptedPayload(
            nonce: Data(repeating: 0xA5, count: 12),
            ciphertext: Data([2, 3, 4]),
            tag: Data(repeating: 0x5A, count: 16)
        )

        _ = try await store.storeAttachment(
            attachmentId: attachmentId,
            chunkIndex: 0,
            payload: payload,
            ttlSeconds: 60
        )
        blobStore.corruptAll()

        do {
            _ = try await store.fetchAttachment(attachmentId: attachmentId, chunkIndex: 0)
            XCTFail("Expected corrupt external attachment blob to be rejected")
        } catch {
            XCTAssertTrue(error is AttachmentBlobStoreError || error is RelayStoreError)
        }
    }

    func testFederationDirectoryKeyLoaderDoesNotReplaceCorruptExistingKey() {
        XCTAssertTrue(FederationDirectorySignature.privateKeyData(from: Data([0xDE, 0xAD])).isEmpty)
        XCTAssertNil(FederationDirectorySignature.publicKeyData(from: Data([0xDE, 0xAD])))
    }

    func testRelayStoreRejectsInvalidAttachmentPayload() async throws {
        let store = RelayStore()
        let attachmentId = UUID()
        let payload = EncryptedPayload(
            nonce: Data([1]),
            ciphertext: Data([2, 3]),
            tag: Data([4])
        )

        do {
            _ = try await store.storeAttachment(
                attachmentId: attachmentId,
                chunkIndex: 0,
                payload: payload,
                ttlSeconds: 60
            )
            XCTFail("Expected invalid attachment payload to be rejected.")
        } catch RelayStoreError.invalidAttachmentPayload {
            // Expected.
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    private func relayAttachmentExpiry(at sqliteURL: URL, attachmentId: UUID) throws -> Date {
        var db: OpaquePointer?
        guard sqlite3_open(sqliteURL.path, &db) == SQLITE_OK, let db else {
            throw NSError(domain: "NoctweaveCoreTests.SQLite", code: 10)
        }
        defer { sqlite3_close(db) }

        let sql = "SELECT expires_at FROM relay_attachment_chunks WHERE attachment_id = ?1 LIMIT 1;"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
            throw NSError(domain: "NoctweaveCoreTests.SQLite", code: 11)
        }
        defer { sqlite3_finalize(statement) }

        guard sqlite3_bind_text(statement, 1, attachmentId.uuidString, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self)) == SQLITE_OK else {
            throw NSError(domain: "NoctweaveCoreTests.SQLite", code: 12)
        }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw NSError(domain: "NoctweaveCoreTests.SQLite", code: 13)
        }
        return Date(timeIntervalSince1970: sqlite3_column_double(statement, 0))
    }

    func testClientStateStoreRejectsOversizedStateBeforeReadingIt() async throws {
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: temp) }
        try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
        let fileURL = temp.appendingPathComponent("oversized-state.json")
        XCTAssertTrue(FileManager.default.createFile(atPath: fileURL.path, contents: Data([0x00])))
        let handle = try FileHandle(forWritingTo: fileURL)
        try handle.truncate(atOffset: UInt64(ClientStateStore.maximumStoredBytes + 1))
        try handle.close()

        let store = ClientStateStore(fileURL: fileURL, useEncryption: false)
        do {
            _ = try await store.load()
            XCTFail("Expected oversized state to be rejected before decoding")
        } catch {
            // Expected: the sparse file exceeds the hard storage bound.
        }
    }

    func testRelayInfoAdvertisesPasswordRequirement() throws {
        let openRelay = RelayConfiguration(accessPassword: nil)
        XCTAssertEqual(openRelay.makeInfo().requiresPassword, false)
        XCTAssertEqual(openRelay.makeInfo().attachmentDefaultTTLSeconds, 3600)
        XCTAssertEqual(openRelay.makeInfo().attachmentMaxTTLSeconds, 21600)

        let protectedRelay = RelayConfiguration(accessPassword: "  relay-secret  ")
        XCTAssertEqual(protectedRelay.makeInfo().requiresPassword, true)

        let curatedRelay = RelayConfiguration(
            federation: FederationDescriptor(mode: .curated, name: "mesh-test"),
            curatedStrictPolicyEnabled: true,
            curatedCoordinatorQuorum: 2,
            curatedRequireSignedDirectory: true
        )
        let curatedInfo = curatedRelay.makeInfo()
        XCTAssertEqual(curatedInfo.curatedStrictPolicyEnabled, true)
        XCTAssertEqual(curatedInfo.curatedCoordinatorQuorum, 2)
        XCTAssertEqual(curatedInfo.curatedRequireSignedDirectory, true)
    }

    func testRelayInfoAdvertisesTemporalBucketSchedule() throws {
        let relay = RelayConfiguration(
            temporalBucketSeconds: 300,
            temporalBucketScheduleSeconds: [60, 120, 300],
            attachmentDefaultTTLSeconds: 1200,
            attachmentMaxTTLSeconds: 7200
        )
        let info = relay.makeInfo()
        XCTAssertEqual(info.temporalBucketSeconds, 300)
        XCTAssertEqual(info.temporalBucketScheduleSeconds ?? [], [60, 120, 300])
        XCTAssertEqual(info.attachmentDefaultTTLSeconds, 1200)
        XCTAssertEqual(info.attachmentMaxTTLSeconds, 7200)

        let encoded = try NoctweaveCoder.encode(info)
        let decoded = try NoctweaveCoder.decode(RelayInfo.self, from: encoded)
        XCTAssertEqual(decoded.temporalBucketScheduleSeconds ?? [], [60, 120, 300])
        XCTAssertEqual(decoded.attachmentDefaultTTLSeconds, 1200)
        XCTAssertEqual(decoded.attachmentMaxTTLSeconds, 7200)
    }

    func testRelayConfigurationNormalizesAttachmentTTLPolicy() {
        let relay = RelayConfiguration(
            attachmentDefaultTTLSeconds: 30,
            attachmentMaxTTLSeconds: 45,
            attachmentsEnabled: false
        )
        XCTAssertEqual(relay.attachmentDefaultTTLSeconds, 60)
        XCTAssertEqual(relay.attachmentMaxTTLSeconds, 60)
        XCTAssertEqual(relay.makeInfo().attachmentsEnabled, false)
    }

    func testRelayHTTPResponsesIncludeSecurityHeaders() {
        var headerLines: [String] = []
        RelayHTTPSecurityHeaders.append(to: &headerLines)
        let headers = Dictionary(
            uniqueKeysWithValues: headerLines.compactMap { line -> (String, String)? in
                guard let separator = line.firstIndex(of: ":") else {
                    return nil
                }
                let name = String(line[..<separator]).lowercased()
                let value = line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces)
                return (name, value)
            }
        )

        XCTAssertEqual(headers["cache-control"], "no-store")
        XCTAssertEqual(headers["pragma"], "no-cache")
        XCTAssertEqual(headers["x-content-type-options"], "nosniff")
        XCTAssertEqual(headers["x-frame-options"], "DENY")
        XCTAssertEqual(headers["referrer-policy"], "no-referrer")
        XCTAssertEqual(headers["cross-origin-resource-policy"], "same-origin")
        XCTAssertEqual(headers["content-security-policy"], "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        XCTAssertEqual(headers["permissions-policy"], "camera=(), microphone=(), geolocation=(), interest-cohort=()")
    }

    func testRelayRequestRateLimiterCapsSourceWindow() async {
        let limiter = RelayRequestRateLimiter(maxRequests: 2, windowSeconds: 60)
        let now = Date(timeIntervalSince1970: 1_800_000_000)

        let first = await limiter.allow(sourceKey: "client-a", now: now)
        let second = await limiter.allow(sourceKey: "client-a", now: now.addingTimeInterval(1))
        let capped = await limiter.allow(sourceKey: "client-a", now: now.addingTimeInterval(2))
        let otherSource = await limiter.allow(sourceKey: "client-b", now: now.addingTimeInterval(2))
        let afterWindow = await limiter.allow(sourceKey: "client-a", now: now.addingTimeInterval(61))

        XCTAssertTrue(first)
        XCTAssertTrue(second)
        XCTAssertFalse(capped)
        XCTAssertTrue(otherSource)
        XCTAssertTrue(afterWindow)
    }

    func testCoordinatorRegistersAndListsFederationNodes() async throws {
        let coordinatorEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39464)
        let nodeEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39463)
        let federation = FederationDescriptor(mode: .curated, name: "mesh-a")
        let coordinator = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorRegistrationToken: "test-coordinator-registration-token"
            )
        )
        let nodeRelay = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                temporalBucketSeconds: 120
            )
        )
        let started = expectation(description: "coordinator started")
        coordinator.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        let startedNode = expectation(description: "node relay started")
        nodeRelay.onEvent = { event in
            if case .started = event {
                startedNode.fulfill()
            }
        }
        try coordinator.start(host: "0.0.0.0", port: coordinatorEndpoint.port)
        try nodeRelay.start(host: "0.0.0.0", port: nodeEndpoint.port)
        defer { coordinator.stop() }
        defer { nodeRelay.stop() }
        await fulfillment(of: [started, startedNode], timeout: 5.0)

        let client = RelayClient(
            endpoint: coordinatorEndpoint,
            authToken: "test-coordinator-registration-token"
        )
        let nodeInfo = RelayConfiguration(
            kind: .standard,
            federation: federation,
            temporalBucketSeconds: 120
        ).makeInfo()

        let registerResponse = try await client.send(
            .registerFederationNode(
                FederationNodeRegistrationRequest(
                    endpoint: nodeEndpoint,
                    relayInfo: nodeInfo,
                    ttlSeconds: 120
                )
            )
        )
        guard case .federationNodes(let registrationDirectory)? = registerResponse.successBody else {
            return XCTFail("Expected federation registration response")
        }
        XCTAssertEqual(registrationDirectory.nodes.first?.endpoint, nodeEndpoint)

        let listResponse = try await client.send(
            .listFederationNodes(
                ListFederationNodesRequest(
                    mode: .curated,
                    federationName: "mesh-a",
                    onlyHealthy: true,
                    requireSignedSnapshot: true
                )
            )
        )
        guard case .federationNodes(let listedDirectory)? = listResponse.successBody else {
            return XCTFail("Expected federation directory response")
        }
        XCTAssertEqual(listedDirectory.nodes.count, 1)
        XCTAssertEqual(listedDirectory.nodes.first?.endpoint, nodeEndpoint)
        let snapshot = try XCTUnwrap(listedDirectory.snapshot)
        XCTAssertGreaterThan(snapshot.validUntil, Date())

        let infoResponse = try await client.send(.info())
        guard case .relayInfo(let coordinatorInfo)? = infoResponse.successBody else {
            return XCTFail("Expected coordinator info response")
        }
        XCTAssertEqual(coordinatorInfo.kind, .coordinator)
        XCTAssertEqual(coordinatorInfo.coordinatorReportedRelayCount, 1)
        let publicKey = try XCTUnwrap(coordinatorInfo.federationDirectoryPublicKey)
        XCTAssertTrue(FederationDirectorySignature.verify(snapshot: snapshot, trustedPublicKey: publicKey))
    }

    func testCoordinatorRegistrationTokenIsEnforcedWhenConfigured() async throws {
        let coordinatorEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39486)
        let nodeEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39487)
        let token = "mesh-secret-token"
        let federation = FederationDescriptor(mode: .curated, name: "mesh-token")
        let coordinator = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorRegistrationToken: token
            )
        )
        let nodeRelay = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation
            )
        )
        let started = expectation(description: "coordinator token started")
        coordinator.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        let startedNode = expectation(description: "coordinator token node started")
        nodeRelay.onEvent = { event in
            if case .started = event {
                startedNode.fulfill()
            }
        }
        try coordinator.start(host: "0.0.0.0", port: coordinatorEndpoint.port)
        try nodeRelay.start(host: "0.0.0.0", port: nodeEndpoint.port)
        defer { coordinator.stop() }
        defer { nodeRelay.stop() }
        await fulfillment(of: [started, startedNode], timeout: 2.0)

        let client = RelayClient(endpoint: coordinatorEndpoint)
        let request = RelayRequest.registerFederationNode(
            FederationNodeRegistrationRequest(
                endpoint: nodeEndpoint,
                relayInfo: RelayConfiguration(
                    kind: .standard,
                    federation: federation
                ).makeInfo(),
                ttlSeconds: 120
            )
        )

        let unauthorized = try await client.send(request)
        XCTAssertEqual(unauthorized.status, .error)
        XCTAssertEqual(unauthorized.error?.message, "Unauthorized: coordinator registration token is required.")

        let wrongToken = try await client.send(request.withAuthToken("wrong-token"))
        XCTAssertEqual(wrongToken.status, .error)
        XCTAssertEqual(wrongToken.error?.message, "Unauthorized: coordinator registration token is required.")

        let authorized = try await client.send(request.withAuthToken(token))
        guard case .federationNodes(let directory)? = authorized.successBody else {
            return XCTFail("Expected authorized federation registration response")
        }
        XCTAssertEqual(directory.nodes.count, 1)
    }

    func testCuratedCoordinatorFailsClosedWithoutRegistrationToken() async throws {
        let coordinatorEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39488)
        let federation = FederationDescriptor(mode: .curated, name: "mesh-token-required")
        let coordinator = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(kind: .coordinator, federation: federation)
        )
        let started = expectation(description: "curated coordinator without token started")
        coordinator.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        try coordinator.start(host: "127.0.0.1", port: coordinatorEndpoint.port)
        defer { coordinator.stop() }
        await fulfillment(of: [started], timeout: 2.0)

        let response = try await RelayClient(endpoint: coordinatorEndpoint).send(
            .registerFederationNode(
                FederationNodeRegistrationRequest(
                    endpoint: RelayEndpoint(host: "127.0.0.1", port: 39999),
                    relayInfo: RelayConfiguration(kind: .standard, federation: federation).makeInfo(),
                    ttlSeconds: 120
                )
            )
        )

        XCTAssertEqual(response.status, .error)
        XCTAssertEqual(
            response.error?.message,
            "Coordinator configuration error: curated registration requires a token."
        )
    }

    func testFederationNodeListingRespectsMaxStaleness() async throws {
        let store = RelayStore(storeURL: nil, temporalBucketSeconds: 300)
        let federation = FederationDescriptor(mode: .open, name: "mesh-stale")
        let endpoint = RelayEndpoint(host: "relay-stale.example", port: 9339)
        let info = RelayConfiguration(kind: .standard, federation: federation).makeInfo(now: Date())
        _ = try await store.registerFederationNode(
            FederationNodeRegistrationRequest(
                endpoint: endpoint,
                relayInfo: info,
                ttlSeconds: 120
            )
        )
        try await Task.sleep(nanoseconds: 2_100_000_000)
        let staleFiltered = await store.listFederationNodes(
            ListFederationNodesRequest(
                mode: .open,
                federationName: "mesh-stale",
                onlyHealthy: true,
                maxStalenessSeconds: 1
            )
        )
        XCTAssertTrue(staleFiltered.isEmpty)
    }

    func testCoordinatorRegistrationTTLIsBounded() async throws {
        let store = RelayStore(storeURL: nil, temporalBucketSeconds: 300)
        let federation = FederationDescriptor(mode: .open, name: "bounded-ttl")
        let record = try await store.registerFederationNode(
            FederationNodeRegistrationRequest(
                endpoint: RelayEndpoint(host: "relay.example.org", port: 443, useTLS: true),
                relayInfo: RelayConfiguration(kind: .standard, federation: federation).makeInfo(),
                ttlSeconds: Int.max
            )
        )

        XCTAssertGreaterThanOrEqual(record.expiresAt.timeIntervalSince(record.lastHeartbeatAt), 899)
        XCTAssertLessThanOrEqual(record.expiresAt.timeIntervalSince(record.lastHeartbeatAt), 901)
    }

    func testRelayConfigurationRuntimeUpdatesAreThreadSafe() {
        let server = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: FederationDescriptor(mode: .manual, name: "race-a")
            )
        )
        let queue = DispatchQueue(label: "NoctweaveTests.RelayConfigurationRace", attributes: .concurrent)
        let group = DispatchGroup()
        let iterations = 250

        for index in 0..<iterations {
            group.enter()
            queue.async {
                let endpoint = RelayEndpoint(
                    host: "relay-\(index).example.org",
                    port: UInt16(9_000 + index)
                )
                server.updateFederationRuntimeSettings(
                    from: RelayConfiguration(
                        kind: .standard,
                        federation: FederationDescriptor(
                            mode: index.isMultiple(of: 2) ? .manual : .curated,
                            name: "race-\(index)"
                        ),
                        federationCoordinatorEndpoints: [endpoint],
                        coordinatorHeartbeatSeconds: 15 + index,
                        coordinatorDirectoryMaxStalenessSeconds: 30 + index,
                        federationAllowList: [endpoint]
                    )
                )
                group.leave()
            }

            group.enter()
            queue.async {
                let snapshot = server.configuration
                _ = snapshot.makeInfo()
                _ = snapshot.federationAllowList
                _ = snapshot.federationCoordinatorEndpoints
                group.leave()
            }
        }

        XCTAssertEqual(group.wait(timeout: .now() + 5), .success)
        let final = server.configuration
        XCTAssertFalse(final.federation.name?.isEmpty ?? true)
    }

    func testAttachmentCryptoRoundTrip() throws {
        let attachmentId = UUID()
        let plaintext = Data("image-bytes".utf8)
        let counter: UInt64 = 7
        let messageKey = SymmetricKey(size: .bits256)
        let aad = AttachmentCrypto.authenticatedData(
            conversationId: "direct-v4-conversation",
            sessionId: "direct-v4-session",
            messageCounter: counter,
            attachmentId: attachmentId,
            chunkIndex: 0,
            byteCount: plaintext.count
        )
        let encrypted = try AttachmentCrypto.encryptChunk(
            plaintext: plaintext,
            messageKey: messageKey,
            attachmentId: attachmentId,
            chunkIndex: 0,
            authenticatedData: aad
        )
        let decrypted = try AttachmentCrypto.decryptChunk(
            payload: encrypted,
            messageKey: messageKey,
            attachmentId: attachmentId,
            chunkIndex: 0,
            authenticatedData: aad
        )
        XCTAssertEqual(decrypted, plaintext)
    }

    func testAttachmentMessageBodyRoundTrip() throws {
        let descriptor = AttachmentDescriptor(
            fileName: nil,
            mimeType: "image/jpeg",
            byteCount: 123,
            sha256: Data([0x01, 0x02]),
            chunkCount: 1,
            chunkSize: 123
        )
        let body = MessageBody.attachment(descriptor)
        let data = try NoctweaveCoder.encode(body)
        let decoded = try NoctweaveCoder.decode(MessageBody.self, from: data)
        XCTAssertEqual(decoded, body)
    }

    func testAttachmentDescriptorStructuralValidationEnforcesPrivacyAndResourceBounds() {
        let valid = AttachmentDescriptor(
            fileName: nil,
            mimeType: "image/jpeg",
            byteCount: 65_537,
            sha256: Data(repeating: 0x42, count: 32),
            chunkCount: 2,
            chunkSize: 65_536,
            relayTTLSeconds: 1_800
        )
        XCTAssertTrue(valid.isStructurallyValid())

        let leakedName = AttachmentDescriptor(
            fileName: "../../private.jpg",
            mimeType: valid.mimeType,
            byteCount: valid.byteCount,
            sha256: valid.sha256,
            chunkCount: valid.chunkCount,
            chunkSize: valid.chunkSize
        )
        XCTAssertFalse(leakedName.isStructurallyValid())

        let excessiveChunks = AttachmentDescriptor(
            fileName: nil,
            mimeType: valid.mimeType,
            byteCount: 129 * 1_024,
            sha256: valid.sha256,
            chunkCount: 129,
            chunkSize: 1_024
        )
        XCTAssertFalse(excessiveChunks.isStructurallyValid())

        let injectedMIME = AttachmentDescriptor(
            fileName: nil,
            mimeType: "image/jpeg\r\nX-Injected: true",
            byteCount: 1,
            sha256: valid.sha256,
            chunkCount: 1,
            chunkSize: 1
        )
        XCTAssertFalse(injectedMIME.isStructurallyValid())
    }


    func testMessageDecodingAllowsMissingOptionalSenderDisplayName() throws {
        let json = """
        {
          "id": "E5C22757-5D8E-4F67-A2C1-73092E5B5E8E",
          "direction": "received",
          "body": "hello",
          "timestamp": "2026-02-16T00:00:00Z",
          "counter": 1,
          "isMismatch": false
        }
        """
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let message = try decoder.decode(Message.self, from: Data(json.utf8))
        XCTAssertNil(message.senderDisplayName)
        XCTAssertEqual(message.body, "hello")
    }

    func testOnionTransportPeelsThreeHopsInOrder() throws {
        let hop1 = AgreementKeyPair()
        let hop2 = AgreementKeyPair()
        let hop3 = AgreementKeyPair()
        let finalPayload = Data("fixed-size-message-frame".utf8)
        let packet = try OnionTransport.seal(
            finalPayload: finalPayload,
            hops: [
                OnionHopDescriptor(
                    hopId: "relay-a",
                    publicKeyData: hop1.publicKeyData,
                    routingInstruction: "forward:relay-b",
                    delayBucketSeconds: 60
                ),
                OnionHopDescriptor(
                    hopId: "relay-b",
                    publicKeyData: hop2.publicKeyData,
                    routingInstruction: "forward:relay-c",
                    delayBucketSeconds: 120
                ),
                OnionHopDescriptor(
                    hopId: "relay-c",
                    publicKeyData: hop3.publicKeyData,
                    routingInstruction: "deliver:opaque-route",
                    delayBucketSeconds: 300
                )
            ]
        )

        XCTAssertEqual(packet.entryHopId, "relay-a")
        let first = try OnionTransport.peel(layer: packet.layer, using: hop1)
        XCTAssertEqual(first.routingInstruction, "forward:relay-b")
        XCTAssertEqual(first.nextHopId, "relay-b")
        XCTAssertNil(first.finalPayload)

        let secondLayer = try XCTUnwrap(first.nextLayer)
        let second = try OnionTransport.peel(layer: secondLayer, using: hop2)
        XCTAssertEqual(second.routingInstruction, "forward:relay-c")
        XCTAssertEqual(second.nextHopId, "relay-c")
        XCTAssertNil(second.finalPayload)

        let thirdLayer = try XCTUnwrap(second.nextLayer)
        let third = try OnionTransport.peel(layer: thirdLayer, using: hop3)
        XCTAssertEqual(third.routingInstruction, "deliver:opaque-route")
        XCTAssertNil(third.nextHopId)
        XCTAssertNil(third.nextLayer)
        XCTAssertEqual(third.finalPayload, finalPayload)
    }

    func testOnionTransportRejectsWrongHopKey() throws {
        let intendedHop = AgreementKeyPair()
        let wrongHop = AgreementKeyPair()
        let packet = try OnionTransport.seal(
            finalPayload: Data("payload".utf8),
            hops: [
                OnionHopDescriptor(
                    hopId: "relay-a",
                    publicKeyData: intendedHop.publicKeyData,
                    routingInstruction: "deliver"
                )
            ]
        )

        XCTAssertThrowsError(try OnionTransport.peel(layer: packet.layer, using: wrongHop))
    }

    func testOnionTransportRejectsTamperedLayer() throws {
        let hop = AgreementKeyPair()
        let packet = try OnionTransport.seal(
            finalPayload: Data("payload".utf8),
            hops: [
                OnionHopDescriptor(
                    hopId: "relay-a",
                    publicKeyData: hop.publicKeyData,
                    routingInstruction: "deliver"
                )
            ]
        )
        var tamperedTag = packet.layer.payload.tag
        tamperedTag.append(0x01)
        let tamperedLayer = OnionLayer(
            hopId: packet.layer.hopId,
            kemCiphertext: packet.layer.kemCiphertext,
            payload: EncryptedPayload(
                nonce: packet.layer.payload.nonce,
                ciphertext: packet.layer.payload.ciphertext,
                tag: tamperedTag
            )
        )

        XCTAssertThrowsError(try OnionTransport.peel(layer: tamperedLayer, using: hop))
    }

    func testRelayInfoAdvertisesOptionalOnionTransportSupport() throws {
        let info = RelayConfiguration(
            onionTransport: OnionTransportSupport(enabled: true, maxHops: 5, requiresFixedSizePackets: true)
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))

        XCTAssertEqual(info.onionTransport?.enabled, true)
        XCTAssertEqual(info.onionTransport?.maxHops, 5)
        XCTAssertEqual(info.onionTransport?.requiresFixedSizePackets, true)

        let decoded = try NoctweaveCoder.decode(RelayInfo.self, from: NoctweaveCoder.encode(info))
        XCTAssertEqual(decoded.onionTransport, info.onionTransport)
    }

    func testRelayInfoSuppressesUnusableOnionTransportSupport() {
        let disabledInfo = RelayConfiguration(
            onionTransport: OnionTransportSupport(enabled: false, maxHops: 5, requiresFixedSizePackets: true)
        ).makeInfo()
        XCTAssertNil(disabledInfo.onionTransport)

        let oneHopInfo = RelayConfiguration(
            onionTransport: OnionTransportSupport(enabled: true, maxHops: 1, requiresFixedSizePackets: true)
        ).makeInfo()
        XCTAssertNil(oneHopInfo.onionTransport)

        XCTAssertEqual(
            OnionTransportPolicyValidator.issues(for: OnionTransportSupport(enabled: true, maxHops: 1)),
            [.insufficientHops]
        )
    }

    func testMixnetSchedulerBuildsDeterministicBatchWithCoverTraffic() throws {
        let policy = MixnetTransportSupport(
            batchIntervalSeconds: 30,
            minBatchSize: 5,
            coverPacketsPerBatch: 1,
            maxDelaySeconds: 10
        )
        let now = Date(timeIntervalSince1970: 1_000)
        let secret = Data("mixnet-test-secret".utf8)
        let first = try MixnetScheduler.makeBatchPlan(
            pendingPacketIds: ["msg-c", "msg-a", "msg-b"],
            now: now,
            policy: policy,
            secret: secret
        )
        let second = try MixnetScheduler.makeBatchPlan(
            pendingPacketIds: ["msg-b", "msg-c", "msg-a"],
            now: now,
            policy: policy,
            secret: secret
        )

        XCTAssertEqual(first, second)
        XCTAssertEqual(first.realPacketCount, 3)
        XCTAssertEqual(first.coverPacketCount, 2)
        XCTAssertEqual(first.packets.count, 5)
        XCTAssertTrue(first.packets.allSatisfy { $0.batchId == first.batchId })
        XCTAssertTrue(first.packets.allSatisfy { $0.releaseAt == first.releaseAt })
        XCTAssertLessThanOrEqual(first.packets.first?.delaySeconds ?? 0, 10)
    }

    func testMixnetSchedulerCanEmitPureCoverBatch() throws {
        let policy = MixnetTransportSupport(
            batchIntervalSeconds: 60,
            minBatchSize: 3,
            coverPacketsPerBatch: 3,
            maxDelaySeconds: 0
        )
        let plan = try MixnetScheduler.makeBatchPlan(
            pendingPacketIds: [],
            now: Date(timeIntervalSince1970: 1_001),
            policy: policy,
            secret: Data("cover-secret".utf8)
        )

        XCTAssertEqual(plan.realPacketCount, 0)
        XCTAssertEqual(plan.coverPacketCount, 3)
        XCTAssertEqual(plan.releaseAt, Date(timeIntervalSince1970: 1_020))
        XCTAssertTrue(plan.packets.allSatisfy { $0.packetId.hasPrefix("cover-") })
    }

    func testMixnetSchedulerBuildsContinuousCoverCycle() throws {
        let policy = MixnetTransportSupport(
            batchIntervalSeconds: 30,
            minBatchSize: 4,
            coverPacketsPerBatch: 2,
            maxDelaySeconds: 10
        )
        let now = Date(timeIntervalSince1970: 1_001)
        let secret = Data("cycle-secret".utf8)

        let first = try MixnetScheduler.makeCoverCyclePlan(
            pendingPacketIdsByBatch: [
                ["message-a", "message-b"],
                [],
                ["message-c"]
            ],
            now: now,
            policy: policy,
            secret: secret,
            horizonSeconds: 95
        )
        let second = try MixnetScheduler.makeCoverCyclePlan(
            pendingPacketIdsByBatch: [
                ["message-b", "message-a"],
                [],
                ["message-c"]
            ],
            now: now,
            policy: policy,
            secret: secret,
            horizonSeconds: 95
        )

        XCTAssertEqual(first, second)
        XCTAssertTrue(first.coversEveryInterval)
        XCTAssertEqual(first.cycleStart, Date(timeIntervalSince1970: 1_020))
        XCTAssertEqual(first.batchIntervalSeconds, 30)
        XCTAssertEqual(first.batches.count, 4)
        XCTAssertEqual(first.batches.map(\.realPacketCount), [2, 0, 1, 0])
        XCTAssertTrue(first.batches.allSatisfy { $0.coverPacketCount >= 2 })
        XCTAssertTrue(first.batches.allSatisfy { $0.packets.count >= policy.minBatchSize })
    }

    func testMixnetInterRelayCoverCoordinatorBuildsDeterministicLinkCoverPlan() throws {
        let policy = MixnetTransportSupport(
            batchIntervalSeconds: 30,
            minBatchSize: 4,
            coverPacketsPerBatch: 2,
            maxDelaySeconds: 10
        )
        let relays = [
            mixnetRelayPeer(id: "relay-a", operatorId: "operator-a", host: "relay-a.example"),
            mixnetRelayPeer(id: "relay-b", operatorId: "operator-b", host: "relay-b.example"),
            mixnetRelayPeer(id: "relay-c", operatorId: "operator-c", host: "relay-c.example")
        ]
        let secret = Data("inter-relay-cover-secret".utf8)

        let first = try MixnetInterRelayCoverCoordinator.makePlan(
            relays: relays,
            now: Date(timeIntervalSince1970: 1_001),
            policy: policy,
            secret: secret,
            horizonSeconds: 95,
            coverPacketsPerLink: 2
        )
        let second = try MixnetInterRelayCoverCoordinator.makePlan(
            relays: relays.reversed(),
            now: Date(timeIntervalSince1970: 1_001),
            policy: policy,
            secret: secret,
            horizonSeconds: 95,
            coverPacketsPerLink: 2
        )

        XCTAssertEqual(first, second)
        XCTAssertTrue(first.coversEveryRelayLinkEachInterval)
        XCTAssertEqual(first.cycleStart, Date(timeIntervalSince1970: 1_020))
        XCTAssertEqual(first.batches.count, 4)
        XCTAssertEqual(first.relayIds, ["relay-a", "relay-b", "relay-c"])
        XCTAssertTrue(first.batches.allSatisfy { $0.packets.count == 12 })
        XCTAssertTrue(first.batches.flatMap(\.packets).allSatisfy { $0.packetId.hasPrefix("relay-cover-") })
        XCTAssertTrue(first.batches.flatMap(\.packets).allSatisfy { $0.sourceRelayId != $0.destinationRelayId })
        XCTAssertLessThanOrEqual(first.batches.first?.packets.first?.delaySeconds ?? 0, 10)
    }

    func testMixnetInterRelayCoverCoordinatorRejectsWeakRelaySets() {
        let policy = MixnetTransportSupport(batchIntervalSeconds: 30, minBatchSize: 4, coverPacketsPerBatch: 2)
        let diverse = [
            mixnetRelayPeer(id: "relay-a", operatorId: "operator-a", host: "relay-a.example"),
            mixnetRelayPeer(id: "relay-b", operatorId: "operator-b", host: "relay-b.example")
        ]

        XCTAssertThrowsError(
            try MixnetInterRelayCoverCoordinator.makePlan(
                relays: diverse,
                now: Date(),
                policy: policy,
                secret: Data(),
                horizonSeconds: 60
            )
        ) { error in
            XCTAssertEqual(error as? MixnetInterRelayCoverError, .emptySecret)
        }
        XCTAssertThrowsError(
            try MixnetInterRelayCoverCoordinator.makePlan(
                relays: diverse,
                now: Date(),
                policy: policy,
                secret: Data("secret".utf8),
                horizonSeconds: 0
            )
        ) { error in
            XCTAssertEqual(error as? MixnetInterRelayCoverError, .invalidHorizon)
        }
        XCTAssertThrowsError(
            try MixnetInterRelayCoverCoordinator.makePlan(
                relays: diverse,
                now: Date(),
                policy: policy,
                secret: Data("secret".utf8),
                horizonSeconds: 60,
                coverPacketsPerLink: 0
            )
        ) { error in
            XCTAssertEqual(error as? MixnetInterRelayCoverError, .invalidCoverPacketCount)
        }

        let duplicateRelay = [
            mixnetRelayPeer(id: "relay-a", operatorId: "operator-a", host: "relay-a.example"),
            mixnetRelayPeer(id: " relay-a ", operatorId: "operator-b", host: "relay-b.example")
        ]
        XCTAssertThrowsError(
            try MixnetInterRelayCoverCoordinator.makePlan(
                relays: duplicateRelay,
                now: Date(),
                policy: policy,
                secret: Data("secret".utf8),
                horizonSeconds: 60
            )
        ) { error in
            XCTAssertEqual(error as? MixnetInterRelayCoverError, .invalidRelaySet)
        }

        let sameOperator = [
            mixnetRelayPeer(id: "relay-a", operatorId: "operator-a", host: "relay-a.example"),
            mixnetRelayPeer(id: "relay-b", operatorId: "operator-a", host: "relay-b.example")
        ]
        XCTAssertThrowsError(
            try MixnetInterRelayCoverCoordinator.makePlan(
                relays: sameOperator,
                now: Date(),
                policy: policy,
                secret: Data("secret".utf8),
                horizonSeconds: 60
            )
        ) { error in
            XCTAssertEqual(error as? MixnetInterRelayCoverError, .insufficientDiversity)
        }

        let sameHost = [
            mixnetRelayPeer(id: "relay-a", operatorId: "operator-a", host: "relay-shared.example"),
            mixnetRelayPeer(id: "relay-b", operatorId: "operator-b", host: "relay-shared.example")
        ]
        XCTAssertThrowsError(
            try MixnetInterRelayCoverCoordinator.makePlan(
                relays: sameHost,
                now: Date(),
                policy: policy,
                secret: Data("secret".utf8),
                horizonSeconds: 60
            )
        ) { error in
            XCTAssertEqual(error as? MixnetInterRelayCoverError, .insufficientDiversity)
        }

        XCTAssertThrowsError(
            try MixnetInterRelayCoverCoordinator.makePlan(
                relays: [mixnetRelayPeer(id: "relay-a", operatorId: "operator-a", host: "relay-a.example", useTLS: false)],
                now: Date(),
                policy: policy,
                secret: Data("secret".utf8),
                horizonSeconds: 60
            )
        ) { error in
            XCTAssertEqual(error as? MixnetInterRelayCoverError, .invalidEndpoint)
        }
    }

    func testMixnetSchedulerRejectsMalformedInputs() {
        let policy = MixnetTransportSupport(minBatchSize: 1, coverPacketsPerBatch: 0)
        XCTAssertThrowsError(
            try MixnetScheduler.makeBatchPlan(
                pendingPacketIds: ["msg-a"],
                now: Date(),
                policy: policy,
                secret: Data()
            )
        ) { error in
            XCTAssertEqual(error as? MixnetSchedulerError, .emptySecret)
        }
        XCTAssertThrowsError(
            try MixnetScheduler.makeBatchPlan(
                pendingPacketIds: ["msg-a", " "],
                now: Date(),
                policy: policy,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? MixnetSchedulerError, .blankPacketId)
        }
        XCTAssertThrowsError(
            try MixnetScheduler.makeCoverCyclePlan(
                pendingPacketIds: [],
                now: Date(),
                policy: policy,
                secret: Data("secret".utf8),
                horizonSeconds: 0
            )
        ) { error in
            XCTAssertEqual(error as? MixnetSchedulerError, .invalidHorizon)
        }
    }

    func testMixnetPacketPadderProducesFixedSizePackets() throws {
        let shortPayload = Data("short".utf8)
        let longerPayload = Data("longer-payload".utf8)
        let fixedPayloadSize = 64

        let shortPacket = try MixnetPacketPadder.pad(
            packetId: " packet-a ",
            payload: shortPayload,
            fixedPayloadSize: fixedPayloadSize
        )
        let longerPacket = try MixnetPacketPadder.pad(
            packetId: "packet-b",
            payload: longerPayload,
            fixedPayloadSize: fixedPayloadSize
        )

        XCTAssertEqual(shortPacket.packetId, "packet-a")
        XCTAssertEqual(shortPacket.paddedPayload.count, fixedPayloadSize)
        XCTAssertEqual(longerPacket.paddedPayload.count, fixedPayloadSize)
        XCTAssertEqual(shortPacket.fixedPayloadSize, longerPacket.fixedPayloadSize)
        XCTAssertEqual(try MixnetPacketPadder.open(shortPacket), shortPayload)
        XCTAssertEqual(try MixnetPacketPadder.open(longerPacket), longerPayload)
    }

    func testMixnetPacketPadderRejectsMalformedPackets() throws {
        XCTAssertThrowsError(
            try MixnetPacketPadder.pad(packetId: " ", payload: Data("payload".utf8), fixedPayloadSize: 32)
        ) { error in
            XCTAssertEqual(error as? MixnetPacketPaddingError, .blankPacketId)
        }
        XCTAssertThrowsError(
            try MixnetPacketPadder.pad(packetId: "packet", payload: Data(), fixedPayloadSize: 32)
        ) { error in
            XCTAssertEqual(error as? MixnetPacketPaddingError, .invalidPayload)
        }
        XCTAssertThrowsError(
            try MixnetPacketPadder.pad(packetId: "packet", payload: Data("payload".utf8), fixedPayloadSize: 0)
        ) { error in
            XCTAssertEqual(error as? MixnetPacketPaddingError, .invalidFixedSize)
        }
        XCTAssertThrowsError(
            try MixnetPacketPadder.pad(packetId: "packet", payload: Data("payload".utf8), fixedPayloadSize: 3)
        ) { error in
            XCTAssertEqual(error as? MixnetPacketPaddingError, .payloadTooLarge)
        }

        let wrongSizePacket = MixnetFixedSizePacket(
            packetId: "packet",
            paddedPayload: Data(repeating: 1, count: 31),
            originalPayloadSize: 8,
            fixedPayloadSize: 32
        )
        XCTAssertThrowsError(try MixnetPacketPadder.open(wrongSizePacket)) { error in
            XCTAssertEqual(error as? MixnetPacketPaddingError, .malformedPacket)
        }

        let oversizedOriginalPacket = MixnetFixedSizePacket(
            packetId: "packet",
            paddedPayload: Data(repeating: 1, count: 32),
            originalPayloadSize: 33,
            fixedPayloadSize: 32
        )
        XCTAssertThrowsError(try MixnetPacketPadder.open(oversizedOriginalPacket)) { error in
            XCTAssertEqual(error as? MixnetPacketPaddingError, .malformedPacket)
        }
    }

    func testMixnetRouteSelectorBuildsDeterministicDiverseRoute() throws {
        let candidates = [
            mixnetRouteCandidate(id: "hop-a", operatorId: "operator-a", host: "relay-a.example"),
            mixnetRouteCandidate(id: "hop-b", operatorId: "operator-b", host: "relay-b.example"),
            mixnetRouteCandidate(id: "hop-c", operatorId: "operator-c", host: "relay-c.example"),
            mixnetRouteCandidate(id: "hop-d", operatorId: "operator-d", host: "relay-d.example")
        ]
        let secret = Data("route-secret".utf8)

        let first = try MixnetRouteSelector.makeRoutePlan(
            candidates: candidates,
            secret: secret,
            routeContext: "batch-1",
            hopCount: 3
        )
        let second = try MixnetRouteSelector.makeRoutePlan(
            candidates: candidates.reversed(),
            secret: secret,
            routeContext: "batch-1",
            hopCount: 3
        )

        XCTAssertEqual(first, second)
        XCTAssertEqual(first.selectedCandidates.count, 3)
        XCTAssertEqual(Set(first.selectedCandidates.map(\.operatorId)).count, 3)
        XCTAssertEqual(Set(first.selectedCandidates.map { $0.endpoint.host }).count, 3)
        XCTAssertEqual(first.onionHops.map(\.hopId), first.selectedCandidates.map(\.hopId))
        XCTAssertFalse(first.routeId.isEmpty)
    }

    func testMixnetRouteSelectorRejectsWeakRoutes() {
        let diverse = [
            mixnetRouteCandidate(id: "hop-a", operatorId: "operator-a", host: "relay-a.example"),
            mixnetRouteCandidate(id: "hop-b", operatorId: "operator-b", host: "relay-b.example")
        ]

        XCTAssertThrowsError(
            try MixnetRouteSelector.makeRoutePlan(
                candidates: diverse,
                secret: Data(),
                routeContext: "batch-1",
                hopCount: 2
            )
        ) { error in
            XCTAssertEqual(error as? MixnetRouteSelectionError, .emptySecret)
        }
        XCTAssertThrowsError(
            try MixnetRouteSelector.makeRoutePlan(
                candidates: diverse,
                secret: Data("route-secret".utf8),
                routeContext: "batch-1",
                hopCount: 1
            )
        ) { error in
            XCTAssertEqual(error as? MixnetRouteSelectionError, .invalidRouteLength)
        }

        let sameOperator = [
            mixnetRouteCandidate(id: "hop-a", operatorId: "operator-a", host: "relay-a.example"),
            mixnetRouteCandidate(id: "hop-b", operatorId: "operator-a", host: "relay-b.example")
        ]
        XCTAssertThrowsError(
            try MixnetRouteSelector.makeRoutePlan(
                candidates: sameOperator,
                secret: Data("route-secret".utf8),
                routeContext: "batch-1",
                hopCount: 2
            )
        ) { error in
            XCTAssertEqual(error as? MixnetRouteSelectionError, .insufficientDiversity)
        }

        let sameHost = [
            mixnetRouteCandidate(id: "hop-a", operatorId: "operator-a", host: "relay-shared.example"),
            mixnetRouteCandidate(id: "hop-b", operatorId: "operator-b", host: "relay-shared.example")
        ]
        XCTAssertThrowsError(
            try MixnetRouteSelector.makeRoutePlan(
                candidates: sameHost,
                secret: Data("route-secret".utf8),
                routeContext: "batch-1",
                hopCount: 2
            )
        ) { error in
            XCTAssertEqual(error as? MixnetRouteSelectionError, .insufficientDiversity)
        }

        XCTAssertThrowsError(
            try MixnetRouteSelector.makeRoutePlan(
                candidates: [mixnetRouteCandidate(id: "hop-a", operatorId: "operator-a", host: "relay-a.example", useTLS: false)],
                secret: Data("route-secret".utf8),
                routeContext: "batch-1",
                hopCount: 2
            )
        ) { error in
            XCTAssertEqual(error as? MixnetRouteSelectionError, .invalidEndpoint)
        }
    }

    func testRelayInfoAdvertisesOptionalMixnetTransportSupport() throws {
        let support = MixnetTransportSupport(
            enabled: true,
            batchIntervalSeconds: 45,
            minBatchSize: 12,
            coverPacketsPerBatch: 4,
            maxDelaySeconds: 90
        )
        let onion = OnionTransportSupport(enabled: true, maxHops: 3, requiresFixedSizePackets: true)
        let info = RelayConfiguration(
            onionTransport: onion,
            mixnetTransport: support
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))

        XCTAssertEqual(info.onionTransport, onion)
        XCTAssertEqual(info.mixnetTransport, support)
        let decoded = try NoctweaveCoder.decode(RelayInfo.self, from: NoctweaveCoder.encode(info))
        XCTAssertEqual(decoded.mixnetTransport, support)
    }

    func testRelayInfoSuppressesMisleadingMixnetAdvertisement() {
        let mixnet = MixnetTransportSupport(
            enabled: true,
            batchIntervalSeconds: 45,
            minBatchSize: 12,
            coverPacketsPerBatch: 4,
            maxDelaySeconds: 90
        )
        let missingOnionInfo = RelayConfiguration(mixnetTransport: mixnet).makeInfo()
        XCTAssertNil(missingOnionInfo.mixnetTransport)

        let weakOnion = OnionTransportSupport(enabled: true, maxHops: 1, requiresFixedSizePackets: false)
        let weakOnionInfo = RelayConfiguration(
            onionTransport: weakOnion,
            mixnetTransport: mixnet
        ).makeInfo()
        XCTAssertNil(weakOnionInfo.onionTransport)
        XCTAssertNil(weakOnionInfo.mixnetTransport)
    }

    func testMixnetRoutePolicyValidatorAcceptsOnionBackedCoverBatches() {
        let mixnet = MixnetTransportSupport(
            enabled: true,
            batchIntervalSeconds: 45,
            minBatchSize: 12,
            coverPacketsPerBatch: 4,
            maxDelaySeconds: 90
        )
        let onion = OnionTransportSupport(enabled: true, maxHops: 3, requiresFixedSizePackets: true)

        XCTAssertTrue(MixnetRoutePolicyValidator.isUsable(mixnetSupport: mixnet, onionSupport: onion))
        XCTAssertEqual(
            MixnetRoutePolicyValidator.issues(for: mixnet, onionSupport: onion),
            []
        )
    }

    func testMixnetRoutePolicyValidatorRejectsMisleadingMixnetAdvertisements() {
        XCTAssertEqual(
            MixnetRoutePolicyValidator.issues(for: nil, onionSupport: nil),
            [.notAdvertised]
        )

        let weakMixnet = MixnetTransportSupport(
            enabled: false,
            batchIntervalSeconds: 5,
            minBatchSize: 1,
            coverPacketsPerBatch: 0,
            maxDelaySeconds: 0
        )
        let weakOnion = OnionTransportSupport(enabled: false, maxHops: 1, requiresFixedSizePackets: false)
        let issues = MixnetRoutePolicyValidator.issues(for: weakMixnet, onionSupport: weakOnion)

        XCTAssertTrue(issues.contains(.disabled))
        XCTAssertTrue(issues.contains(.insufficientBatchSize))
        XCTAssertTrue(issues.contains(.coverTrafficDisabled))
        XCTAssertTrue(issues.contains(.batchIntervalTooShort))
        XCTAssertTrue(issues.contains(.releaseDelayDisabled))
        XCTAssertTrue(issues.contains(.onionTransportDisabled))
        XCTAssertTrue(issues.contains(.insufficientOnionHops))
        XCTAssertTrue(issues.contains(.fixedSizePacketsNotRequired))

        let missingOnion = MixnetTransportSupport(
            enabled: true,
            batchIntervalSeconds: 30,
            minBatchSize: 8,
            coverPacketsPerBatch: 2,
            maxDelaySeconds: 120
        )
        XCTAssertTrue(
            MixnetRoutePolicyValidator.issues(for: missingOnion, onionSupport: nil).contains(.missingOnionTransport)
        )
    }


    func testResendRequestRejectsUnboundedWireCounts() throws {
        XCTAssertEqual(ResendRequest(count: Int.max).count, ResendRequest.maximumCount)
        let oversized = Data("{\"count\":9223372036854775807}".utf8)
        XCTAssertThrowsError(try NoctweaveCoder.decode(ResendRequest.self, from: oversized))
        let valid = try NoctweaveCoder.decode(ResendRequest.self, from: Data("{\"count\":32}".utf8))
        XCTAssertEqual(valid.count, 32)
    }

    private func makeDHTRecord(
        host: String,
        federationName: String?,
        signingKey: SigningKeyPair = SigningKeyPair(),
        issuedAt: Date,
        lifetimeSeconds: TimeInterval = 300
    ) throws -> OpenFederationDHTRecord {
        try makeDHTRecord(
            endpoint: RelayEndpoint(host: host, port: 443, useTLS: true, transport: .websocket),
            federationName: federationName,
            signingKey: signingKey,
            issuedAt: issuedAt,
            lifetimeSeconds: lifetimeSeconds
        )
    }

    private func makeDHTRecord(
        endpoint: RelayEndpoint,
        federationName: String?,
        signingKey: SigningKeyPair = SigningKeyPair(),
        issuedAt: Date,
        lifetimeSeconds: TimeInterval = 300
    ) throws -> OpenFederationDHTRecord {
        try OpenFederationDHTRecord.signed(
            endpoint: endpoint,
            federationName: federationName,
            signingKey: signingKey,
            issuedAt: issuedAt,
            lifetimeSeconds: lifetimeSeconds
        )
    }
}

private func mixnetRouteCandidate(
    id: String,
    operatorId: String,
    host: String,
    useTLS: Bool = true
) -> MixnetRouteCandidate {
    MixnetRouteCandidate(
        hopId: id,
        operatorId: operatorId,
        endpoint: RelayEndpoint(host: host, port: 443, useTLS: useTLS, transport: .http),
        onionHop: OnionHopDescriptor(
            hopId: id,
            publicKeyData: Data("public-key-\(id)".utf8),
            routingInstruction: "route-to-\(host)",
            delayBucketSeconds: 30
        )
    )
}

private func mixnetRelayPeer(
    id: String,
    operatorId: String,
    host: String,
    useTLS: Bool = true
) -> MixnetRelayPeer {
    MixnetRelayPeer(
        relayId: id,
        operatorId: operatorId,
        endpoint: RelayEndpoint(host: host, port: 443, useTLS: useTLS, transport: .http)
    )
}

private func testBitset(recordCount: Int, enabledIndex: Int) -> Data {
    var bitset = Data(repeating: 0, count: (recordCount + 7) / 8)
    bitset[enabledIndex / 8] = UInt8(1) << UInt8(enabledIndex % 8)
    return bitset
}

private func xorTestData(_ lhs: Data, _ rhs: Data) -> Data {
    Data(zip(lhs, rhs).map { $0 ^ $1 })
}

private struct SeededGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        self.state = seed == 0 ? 0x123456789ABCDEF : seed
    }

    mutating func next() -> UInt64 {
        state = state &* 6364136223846793005 &+ 1
        return state
    }

    mutating func nextInt(upperBound: Int) -> Int {
        guard upperBound > 0 else { return 0 }
        return Int(next() % UInt64(upperBound))
    }
}

private extension Array {
    mutating func shuffle(using generator: inout SeededGenerator) {
        guard count > 1 else { return }
        for index in stride(from: count - 1, through: 1, by: -1) {
            let swapIndex = generator.nextInt(upperBound: index + 1)
            if swapIndex != index {
                swapAt(index, swapIndex)
            }
        }
    }
}

private actor MockOpenFederationDHTTransport: OpenFederationDHTTransport {
    private var recordsByNamespace: [String: [OpenFederationDHTRecord]]
    private var published: [OpenFederationDHTRecord] = []
    private var queries = 0
    private var mostRecentLimit: Int?
    private var queryFailureEnabled = false

    init(recordsByNamespace: [String: [OpenFederationDHTRecord]] = [:]) {
        self.recordsByNamespace = recordsByNamespace
    }

    func publish(_ record: OpenFederationDHTRecord, namespace: String) async throws {
        published.append(record)
        recordsByNamespace[namespace, default: []].append(record)
    }

    func query(namespace: String, limit: Int) async throws -> [OpenFederationDHTRecord] {
        queries += 1
        mostRecentLimit = limit
        if queryFailureEnabled {
            throw MockOpenFederationDHTTransportError.queryFailed
        }
        return Array((recordsByNamespace[namespace] ?? []).prefix(limit))
    }

    func publishedRecords() -> [OpenFederationDHTRecord] {
        published
    }

    func queryCount() -> Int {
        queries
    }

    func lastQueryLimit() -> Int? {
        mostRecentLimit
    }

    func setQueryFailureEnabled(_ enabled: Bool) {
        queryFailureEnabled = enabled
    }
}

private enum MockOpenFederationDHTTransportError: Error {
    case queryFailed
}

private struct DHTGatewayPublishRequestProbe: Codable {
    let namespace: String
    let record: OpenFederationDHTRecord
}

private struct DHTGatewayQueryResponseProbe: Codable {
    let records: [OpenFederationDHTRecord]
}

private final class DHTGatewayURLProtocolHarness {
    typealias Handler = (URLRequest) throws -> (status: Int, body: Data)

    private let state = LockedState()

    var handler: Handler? {
        get { state.handler }
        set { state.handler = newValue }
    }

    var requestCount: Int {
        state.requests.count
    }

    func makeSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [DHTGatewayURLProtocol.self]
        let token = UUID().uuidString
        configuration.httpAdditionalHeaders = ["X-Noctyra-Test-Token": token]
        DHTGatewayURLProtocol.register(harness: self, token: token)
        return URLSession(configuration: configuration)
    }

    fileprivate func handle(_ request: URLRequest) throws -> (status: Int, body: Data) {
        state.requests.append(request)
        guard let handler = state.handler else {
            return (500, Data())
        }
        return try handler(request)
    }

    static func bodyData(from request: URLRequest) -> Data? {
        if let body = request.httpBody {
            return body
        }
        guard let stream = request.httpBodyStream else {
            return nil
        }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count > 0 {
                data.append(buffer, count: count)
            } else {
                break
            }
        }
        return data
    }

    private final class LockedState {
        private let lock = NSLock()
        private var _handler: Handler?
        private var _requests: [URLRequest] = []

        var handler: Handler? {
            get {
                lock.lock()
                defer { lock.unlock() }
                return _handler
            }
            set {
                lock.lock()
                _handler = newValue
                lock.unlock()
            }
        }

        var requests: [URLRequest] {
            get {
                lock.lock()
                defer { lock.unlock() }
                return _requests
            }
            set {
                lock.lock()
                _requests = newValue
                lock.unlock()
            }
        }
    }
}

private final class TestAttachmentBlobStore: AttachmentBlobStore {
    let backendName = "test-blob"
    private(set) var records: [String: AttachmentExternalRecord] = [:]
    private var blobs: [String: Data] = [:]
    private(set) var putCount = 0

    func put(_ data: Data, attachmentId: UUID, chunkIndex: Int, expiresAt: Date) throws -> AttachmentExternalRecord {
        putCount += 1
        let locator = "\(attachmentId.uuidString)-\(chunkIndex)-\(putCount)"
        blobs[locator] = data
        let record = AttachmentExternalRecord(
            backend: backendName,
            locator: locator,
            byteCount: data.count,
            sha256Hex: AttachmentBlobDigest.sha256Hex(data),
            expiresAt: expiresAt
        )
        records[locator] = record
        return record
    }

    func get(_ record: AttachmentExternalRecord) throws -> Data {
        guard let data = blobs[record.locator] else {
            throw AttachmentBlobStoreError.fetchFailed("missing test blob")
        }
        guard data.count == record.byteCount,
              AttachmentBlobDigest.sha256Hex(data) == record.sha256Hex else {
            throw AttachmentBlobStoreError.digestMismatch
        }
        return data
    }

    func delete(_ record: AttachmentExternalRecord) {
        blobs.removeValue(forKey: record.locator)
        records.removeValue(forKey: record.locator)
    }

    func corruptAll() {
        blobs = blobs.mapValues { data in
            var corrupted = data
            corrupted.append(0x00)
            return corrupted
        }
    }
}

private final class DHTGatewayURLProtocol: URLProtocol {
    private static let lock = NSLock()
    private static var harnesses: [String: DHTGatewayURLProtocolHarness] = [:]

    static func register(harness: DHTGatewayURLProtocolHarness, token: String) {
        lock.lock()
        harnesses[token] = harness
        lock.unlock()
    }

    override class func canInit(with request: URLRequest) -> Bool {
        request.value(forHTTPHeaderField: "X-Noctyra-Test-Token") != nil
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let token = request.value(forHTTPHeaderField: "X-Noctyra-Test-Token"),
              let harness = Self.harness(for: token),
              let url = request.url else {
            client?.urlProtocol(self, didFailWithError: OpenFederationDHTGatewayTransportError.invalidURL)
            return
        }

        do {
            let result = try harness.handle(request)
            let response = HTTPURLResponse(
                url: url,
                statusCode: result.status,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            if !result.body.isEmpty {
                client?.urlProtocol(self, didLoad: result.body)
            }
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}

    private static func harness(for token: String) -> DHTGatewayURLProtocolHarness? {
        lock.lock()
        defer { lock.unlock() }
        return harnesses[token]
    }
}
