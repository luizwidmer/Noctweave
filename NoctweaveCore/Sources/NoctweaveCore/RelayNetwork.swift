import Foundation
import Network
import Dispatch
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Security)
import Security
#endif

enum RelayNetworkError: Error {
    case connectionFailed
    case responseTooLarge
    case invalidResponse
    case tlsConfigurationFailed(String)
}

extension NWConnection {
    func awaitReady() async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                final class ResumeGate: @unchecked Sendable {
                    private let lock = NSLock()
                    private var resumed = false

                    func claim() -> Bool {
                        lock.lock()
                        defer { lock.unlock() }
                        guard !resumed else { return false }
                        resumed = true
                        return true
                    }
                }
                let gate = ResumeGate()
                let resumeOnce: @Sendable (Result<Void, Error>) -> Void = { [self] result in
                    guard gate.claim() else { return }
                    self.stateUpdateHandler = nil
                    continuation.resume(with: result)
                }

                stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        resumeOnce(.success(()))
                    case .failed(let error):
                        resumeOnce(.failure(error))
                    case .cancelled:
                        resumeOnce(.failure(RelayNetworkError.connectionFailed))
                    default:
                        break
                    }
                }
                start(queue: DispatchQueue(label: "NoctweaveCore.RelayNetwork"))
            }
        } onCancel: { [self] in
            cancel()
        }
    }

    func sendLine(_ data: Data) async throws {
        var payload = data
        payload.append(0x0A)
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                send(content: payload, completion: .contentProcessed { error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume()
                    }
                })
            }
        } onCancel: { [self] in
            cancel()
        }
    }

    func receiveLine(maxLength: Int = 65_536) async throws -> Data {
        var buffer = Data()
        while buffer.count < maxLength {
            let chunk = try await receiveChunk()
            buffer.append(chunk)
            if let newlineIndex = buffer.firstIndex(of: 0x0A) {
                let line = buffer.prefix(upTo: newlineIndex)
                return Data(line)
            }
        }
        throw RelayNetworkError.responseTooLarge
    }

    private func receiveChunk() async throws -> Data {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                receive(minimumIncompleteLength: 1, maximumLength: 65_536) { data, _, isComplete, error in
                    if let error {
                        continuation.resume(throwing: error)
                        return
                    }
                    if isComplete && (data == nil || data?.isEmpty == true) {
                        continuation.resume(throwing: RelayNetworkError.invalidResponse)
                        return
                    }
                    continuation.resume(returning: data ?? Data())
                }
            }
        } onCancel: { [self] in
            cancel()
        }
    }
}

enum RelayNetworkTransport {
    static func clientParameters(for endpoint: RelayEndpoint) -> NWParameters {
        guard endpoint.useTLS else {
            return .tcp
        }
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(
            tls.securityProtocolOptions,
            .TLSv12
        )
        if let expectedFingerprint = endpoint.tlsCertificateFingerprintSHA256 {
            #if canImport(Security) && canImport(CryptoKit)
            sec_protocol_options_set_verify_block(
                tls.securityProtocolOptions,
                { _, trust, completion in
                    let isValid = RelayTLSVerifier.evaluateTrust(
                        trust: trust,
                        expectedLeafCertificateSHA256: expectedFingerprint
                    )
                    completion(isValid)
                },
                DispatchQueue.global(qos: .userInitiated)
            )
            #endif
        }
        return NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
    }

    static func listenerParameters(configuration: RelayConfiguration) throws -> NWParameters {
        guard configuration.tlsEnabled else {
            return .tcp
        }
        let tls = try makeServerTLSOptions(configuration: configuration)
        return NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
    }

    private static func makeServerTLSOptions(configuration: RelayConfiguration) throws -> NWProtocolTLS.Options {
        let options = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(
            options.securityProtocolOptions,
            .TLSv12
        )
        sec_protocol_options_set_peer_authentication_required(
            options.securityProtocolOptions,
            false
        )
        let identity = try loadIdentity(configuration: configuration)
        sec_protocol_options_set_local_identity(options.securityProtocolOptions, identity)
        return options
    }

    private static func loadIdentity(configuration: RelayConfiguration) throws -> sec_identity_t {
        #if canImport(Security)
        let trimmedPath = configuration.tlsIdentityPKCS12Path?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !trimmedPath.isEmpty else {
            throw RelayNetworkError.tlsConfigurationFailed("TLS is enabled but certificate path is missing.")
        }
        let password = configuration.tlsIdentityPassword ?? ""
        let expandedPath = (trimmedPath as NSString).expandingTildeInPath
        let url = URL(fileURLWithPath: expandedPath)
        let resourceValues = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
        guard resourceValues.isRegularFile == true,
              let fileSize = resourceValues.fileSize,
              fileSize > 0,
              fileSize <= 10 * 1024 * 1024 else {
            throw RelayNetworkError.tlsConfigurationFailed("PKCS#12 identity must be a regular file no larger than 10 MB.")
        }
        let data = try Data(contentsOf: url)
        var items: CFArray?
        let importOptions: [String: Any] = [
            kSecImportExportPassphrase as String: password
        ]
        let status = SecPKCS12Import(
            data as CFData,
            importOptions as CFDictionary,
            &items
        )
        guard status == errSecSuccess,
              let imported = items as? [[String: Any]],
              let first = imported.first,
              let rawIdentity = first[kSecImportItemIdentity as String],
              CFGetTypeID(rawIdentity as CFTypeRef) == SecIdentityGetTypeID() else {
            throw RelayNetworkError.tlsConfigurationFailed("Unable to load PKCS#12 identity.")
        }
        let identity = unsafeBitCast(rawIdentity as AnyObject, to: SecIdentity.self)
        guard let secIdentity = sec_identity_create(identity) else {
            throw RelayNetworkError.tlsConfigurationFailed("Unable to bridge PKCS#12 identity for Network TLS.")
        }
        return secIdentity
        #else
        throw RelayNetworkError.tlsConfigurationFailed("Security framework unavailable for TLS identity loading.")
        #endif
    }
}

#if canImport(Security) && canImport(CryptoKit)
enum RelayTLSVerifier {
    static func evaluateTrust(
        trust: sec_trust_t,
        expectedLeafCertificateSHA256: Data
    ) -> Bool {
        let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
        var error: CFError?
        guard SecTrustEvaluateWithError(secTrust, &error) else {
            return false
        }
        return trustMatchesLeafCertificateSHA256(secTrust, expectedFingerprint: expectedLeafCertificateSHA256)
    }

    static func trustMatchesLeafCertificateSHA256(_ trust: SecTrust, expectedFingerprint: Data) -> Bool {
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first else {
            return false
        }
        let data = SecCertificateCopyData(leaf) as Data
        let digest = SHA256.hash(data: data)
        return Data(digest) == expectedFingerprint
    }
}
#endif
