import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Security)
import Security
#endif

enum BoundedURLSessionLoaderError: Error, Equatable {
    case responseTooLarge
    case missingResponse
    case invalidLimit
}

public enum BoundedHTTPResponseLoader {
    public static func load(
        _ request: URLRequest,
        configuration: URLSessionConfiguration = .ephemeral,
        maximumBytes: Int,
        expectedLeafCertificateSHA256: Data? = nil
    ) async throws -> (data: Data, response: URLResponse) {
        try await BoundedURLSessionLoader.load(
            request,
            configuration: configuration,
            maximumBytes: maximumBytes,
            expectedLeafCertificateSHA256: expectedLeafCertificateSHA256
        )
    }
}

final class BoundedURLSessionLoader: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private static let absoluteMaximumBytes = 16 * 1024 * 1024
    typealias Output = (data: Data, response: URLResponse)

    private let maximumBytes: Int
    private let expectedLeafCertificateSHA256: Data?
    private let observedLeafCertificateSHA256: (@Sendable (Data) -> Void)?
    private let lock = NSLock()
    private var buffer = Data()
    private var receivedResponse: URLResponse?
    private var continuation: CheckedContinuation<Output, Error>?
    private var session: URLSession?
    private var isComplete = false

    private init(
        maximumBytes: Int,
        expectedLeafCertificateSHA256: Data?,
        observedLeafCertificateSHA256: (@Sendable (Data) -> Void)?
    ) {
        self.maximumBytes = max(1, maximumBytes)
        self.expectedLeafCertificateSHA256 = expectedLeafCertificateSHA256
        self.observedLeafCertificateSHA256 = observedLeafCertificateSHA256
    }

    static func load(
        _ request: URLRequest,
        configuration: URLSessionConfiguration = .ephemeral,
        maximumBytes: Int,
        expectedLeafCertificateSHA256: Data? = nil,
        observedLeafCertificateSHA256: (@Sendable (Data) -> Void)? = nil
    ) async throws -> Output {
        guard (1...absoluteMaximumBytes).contains(maximumBytes) else {
            throw BoundedURLSessionLoaderError.invalidLimit
        }
        let loader = BoundedURLSessionLoader(
            maximumBytes: maximumBytes,
            expectedLeafCertificateSHA256: expectedLeafCertificateSHA256,
            observedLeafCertificateSHA256: observedLeafCertificateSHA256
        )
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                loader.start(request, configuration: configuration, continuation: continuation)
            }
        } onCancel: {
            loader.cancel()
        }
    }

    private func start(
        _ request: URLRequest,
        configuration: URLSessionConfiguration,
        continuation: CheckedContinuation<Output, Error>
    ) {
        lock.lock()
        guard !isComplete else {
            lock.unlock()
            continuation.resume(throwing: CancellationError())
            return
        }
        self.continuation = continuation
        lock.unlock()

        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: queue)
        lock.lock()
        guard !isComplete else {
            lock.unlock()
            session.invalidateAndCancel()
            return
        }
        self.session = session
        lock.unlock()
        session.dataTask(with: request).resume()
    }

    private func cancel() {
        finish(.failure(CancellationError()))
    }

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        if response.expectedContentLength > Int64(maximumBytes) {
            completionHandler(.cancel)
            finish(.failure(BoundedURLSessionLoaderError.responseTooLarge))
            return
        }
        lock.lock()
        receivedResponse = response
        lock.unlock()
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        guard !isComplete else {
            lock.unlock()
            return
        }
        let exceedsLimit = data.count > maximumBytes - buffer.count
        if !exceedsLimit {
            buffer.append(data)
        }
        lock.unlock()

        if exceedsLimit {
            dataTask.cancel()
            finish(.failure(BoundedURLSessionLoaderError.responseTooLarge))
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error {
            finish(.failure(error))
            return
        }
        lock.lock()
        let response = receivedResponse
        let data = buffer
        lock.unlock()
        guard let response else {
            finish(.failure(BoundedURLSessionLoaderError.missingResponse))
            return
        }
        finish(.success((data, response)))
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard expectedLeafCertificateSHA256 != nil || observedLeafCertificateSHA256 != nil else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        #if canImport(Security) && canImport(CryptoKit)
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error),
              let observedFingerprint = RelayTLSVerifier.leafCertificateSHA256(trust),
              expectedLeafCertificateSHA256.map({ $0 == observedFingerprint }) ?? true else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        observedLeafCertificateSHA256?(observedFingerprint)
        completionHandler(.useCredential, URLCredential(trust: trust))
        #else
        completionHandler(.cancelAuthenticationChallenge, nil)
        #endif
    }

    private func finish(_ result: Result<Output, Error>) {
        lock.lock()
        guard !isComplete else {
            lock.unlock()
            return
        }
        isComplete = true
        let continuation = self.continuation
        self.continuation = nil
        let session = self.session
        self.session = nil
        buffer.removeAll(keepingCapacity: false)
        lock.unlock()

        session?.invalidateAndCancel()
        guard let continuation else { return }
        switch result {
        case .success(let output):
            continuation.resume(returning: output)
        case .failure(let error):
            continuation.resume(throwing: error)
        }
    }
}
