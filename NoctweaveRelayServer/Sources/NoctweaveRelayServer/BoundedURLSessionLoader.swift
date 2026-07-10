import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

enum BoundedURLSessionLoaderError: Error, Equatable {
    case responseTooLarge
    case missingResponse
    case timedOut
    case invalidConfiguration
}

final class BoundedURLSessionLoader: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private static let absoluteMaximumBytes = 16 * 1024 * 1024
    typealias Output = (data: Data, response: URLResponse)

    private let maximumBytes: Int
    private let lock = NSLock()
    private var buffer = Data()
    private var receivedResponse: URLResponse?
    private var completion: ((Result<Output, Error>) -> Void)?
    private var session: URLSession?
    private var isComplete = false

    private init(maximumBytes: Int) {
        self.maximumBytes = max(1, maximumBytes)
    }

    static func load(
        _ request: URLRequest,
        configuration: URLSessionConfiguration = .ephemeral,
        maximumBytes: Int
    ) async throws -> Output {
        guard (1...absoluteMaximumBytes).contains(maximumBytes) else {
            throw BoundedURLSessionLoaderError.invalidConfiguration
        }
        let loader = BoundedURLSessionLoader(maximumBytes: maximumBytes)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                loader.start(request, configuration: configuration) { result in
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            loader.cancel()
        }
    }

    static func loadSynchronously(
        _ request: URLRequest,
        configuration: URLSessionConfiguration = .ephemeral,
        maximumBytes: Int,
        timeout: TimeInterval
    ) throws -> Output {
        guard (1...absoluteMaximumBytes).contains(maximumBytes),
              timeout.isFinite,
              (1...300).contains(timeout) else {
            throw BoundedURLSessionLoaderError.invalidConfiguration
        }
        let loader = BoundedURLSessionLoader(maximumBytes: maximumBytes)
        let semaphore = DispatchSemaphore(value: 0)
        let box = SynchronousResultBox<Output>()
        loader.start(request, configuration: configuration) { result in
            box.set(result)
            semaphore.signal()
        }
        guard semaphore.wait(timeout: .now() + timeout) == .success else {
            loader.cancel()
            throw BoundedURLSessionLoaderError.timedOut
        }
        guard let result = box.get() else {
            throw BoundedURLSessionLoaderError.missingResponse
        }
        return try result.get()
    }

    private func start(
        _ request: URLRequest,
        configuration: URLSessionConfiguration,
        completion: @escaping (Result<Output, Error>) -> Void
    ) {
        lock.lock()
        guard !isComplete else {
            lock.unlock()
            completion(.failure(CancellationError()))
            return
        }
        self.completion = completion
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

    private func finish(_ result: Result<Output, Error>) {
        lock.lock()
        guard !isComplete else {
            lock.unlock()
            return
        }
        isComplete = true
        let completion = self.completion
        self.completion = nil
        let session = self.session
        self.session = nil
        buffer.removeAll(keepingCapacity: false)
        lock.unlock()

        session?.invalidateAndCancel()
        completion?(result)
    }
}

private final class SynchronousResultBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<Value, Error>?

    func set(_ result: Result<Value, Error>) {
        lock.lock()
        self.result = result
        lock.unlock()
    }

    func get() -> Result<Value, Error>? {
        lock.lock()
        defer { lock.unlock() }
        return result
    }
}
