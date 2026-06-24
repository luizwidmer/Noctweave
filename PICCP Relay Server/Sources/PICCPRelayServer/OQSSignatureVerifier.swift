import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

final class OQSSignatureVerifier: @unchecked Sendable {
    static let shared = OQSSignatureVerifier()
    private static let mlDSA65PublicKeyBytes = 1_952
    private static let mlDSA65SignatureBytes = 3_309

    private let lock = NSLock()
    private var didResolveRuntime = false
    private var runtime: OQSRuntime?

    private init() {}

    var isAvailable: Bool {
        runtimeFunctions() != nil
    }

    func verify(signature: Data, data: Data, publicKey: Data) -> Bool {
        guard let runtime = runtimeFunctions(),
              signature.count == Self.mlDSA65SignatureBytes,
              !data.isEmpty,
              publicKey.count == Self.mlDSA65PublicKeyBytes else {
            return false
        }
        guard let sig = runtime.newSignature() else {
            return false
        }
        defer { runtime.freeSignature(sig) }
        let status = signature.withUnsafeBytes { signaturePtr in
            data.withUnsafeBytes { dataPtr in
                publicKey.withUnsafeBytes { publicKeyPtr in
                    runtime.verify(
                        sig,
                        dataPtr.bindMemory(to: UInt8.self).baseAddress,
                        data.count,
                        signaturePtr.bindMemory(to: UInt8.self).baseAddress,
                        signature.count,
                        publicKeyPtr.bindMemory(to: UInt8.self).baseAddress
                    )
                }
            }
        }
        return status == OQSRuntime.success
    }

    private func runtimeFunctions() -> OQSRuntime? {
        lock.lock()
        defer { lock.unlock() }
        if didResolveRuntime {
            return runtime
        }
        runtime = OQSRuntime.load()
        didResolveRuntime = true
        return runtime
    }
}

private struct OQSRuntime {
    private typealias OQSInitFn = @convention(c) () -> Void
    private typealias OQSSigNewFn = @convention(c) (UnsafePointer<CChar>?) -> UnsafeMutableRawPointer?
    private typealias OQSSigFreeFn = @convention(c) (UnsafeMutableRawPointer?) -> Void
    private typealias OQSSigVerifyFn = @convention(c) (
        UnsafeMutableRawPointer?,
        UnsafePointer<UInt8>?,
        Int,
        UnsafePointer<UInt8>?,
        Int,
        UnsafePointer<UInt8>?
    ) -> Int32

    static let success: Int32 = 0
    private static let algorithm = "ML-DSA-65"

    private let handle: UnsafeMutableRawPointer
    private let oqsSigNew: OQSSigNewFn
    private let oqsSigFree: OQSSigFreeFn
    private let oqsSigVerify: OQSSigVerifyFn

    private init(
        handle: UnsafeMutableRawPointer,
        oqsSigNew: @escaping OQSSigNewFn,
        oqsSigFree: @escaping OQSSigFreeFn,
        verify: @escaping OQSSigVerifyFn
    ) {
        self.handle = handle
        self.oqsSigNew = oqsSigNew
        self.oqsSigFree = oqsSigFree
        self.oqsSigVerify = verify
    }

    func newSignature() -> UnsafeMutableRawPointer? {
        Self.algorithm.withCString { algorithm in
            oqsSigNew(algorithm)
        }
    }

    func freeSignature(_ signature: UnsafeMutableRawPointer?) {
        oqsSigFree(signature)
    }

    func verify(
        _ signature: UnsafeMutableRawPointer?,
        _ message: UnsafePointer<UInt8>?,
        _ messageLength: Int,
        _ detachedSignature: UnsafePointer<UInt8>?,
        _ detachedSignatureLength: Int,
        _ publicKey: UnsafePointer<UInt8>?
    ) -> Int32 {
        oqsSigVerify(
            signature,
            message,
            messageLength,
            detachedSignature,
            detachedSignatureLength,
            publicKey
        )
    }

    static func load() -> OQSRuntime? {
        guard let handle = openLibraryHandle() else {
            return nil
        }
        guard let initSymbol = dlsym(handle, "OQS_init"),
              let sigNewSymbol = dlsym(handle, "OQS_SIG_new"),
              let sigFreeSymbol = dlsym(handle, "OQS_SIG_free"),
              let sigVerifySymbol = dlsym(handle, "OQS_SIG_verify") else {
            dlclose(handle)
            return nil
        }

        let oqsInit = unsafeBitCast(initSymbol, to: OQSInitFn.self)
        let oqsSigNew = unsafeBitCast(sigNewSymbol, to: OQSSigNewFn.self)
        let oqsSigFree = unsafeBitCast(sigFreeSymbol, to: OQSSigFreeFn.self)
        let oqsSigVerify = unsafeBitCast(sigVerifySymbol, to: OQSSigVerifyFn.self)
        oqsInit()
        return OQSRuntime(
            handle: handle,
            oqsSigNew: oqsSigNew,
            oqsSigFree: oqsSigFree,
            verify: oqsSigVerify
        )
    }

    private static func openLibraryHandle() -> UnsafeMutableRawPointer? {
        let candidates: [String]
        #if canImport(Darwin)
        candidates = [
            "/opt/homebrew/lib/liboqs.dylib",
            "/usr/local/lib/liboqs.dylib",
            "liboqs.dylib"
        ]
        #else
        candidates = [
            "/usr/local/lib/liboqs.so",
            "liboqs.so.0",
            "liboqs.so"
        ]
        #endif
        for candidate in candidates {
            if let handle = dlopen(candidate, RTLD_NOW | RTLD_LOCAL) {
                return handle
            }
        }
        return nil
    }
}
