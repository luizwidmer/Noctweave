import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

final class OQSSignatureVerifier: @unchecked Sendable {
    static let shared = OQSSignatureVerifier()
    static let mlDSA65PublicKeyBytes = 1_952
    static let mlDSA65PrivateKeyBytes = 4_032
    static let mlDSA65SignatureBytes = 3_309

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

    func generateKeyPair() -> (privateKey: Data, publicKey: Data)? {
        guard let runtime = runtimeFunctions() else {
            return nil
        }
        guard let sig = runtime.newSignature() else {
            return nil
        }
        defer { runtime.freeSignature(sig) }
        var publicKey = Data(count: Self.mlDSA65PublicKeyBytes)
        var privateKey = Data(count: Self.mlDSA65PrivateKeyBytes)
        let status = publicKey.withUnsafeMutableBytes { publicKeyPtr in
            privateKey.withUnsafeMutableBytes { privateKeyPtr in
                runtime.keypair(
                    sig,
                    publicKeyPtr.bindMemory(to: UInt8.self).baseAddress,
                    privateKeyPtr.bindMemory(to: UInt8.self).baseAddress
                )
            }
        }
        guard status == OQSRuntime.success else {
            return nil
        }
        return (privateKey, publicKey)
    }

    func sign(data: Data, privateKey: Data, publicKey: Data) -> Data? {
        guard let runtime = runtimeFunctions(),
              !data.isEmpty,
              privateKey.count == Self.mlDSA65PrivateKeyBytes,
              publicKey.count == Self.mlDSA65PublicKeyBytes else {
            return nil
        }
        guard let sig = runtime.newSignature() else {
            return nil
        }
        defer { runtime.freeSignature(sig) }
        var signature = Data(count: Self.mlDSA65SignatureBytes)
        var signatureLength = Self.mlDSA65SignatureBytes
        let status = signature.withUnsafeMutableBytes { signaturePtr in
            data.withUnsafeBytes { dataPtr in
                privateKey.withUnsafeBytes { privateKeyPtr in
                    runtime.sign(
                        sig,
                        signaturePtr.bindMemory(to: UInt8.self).baseAddress,
                        &signatureLength,
                        dataPtr.bindMemory(to: UInt8.self).baseAddress,
                        data.count,
                        privateKeyPtr.bindMemory(to: UInt8.self).baseAddress
                    )
                }
            }
        }
        guard status == OQSRuntime.success, signatureLength <= signature.count else {
            return nil
        }
        signature.count = signatureLength
        return signature
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
    private typealias OQSSigKeypairFn = @convention(c) (
        UnsafeMutableRawPointer?,
        UnsafeMutablePointer<UInt8>?,
        UnsafeMutablePointer<UInt8>?
    ) -> Int32
    private typealias OQSSigSignFn = @convention(c) (
        UnsafeMutableRawPointer?,
        UnsafeMutablePointer<UInt8>?,
        UnsafeMutablePointer<Int>?,
        UnsafePointer<UInt8>?,
        Int,
        UnsafePointer<UInt8>?
    ) -> Int32
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
    private let oqsSigKeypair: OQSSigKeypairFn
    private let oqsSigSign: OQSSigSignFn
    private let oqsSigVerify: OQSSigVerifyFn

    private init(
        handle: UnsafeMutableRawPointer,
        oqsSigNew: @escaping OQSSigNewFn,
        oqsSigFree: @escaping OQSSigFreeFn,
        keypair: @escaping OQSSigKeypairFn,
        sign: @escaping OQSSigSignFn,
        verify: @escaping OQSSigVerifyFn
    ) {
        self.handle = handle
        self.oqsSigNew = oqsSigNew
        self.oqsSigFree = oqsSigFree
        self.oqsSigKeypair = keypair
        self.oqsSigSign = sign
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

    func keypair(
        _ signature: UnsafeMutableRawPointer?,
        _ publicKey: UnsafeMutablePointer<UInt8>?,
        _ privateKey: UnsafeMutablePointer<UInt8>?
    ) -> Int32 {
        oqsSigKeypair(signature, publicKey, privateKey)
    }

    func sign(
        _ signature: UnsafeMutableRawPointer?,
        _ detachedSignature: UnsafeMutablePointer<UInt8>?,
        _ detachedSignatureLength: UnsafeMutablePointer<Int>?,
        _ message: UnsafePointer<UInt8>?,
        _ messageLength: Int,
        _ privateKey: UnsafePointer<UInt8>?
    ) -> Int32 {
        oqsSigSign(
            signature,
            detachedSignature,
            detachedSignatureLength,
            message,
            messageLength,
            privateKey
        )
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
              let sigKeypairSymbol = dlsym(handle, "OQS_SIG_keypair"),
              let sigSignSymbol = dlsym(handle, "OQS_SIG_sign"),
              let sigVerifySymbol = dlsym(handle, "OQS_SIG_verify") else {
            dlclose(handle)
            return nil
        }

        let oqsInit = unsafeBitCast(initSymbol, to: OQSInitFn.self)
        let oqsSigNew = unsafeBitCast(sigNewSymbol, to: OQSSigNewFn.self)
        let oqsSigFree = unsafeBitCast(sigFreeSymbol, to: OQSSigFreeFn.self)
        let oqsSigKeypair = unsafeBitCast(sigKeypairSymbol, to: OQSSigKeypairFn.self)
        let oqsSigSign = unsafeBitCast(sigSignSymbol, to: OQSSigSignFn.self)
        let oqsSigVerify = unsafeBitCast(sigVerifySymbol, to: OQSSigVerifyFn.self)
        oqsInit()
        return OQSRuntime(
            handle: handle,
            oqsSigNew: oqsSigNew,
            oqsSigFree: oqsSigFree,
            keypair: oqsSigKeypair,
            sign: oqsSigSign,
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
