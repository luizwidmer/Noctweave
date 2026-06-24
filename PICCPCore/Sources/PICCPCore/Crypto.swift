import CryptoKit
import Foundation
import liboqs

public enum CryptoError: Error, Equatable {
    case invalidPublicKey
    case invalidPrivateKey
    case invalidSignature
    case invalidPayload
    case counterOutOfOrder
    case counterReplay
    case counterWindowExceeded
    case algorithmUnavailable
    case operationFailed
}

private enum PQCLibrary {
    static let initialize: Void = {
        OQS_init()
    }()

    static func signature() throws -> UnsafeMutablePointer<OQS_SIG> {
        _ = initialize
        guard let sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65) else {
            throw CryptoError.algorithmUnavailable
        }
        return sig
    }

    static func kem() throws -> UnsafeMutablePointer<OQS_KEM> {
        _ = initialize
        guard let kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768) else {
            throw CryptoError.algorithmUnavailable
        }
        return kem
    }
}

public struct SigningKeyPair: Codable {
    public let privateKeyData: Data
    public let publicKeyData: Data

    public init() {
        do {
            let sig = try PQCLibrary.signature()
            defer { OQS_SIG_free(sig) }
            var publicKey = Data(count: Int(sig.pointee.length_public_key))
            var privateKey = Data(count: Int(sig.pointee.length_secret_key))
            let result = publicKey.withUnsafeMutableBytes { publicPtr in
                privateKey.withUnsafeMutableBytes { privatePtr in
                    OQS_SIG_keypair(
                        sig,
                        publicPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        privatePtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
            guard result == OQS_SUCCESS else {
                self.privateKeyData = Data()
                self.publicKeyData = Data()
                return
            }
            self.privateKeyData = privateKey
            self.publicKeyData = publicKey
        } catch {
            self.privateKeyData = Data()
            self.publicKeyData = Data()
        }
    }

    public init(privateKeyData: Data, publicKeyData: Data) throws {
        let sig = try PQCLibrary.signature()
        defer { OQS_SIG_free(sig) }
        guard privateKeyData.count == Int(sig.pointee.length_secret_key),
              publicKeyData.count == Int(sig.pointee.length_public_key) else {
            throw CryptoError.invalidPrivateKey
        }
        self.privateKeyData = privateKeyData
        self.publicKeyData = publicKeyData
    }

    public func sign(_ data: Data) throws -> Data {
        let sig = try PQCLibrary.signature()
        defer { OQS_SIG_free(sig) }
        guard privateKeyData.count == Int(sig.pointee.length_secret_key),
              publicKeyData.count == Int(sig.pointee.length_public_key) else {
            throw CryptoError.invalidPrivateKey
        }
        var signature = Data(count: Int(sig.pointee.length_signature))
        var signatureLen: size_t = 0
        let result = signature.withUnsafeMutableBytes { sigPtr in
            data.withUnsafeBytes { msgPtr in
                privateKeyData.withUnsafeBytes { privatePtr in
                    OQS_SIG_sign(
                        sig,
                        sigPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        &signatureLen,
                        msgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        data.count,
                        privatePtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        guard result == OQS_SUCCESS else {
            throw CryptoError.invalidSignature
        }
        signature.count = signatureLen
        return signature
    }

    public static func verify(signature: Data, data: Data, publicKeyData: Data) -> Bool {
        do {
            let sig = try PQCLibrary.signature()
            defer { OQS_SIG_free(sig) }
            guard publicKeyData.count == Int(sig.pointee.length_public_key),
                  signature.count == Int(sig.pointee.length_signature) else {
                return false
            }
            let result = signature.withUnsafeBytes { sigPtr in
                data.withUnsafeBytes { msgPtr in
                    publicKeyData.withUnsafeBytes { publicPtr in
                        OQS_SIG_verify(
                            sig,
                            msgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            data.count,
                            sigPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            signature.count,
                            publicPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                        )
                    }
                }
            }
            return result == OQS_SUCCESS
        } catch {
            return false
        }
    }

    public static func isValidPublicKey(_ publicKeyData: Data) -> Bool {
        do {
            let sig = try PQCLibrary.signature()
            defer { OQS_SIG_free(sig) }
            return publicKeyData.count == Int(sig.pointee.length_public_key)
        } catch {
            return false
        }
    }
}

public struct KEMOutput: Codable, Equatable {
    public let ciphertext: Data
    public let sharedSecret: Data

    public init(ciphertext: Data, sharedSecret: Data) {
        self.ciphertext = ciphertext
        self.sharedSecret = sharedSecret
    }
}

public struct AgreementKeyPair: Codable {
    public let privateKeyData: Data
    public let publicKeyData: Data

    public init() {
        do {
            let kem = try PQCLibrary.kem()
            defer { OQS_KEM_free(kem) }
            var publicKey = Data(count: Int(kem.pointee.length_public_key))
            var privateKey = Data(count: Int(kem.pointee.length_secret_key))
            let result = publicKey.withUnsafeMutableBytes { publicPtr in
                privateKey.withUnsafeMutableBytes { privatePtr in
                    OQS_KEM_keypair(
                        kem,
                        publicPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        privatePtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
            guard result == OQS_SUCCESS else {
                self.privateKeyData = Data()
                self.publicKeyData = Data()
                return
            }
            self.privateKeyData = privateKey
            self.publicKeyData = publicKey
        } catch {
            self.privateKeyData = Data()
            self.publicKeyData = Data()
        }
    }

    public init(privateKeyData: Data, publicKeyData: Data) throws {
        let kem = try PQCLibrary.kem()
        defer { OQS_KEM_free(kem) }
        guard privateKeyData.count == Int(kem.pointee.length_secret_key),
              publicKeyData.count == Int(kem.pointee.length_public_key) else {
            throw CryptoError.invalidPrivateKey
        }
        self.privateKeyData = privateKeyData
        self.publicKeyData = publicKeyData
    }

    public static func encapsulate(to publicKeyData: Data) throws -> KEMOutput {
        let kem = try PQCLibrary.kem()
        defer { OQS_KEM_free(kem) }
        guard publicKeyData.count == Int(kem.pointee.length_public_key) else {
            throw CryptoError.invalidPublicKey
        }
        var ciphertext = Data(count: Int(kem.pointee.length_ciphertext))
        var sharedSecret = Data(count: Int(kem.pointee.length_shared_secret))
        let result = ciphertext.withUnsafeMutableBytes { cipherPtr in
            sharedSecret.withUnsafeMutableBytes { secretPtr in
                publicKeyData.withUnsafeBytes { publicPtr in
                    OQS_KEM_encaps(
                        kem,
                        cipherPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        secretPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        publicPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        guard result == OQS_SUCCESS else {
            throw CryptoError.operationFailed
        }
        return KEMOutput(ciphertext: ciphertext, sharedSecret: sharedSecret)
    }

    public static func isValidPublicKey(_ publicKeyData: Data) -> Bool {
        do {
            let kem = try PQCLibrary.kem()
            defer { OQS_KEM_free(kem) }
            return publicKeyData.count == Int(kem.pointee.length_public_key)
        } catch {
            return false
        }
    }

    public func decapsulate(ciphertext: Data) throws -> Data {
        let kem = try PQCLibrary.kem()
        defer { OQS_KEM_free(kem) }
        guard ciphertext.count == Int(kem.pointee.length_ciphertext),
              privateKeyData.count == Int(kem.pointee.length_secret_key),
              publicKeyData.count == Int(kem.pointee.length_public_key) else {
            throw CryptoError.invalidPayload
        }
        var sharedSecret = Data(count: Int(kem.pointee.length_shared_secret))
        let result = sharedSecret.withUnsafeMutableBytes { secretPtr in
            ciphertext.withUnsafeBytes { cipherPtr in
                privateKeyData.withUnsafeBytes { privatePtr in
                    OQS_KEM_decaps(
                        kem,
                        secretPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        cipherPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        privatePtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        guard result == OQS_SUCCESS else {
            throw CryptoError.operationFailed
        }
        return sharedSecret
    }
}

public enum CryptoBox {
    public static func encrypt(_ plaintext: Data, key: SymmetricKey, authenticatedData: Data) throws -> EncryptedPayload {
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: authenticatedData)
        return EncryptedPayload(nonce: Data(sealed.nonce), ciphertext: sealed.ciphertext, tag: sealed.tag)
    }

    public static func decrypt(_ payload: EncryptedPayload, key: SymmetricKey, authenticatedData: Data) throws -> Data {
        let nonce = try AES.GCM.Nonce(data: payload.nonce)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: payload.ciphertext, tag: payload.tag)
        return try AES.GCM.open(box, using: key, authenticating: authenticatedData)
    }

    public static func fingerprint(for publicKeyData: Data) -> String {
        let hash = SHA256.hash(data: publicKeyData)
        return Data(hash).base64EncodedString()
    }

    public static func deriveChainKey(sharedSecret: Data, salt: Data, info: Data) -> Data {
        let baseKey = SymmetricKey(data: sharedSecret)
        let derived = HKDF<SHA256>.deriveKey(inputKeyMaterial: baseKey, salt: salt, info: info, outputByteCount: 32)
        return derived.dataRepresentation
    }
}

public struct EncryptedPayload: Codable, Equatable {
    public let nonce: Data
    public let ciphertext: Data
    public let tag: Data

    public init(nonce: Data, ciphertext: Data, tag: Data) {
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
    }
}
