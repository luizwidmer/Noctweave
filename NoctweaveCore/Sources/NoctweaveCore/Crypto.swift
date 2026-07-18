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
    private static let maximumSignedMessageBytes = 512 * 1024
    public let privateKeyData: Data
    public let publicKeyData: Data

    private enum CodingKeys: String, CodingKey {
        case privateKeyData
        case publicKeyData
    }

    public init() {
        do {
            self = try Self.generate()
        } catch {
            fatalError("Noctweave could not generate an ML-DSA-65 signing key: \(error)")
        }
    }

    public static func generate() throws -> SigningKeyPair {
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
            privateKey.secureWipe()
            throw CryptoError.operationFailed
        }
        return SigningKeyPair(uncheckedPrivateKeyData: privateKey, publicKeyData: publicKey)
    }

    public init(privateKeyData: Data, publicKeyData: Data) throws {
        let sig = try PQCLibrary.signature()
        defer { OQS_SIG_free(sig) }
        guard privateKeyData.count == Int(sig.pointee.length_secret_key),
              publicKeyData.count == Int(sig.pointee.length_public_key) else {
            throw CryptoError.invalidPrivateKey
        }
        guard try Self.keysMatch(
            privateKeyData: privateKeyData,
            publicKeyData: publicKeyData,
            signature: sig
        ) else {
            throw CryptoError.invalidPrivateKey
        }
        self.privateKeyData = privateKeyData
        self.publicKeyData = publicKeyData
    }

    private init(uncheckedPrivateKeyData: Data, publicKeyData: Data) {
        self.privateKeyData = uncheckedPrivateKeyData
        self.publicKeyData = publicKeyData
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let privateKeyData = try container.decode(Data.self, forKey: .privateKeyData)
        let publicKeyData = try container.decode(Data.self, forKey: .publicKeyData)
        try self.init(privateKeyData: privateKeyData, publicKeyData: publicKeyData)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(privateKeyData, forKey: .privateKeyData)
        try container.encode(publicKeyData, forKey: .publicKeyData)
    }

    public func sign(_ data: Data) throws -> Data {
        let sig = try PQCLibrary.signature()
        defer { OQS_SIG_free(sig) }
        guard data.count <= Self.maximumSignedMessageBytes,
              privateKeyData.count == Int(sig.pointee.length_secret_key),
              publicKeyData.count == Int(sig.pointee.length_public_key) else {
            throw data.count > Self.maximumSignedMessageBytes ? CryptoError.invalidPayload : CryptoError.invalidPrivateKey
        }
        var signature = Data(count: Int(sig.pointee.length_signature))
        var signatureLen: size_t = 0
        let messageStorage = data.isEmpty ? Data([0]) : data
        let result = signature.withUnsafeMutableBytes { sigPtr in
            messageStorage.withUnsafeBytes { msgPtr in
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
        guard result == OQS_SUCCESS,
              signatureLen == sig.pointee.length_signature else {
            signature.secureWipe()
            throw CryptoError.invalidSignature
        }
        signature.count = signatureLen
        return signature
    }

    /// Verifies peer-controlled signature material without hiding a local
    /// ML-DSA runtime or algorithm-availability failure.
    public static func verifyThrowing(
        signature: Data,
        data: Data,
        publicKeyData: Data
    ) throws -> Bool {
        let sig = try PQCLibrary.signature()
        defer { OQS_SIG_free(sig) }
        guard data.count <= maximumSignedMessageBytes,
              publicKeyData.count == Int(sig.pointee.length_public_key),
              signature.count == Int(sig.pointee.length_signature) else {
            return false
        }
        let messageStorage = data.isEmpty ? Data([0]) : data
        let result = signature.withUnsafeBytes { sigPtr in
            messageStorage.withUnsafeBytes { msgPtr in
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
    }

    public static func verify(signature: Data, data: Data, publicKeyData: Data) -> Bool {
        (try? verifyThrowing(
            signature: signature,
            data: data,
            publicKeyData: publicKeyData
        )) == true
    }

    public static func isValidPublicKeyThrowing(_ publicKeyData: Data) throws -> Bool {
        let sig = try PQCLibrary.signature()
        defer { OQS_SIG_free(sig) }
        return publicKeyData.count == Int(sig.pointee.length_public_key)
    }

    public static func isValidPublicKey(_ publicKeyData: Data) -> Bool {
        (try? isValidPublicKeyThrowing(publicKeyData)) == true
    }

    private static func keysMatch(
        privateKeyData: Data,
        publicKeyData: Data,
        signature sig: UnsafeMutablePointer<OQS_SIG>
    ) throws -> Bool {
        let challenge = Data("Noctweave/ML-DSA-65/keypair-validation/v1".utf8)
        var signature = Data(count: Int(sig.pointee.length_signature))
        defer { signature.secureWipe() }
        var signatureLength: size_t = 0
        let signResult = signature.withUnsafeMutableBytes { signaturePointer in
            challenge.withUnsafeBytes { challengePointer in
                privateKeyData.withUnsafeBytes { privatePointer in
                    OQS_SIG_sign(
                        sig,
                        signaturePointer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        &signatureLength,
                        challengePointer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        challenge.count,
                        privatePointer.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        guard signResult == OQS_SUCCESS,
              signatureLength == sig.pointee.length_signature else {
            throw CryptoError.operationFailed
        }
        return signature.withUnsafeBytes { signaturePointer in
            challenge.withUnsafeBytes { challengePointer in
                publicKeyData.withUnsafeBytes { publicPointer in
                    OQS_SIG_verify(
                        sig,
                        challengePointer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        challenge.count,
                        signaturePointer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        signatureLength,
                        publicPointer.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        } == OQS_SUCCESS
    }
}

public struct KEMOutput: Codable, Equatable {
    public let ciphertext: Data
    public var sharedSecret: Data

    public init(ciphertext: Data, sharedSecret: Data) {
        self.ciphertext = ciphertext
        self.sharedSecret = sharedSecret
    }
}

public struct AgreementKeyPair: Codable {
    public let privateKeyData: Data
    public let publicKeyData: Data

    private enum CodingKeys: String, CodingKey {
        case privateKeyData
        case publicKeyData
    }

    public init() {
        do {
            self = try Self.generate()
        } catch {
            fatalError("Noctweave could not generate an ML-KEM-768 agreement key: \(error)")
        }
    }

    public static func generate() throws -> AgreementKeyPair {
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
            privateKey.secureWipe()
            throw CryptoError.operationFailed
        }
        return AgreementKeyPair(uncheckedPrivateKeyData: privateKey, publicKeyData: publicKey)
    }

    public init(privateKeyData: Data, publicKeyData: Data) throws {
        let kem = try PQCLibrary.kem()
        defer { OQS_KEM_free(kem) }
        guard privateKeyData.count == Int(kem.pointee.length_secret_key),
              publicKeyData.count == Int(kem.pointee.length_public_key) else {
            throw CryptoError.invalidPrivateKey
        }
        guard try Self.keysMatch(
            privateKeyData: privateKeyData,
            publicKeyData: publicKeyData,
            kem: kem
        ) else {
            throw CryptoError.invalidPrivateKey
        }
        self.privateKeyData = privateKeyData
        self.publicKeyData = publicKeyData
    }

    private init(uncheckedPrivateKeyData: Data, publicKeyData: Data) {
        self.privateKeyData = uncheckedPrivateKeyData
        self.publicKeyData = publicKeyData
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let privateKeyData = try container.decode(Data.self, forKey: .privateKeyData)
        let publicKeyData = try container.decode(Data.self, forKey: .publicKeyData)
        try self.init(privateKeyData: privateKeyData, publicKeyData: publicKeyData)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(privateKeyData, forKey: .privateKeyData)
        try container.encode(publicKeyData, forKey: .publicKeyData)
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
            sharedSecret.secureWipe()
            throw CryptoError.operationFailed
        }
        return KEMOutput(ciphertext: ciphertext, sharedSecret: sharedSecret)
    }

    public static func isValidPublicKeyThrowing(_ publicKeyData: Data) throws -> Bool {
        let kem = try PQCLibrary.kem()
        defer { OQS_KEM_free(kem) }
        return publicKeyData.count == Int(kem.pointee.length_public_key)
    }

    public static func isValidPublicKey(_ publicKeyData: Data) -> Bool {
        (try? isValidPublicKeyThrowing(publicKeyData)) == true
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
            sharedSecret.secureWipe()
            throw CryptoError.operationFailed
        }
        return sharedSecret
    }

    private static func keysMatch(
        privateKeyData: Data,
        publicKeyData: Data,
        kem: UnsafeMutablePointer<OQS_KEM>
    ) throws -> Bool {
        var ciphertext = Data(count: Int(kem.pointee.length_ciphertext))
        var encapsulatedSecret = Data(count: Int(kem.pointee.length_shared_secret))
        var decapsulatedSecret = Data(count: Int(kem.pointee.length_shared_secret))
        defer {
            ciphertext.secureWipe()
            encapsulatedSecret.secureWipe()
            decapsulatedSecret.secureWipe()
        }
        let encapsulationResult = ciphertext.withUnsafeMutableBytes { ciphertextPointer in
            encapsulatedSecret.withUnsafeMutableBytes { secretPointer in
                publicKeyData.withUnsafeBytes { publicPointer in
                    OQS_KEM_encaps(
                        kem,
                        ciphertextPointer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        secretPointer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        publicPointer.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        guard encapsulationResult == OQS_SUCCESS else {
            throw CryptoError.operationFailed
        }
        let decapsulationResult = decapsulatedSecret.withUnsafeMutableBytes { secretPointer in
            ciphertext.withUnsafeBytes { ciphertextPointer in
                privateKeyData.withUnsafeBytes { privatePointer in
                    OQS_KEM_decaps(
                        kem,
                        secretPointer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        ciphertextPointer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        privatePointer.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        guard decapsulationResult == OQS_SUCCESS else {
            throw CryptoError.operationFailed
        }
        return timingSafeEqual(encapsulatedSecret, decapsulatedSecret)
    }
}

public enum CryptoBox {
    public static func encrypt(_ plaintext: Data, key: SymmetricKey, authenticatedData: Data) throws -> EncryptedPayload {
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: authenticatedData)
        return EncryptedPayload(nonce: Data(sealed.nonce), ciphertext: sealed.ciphertext, tag: sealed.tag)
    }

    public static func decrypt(_ payload: EncryptedPayload, key: SymmetricKey, authenticatedData: Data) throws -> Data {
        do {
            let nonce = try AES.GCM.Nonce(data: payload.nonce)
            let box = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: payload.ciphertext,
                tag: payload.tag
            )
            return try AES.GCM.open(box, using: key, authenticating: authenticatedData)
        } catch {
            // Authentication failure and malformed sealed-box bytes are
            // deterministic properties of this envelope. Normalize them so
            // ordered opaque-route consumers can quarantine the event without
            // treating it as a transient crypto-runtime failure.
            throw CryptoError.invalidPayload
        }
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
    public static let nonceByteCount = 12
    public static let tagByteCount = 16
    /// The largest encrypted payload used by any current protocol module.
    /// Individual modules, including attachment upload, impose tighter bounds.
    public static let maximumCiphertextBytes = 2 * 1_024 * 1_024

    public let nonce: Data
    public let ciphertext: Data
    public let tag: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case nonce
        case ciphertext
        case tag
    }

    public init(nonce: Data, ciphertext: Data, tag: Data) {
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: EncryptedPayloadCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Encrypted payload fields must match the current schema exactly"
                )
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        nonce = try values.decode(Data.self, forKey: .nonce)
        ciphertext = try values.decode(Data.self, forKey: .ciphertext)
        tag = try values.decode(Data.self, forKey: .tag)
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Encrypted payload has invalid cryptographic field lengths"
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(
                    codingPath: encoder.codingPath,
                    debugDescription: "Encrypted payload has invalid cryptographic field lengths"
                )
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(nonce, forKey: .nonce)
        try values.encode(ciphertext, forKey: .ciphertext)
        try values.encode(tag, forKey: .tag)
    }

    public var isStructurallyValid: Bool {
        nonce.count == Self.nonceByteCount
            && tag.count == Self.tagByteCount
            && !ciphertext.isEmpty
            && ciphertext.count <= Self.maximumCiphertextBytes
    }
}

private struct EncryptedPayloadCodingKey: CodingKey {
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

private func timingSafeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
    var difference = lhs.count ^ rhs.count
    for index in 0..<max(lhs.count, rhs.count) {
        let left = index < lhs.count ? lhs[index] : 0
        let right = index < rhs.count ? rhs[index] : 0
        difference |= Int(left ^ right)
    }
    return difference == 0
}
