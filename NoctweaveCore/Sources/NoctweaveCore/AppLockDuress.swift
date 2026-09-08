import CryptoKit
import Foundation

public enum AppLockDuressAction: String, Codable, CaseIterable, Identifiable, Sendable {
    case wipeLocalData, destroyLocalKeys, showChatsAndDestroyLocalKeys, decoy
    public var id: String { rawValue }
    public var displayName: String {
        switch self {
        case .wipeLocalData: "Wipe local data"
        case .destroyLocalKeys: "Make stored data unreadable"
        case .showChatsAndDestroyLocalKeys: "Show chats and destroy local keys"
        case .decoy: "Open a decoy"
        }
    }
    public var explanation: String {
        switch self {
        case .wipeLocalData: "Delete this installation's encrypted database, attachments, and their local decryption keys."
        case .destroyLocalKeys: "Destroy local decryption keys. Encrypted files remain, but this installation can no longer decrypt them."
        case .showChatsAndDestroyLocalKeys: "Keep a temporary text-only view of existing chats, destroy local decryption keys, and stop real messaging. The view disappears when the app closes."
        case .decoy: "Show a separate empty local view. Real data stays locked and unchanged; restart the app to return to normal authentication."
        }
    }
    public var destroysKeys: Bool { self != .decoy }
}

public struct AppLockDuressPlan: Codable, Equatable, Identifiable, Sendable {
    public var id: UUID
    public var label: String
    public var salt: Data
    public var verifier: Data
    public var action: AppLockDuressAction
    public init(id: UUID = UUID(), label: String, salt: Data, verifier: Data, action: AppLockDuressAction) {
        self.id = id; self.label = label; self.salt = salt; self.verifier = verifier; self.action = action
    }
    public var isStructurallyValid: Bool {
        !label.isEmpty && label.utf8.count <= 128 && label == label.trimmingCharacters(in: .whitespacesAndNewlines)
            && salt.count == 32 && verifier.count == 32
    }
    private enum CodingKeys: String, CodingKey, CaseIterable { case id, label, salt, verifier, action }
    public init(from decoder: Decoder) throws {
        let c = try strictClientStateContainer(decoder, keyedBy: CodingKeys.self, description: "Duress plan")
        self.init(id: try c.decode(UUID.self, forKey: .id), label: try c.decode(String.self, forKey: .label),
                  salt: try c.decode(Data.self, forKey: .salt), verifier: try c.decode(Data.self, forKey: .verifier),
                  action: try c.decode(AppLockDuressAction.self, forKey: .action))
        try requireValidClientStateDecoding(isStructurallyValid, key: .verifier, container: c, description: "Invalid duress plan")
    }
    public func encode(to encoder: Encoder) throws {
        try requireValidClientStateEncoding(isStructurallyValid, value: self, encoder: encoder, description: "Invalid duress plan")
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id); try c.encode(label, forKey: .label); try c.encode(salt, forKey: .salt)
        try c.encode(verifier, forKey: .verifier); try c.encode(action, forKey: .action)
    }
}

/// Domain-separated, bounded PBKDF2-HMAC-SHA256 verifier. No unlock key is stored in a plan.
public enum AppLockDuressPassword {
    public static func isValid(_ password: String) -> Bool {
        (6...128).contains(password.utf8.count) && !password.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
    }
    public static func makePlan(password: String, label: String, action: AppLockDuressAction) throws -> AppLockDuressPlan {
        guard isValid(password) else { throw AppLockPINV2Error.invalidPIN }
        let salt = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        let plan = AppLockDuressPlan(label: label, salt: salt, verifier: derive(password, salt: salt), action: action)
        guard plan.isStructurallyValid else { throw AppLockPINV2Error.invalidSalt }
        return plan
    }
    public static func matches(_ password: String, plan: AppLockDuressPlan) -> Bool {
        guard isValid(password), plan.isStructurallyValid else { return false }
        let candidate = derive(password, salt: plan.salt)
        var difference: UInt8 = 0
        for (a, b) in zip(candidate, plan.verifier) { difference |= a ^ b }
        return difference == 0
    }
    private static func derive(_ password: String, salt: Data) -> Data {
        let key = SymmetricKey(data: Data(password.utf8))
        let input = Data("org.noctweave.duress-password/v1\0".utf8) + salt + Data([0, 0, 0, 1])
        var block = Data(HMAC<SHA256>.authenticationCode(for: input, using: key))
        var result = block
        for _ in 1..<120_000 {
            block = Data(HMAC<SHA256>.authenticationCode(for: block, using: key))
            for i in result.indices { result[i] ^= block[i] }
        }
        return result
    }
}
