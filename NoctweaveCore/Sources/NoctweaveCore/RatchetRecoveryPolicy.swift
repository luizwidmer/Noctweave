import CryptoKit
import Foundation

public enum RatchetRecoveryDecision: Equatable {
    case acknowledge
    case recover
    case retryLater
}

public enum RatchetRecoveryPolicy {
    public static func decision(for error: Error) -> RatchetRecoveryDecision {
        if error is CryptoKitError {
            return .recover
        }

        guard let cryptoError = error as? CryptoError else {
            return .retryLater
        }

        switch cryptoError {
        case .invalidPayload, .counterOutOfOrder, .counterWindowExceeded:
            return .recover
        case .counterReplay, .invalidSignature:
            return .acknowledge
        default:
            return .retryLater
        }
    }
}
