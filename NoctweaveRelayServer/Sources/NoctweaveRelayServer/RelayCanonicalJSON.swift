import CoreFoundation
import Foundation

/// Noctweave Canonical JSON version 1 (NCJ-1) for authenticated relay data.
///
/// Transport and persistence JSON may use normal encoding. Anything hashed or
/// signed across implementations must pass through this canonical projection.
enum RelayCanonicalJSON {
    private static let maximumSafeInteger: Int64 = 9_007_199_254_740_991
    private static let maximumNestingDepth = 128

    enum Error: Swift.Error, Equatable {
        case invalidJSON
        case unsupportedValue
        case nonIntegerNumber
        case duplicateNormalizedKey
        case nestingDepthExceeded
    }

    static func encode<Value: Encodable>(_ value: Value) throws -> Data {
        try canonicalize(RelayCodec.encoder().encode(value))
    }

    static func canonicalize(_ data: Data) throws -> Data {
        let value: Any
        do {
            value = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        } catch {
            throw Error.invalidJSON
        }
        var output = Data()
        try append(value, depth: 0, to: &output)
        return output
    }

    private static func append(_ value: Any, depth: Int, to output: inout Data) throws {
        guard depth <= maximumNestingDepth else { throw Error.nestingDepthExceeded }
        if value is NSNull {
            output.append(contentsOf: "null".utf8)
            return
        }
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                output.append(contentsOf: number.boolValue ? "true".utf8 : "false".utf8)
                return
            }
            let type = String(cString: number.objCType)
            guard type != "f", type != "d" else { throw Error.nonIntegerNumber }
            let spelling = number.stringValue
            guard isCanonicalInteger(spelling) else { throw Error.nonIntegerNumber }
            output.append(contentsOf: spelling.utf8)
            return
        }
        if let string = value as? String {
            appendEscaped(string.precomposedStringWithCanonicalMapping, to: &output)
            return
        }
        if let array = value as? [Any] {
            output.append(0x5B)
            for (index, child) in array.enumerated() {
                if index > 0 { output.append(0x2C) }
                try append(child, depth: depth + 1, to: &output)
            }
            output.append(0x5D)
            return
        }
        if let object = value as? [String: Any] {
            var normalized: [String: Any] = [:]
            normalized.reserveCapacity(object.count)
            for (key, child) in object {
                let canonicalKey = key.precomposedStringWithCanonicalMapping
                guard normalized.updateValue(child, forKey: canonicalKey) == nil else {
                    throw Error.duplicateNormalizedKey
                }
            }
            let keys = normalized.keys.sorted(by: utf8Precedes)
            output.append(0x7B)
            for (index, key) in keys.enumerated() {
                if index > 0 { output.append(0x2C) }
                appendEscaped(key, to: &output)
                output.append(0x3A)
                guard let child = normalized[key] else { throw Error.unsupportedValue }
                try append(child, depth: depth + 1, to: &output)
            }
            output.append(0x7D)
            return
        }
        throw Error.unsupportedValue
    }

    private static func isCanonicalInteger(_ value: String) -> Bool {
        guard !value.isEmpty else { return false }
        let bytes = Array(value.utf8)
        var index = 0
        if bytes[0] == 0x2D {
            index = 1
            guard index < bytes.count else { return false }
        }
        if bytes[index] == 0x30 { return index + 1 == bytes.count && index == 0 }
        guard (0x31 ... 0x39).contains(bytes[index]) else { return false }
        index += 1
        while index < bytes.count {
            guard (0x30 ... 0x39).contains(bytes[index]) else { return false }
            index += 1
        }
        guard let parsed = Int64(value) else { return false }
        return parsed >= -maximumSafeInteger && parsed <= maximumSafeInteger
    }

    private static func utf8Precedes(_ left: String, _ right: String) -> Bool {
        left.utf8.lexicographicallyPrecedes(right.utf8)
    }

    private static func appendEscaped(_ value: String, to output: inout Data) {
        output.append(0x22)
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x22: output.append(contentsOf: [0x5C, 0x22])
            case 0x5C: output.append(contentsOf: [0x5C, 0x5C])
            case 0x08: output.append(contentsOf: [0x5C, 0x62])
            case 0x09: output.append(contentsOf: [0x5C, 0x74])
            case 0x0A: output.append(contentsOf: [0x5C, 0x6E])
            case 0x0C: output.append(contentsOf: [0x5C, 0x66])
            case 0x0D: output.append(contentsOf: [0x5C, 0x72])
            case 0x00 ... 0x1F:
                output.append(contentsOf: String(format: "\\u%04x", scalar.value).utf8)
            default:
                output.append(contentsOf: String(scalar).utf8)
            }
        }
        output.append(0x22)
    }
}
