import Foundation
import CryptoKit
import CoreFoundation

/// Noctweave Canonical JSON version 1 (NCJ-1).
///
/// NCJ-1 is the deterministic byte representation used by signed, hashed, and
/// otherwise authenticated JSON structures. It deliberately permits only the
/// data model used by the protocol: null, booleans, UTF-8 strings, arrays,
/// objects, and interoperable safe integers (-(2^53-1)...2^53-1). Object keys
/// are NFC-normalized and ordered by their UTF-8 bytes; strings are
/// NFC-normalized and use minimal JSON escaping.
/// Floating-point values are rejected so different language runtimes cannot
/// disagree about exponent or rounding spellings.
public enum NoctweaveCanonicalJSON {
    private static let maximumSafeInteger: Int64 = 9_007_199_254_740_991

    public enum Error: Swift.Error, Equatable {
        case invalidJSON
        case unsupportedValue
        case nonIntegerNumber
        case duplicateNormalizedKey
    }

    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let transportBytes = try NoctweaveCoder.encoder().encode(value)
        return try canonicalize(transportBytes)
    }

    public static func canonicalize(_ data: Data) throws -> Data {
        do {
            var preflight = JSONDecodePreflight(
                data: data,
                maximumNestingDepth: NoctweaveCoder.maximumJSONNestingDepth,
                canonicalNumbersOnly: true
            )
            try preflight.validate()
        } catch {
            throw Error.invalidJSON
        }

        let value: Any
        do {
            value = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        } catch {
            throw Error.invalidJSON
        }

        var output = Data()
        try append(value, to: &output)
        return output
    }

    public static func isCanonical(_ data: Data) -> Bool {
        guard let canonical = try? canonicalize(data) else {
            return false
        }
        return canonical == data
    }

    private static func append(_ value: Any, to output: inout Data) throws {
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
            guard type != "f", type != "d" else {
                throw Error.nonIntegerNumber
            }
            let spelling = number.stringValue
            guard isCanonicalInteger(spelling) else {
                throw Error.nonIntegerNumber
            }
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
                try append(child, to: &output)
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
                guard let child = normalized[key] else {
                    throw Error.unsupportedValue
                }
                try append(child, to: &output)
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
        if bytes[index] == 0x30 {
            return index + 1 == bytes.count && index == 0
        }
        guard (0x31 ... 0x39).contains(bytes[index]) else { return false }
        index += 1
        while index < bytes.count {
            guard (0x30 ... 0x39).contains(bytes[index]) else { return false }
            index += 1
        }
        guard let parsed = Int64(value),
              parsed >= -maximumSafeInteger,
              parsed <= maximumSafeInteger else {
            return false
        }
        return true
    }

    private static func utf8Precedes(_ left: String, _ right: String) -> Bool {
        left.utf8.lexicographicallyPrecedes(right.utf8)
    }

    private static func appendEscaped(_ value: String, to output: inout Data) {
        output.append(0x22)
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x22:
                output.append(contentsOf: [0x5C, 0x22])
            case 0x5C:
                output.append(contentsOf: [0x5C, 0x5C])
            case 0x08:
                output.append(contentsOf: [0x5C, 0x62])
            case 0x09:
                output.append(contentsOf: [0x5C, 0x74])
            case 0x0A:
                output.append(contentsOf: [0x5C, 0x6E])
            case 0x0C:
                output.append(contentsOf: [0x5C, 0x66])
            case 0x0D:
                output.append(contentsOf: [0x5C, 0x72])
            case 0x00 ... 0x1F:
                let escape = String(format: "\\u%04x", scalar.value)
                output.append(contentsOf: escape.utf8)
            default:
                output.append(contentsOf: String(scalar).utf8)
            }
        }
        output.append(0x22)
    }
}

public enum NoctweaveCoder {
    static let maximumJSONNestingDepth = 128

    public static func encoder(sortedKeys: Bool = false) -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        if sortedKeys {
            encoder.outputFormatting = [.sortedKeys]
        }
        return encoder
    }

    private static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    public static func encode<T: Encodable>(_ value: T, sortedKeys: Bool = false) throws -> Data {
        if sortedKeys {
            return try NoctweaveCanonicalJSON.encode(value)
        }
        return try encoder().encode(value)
    }

    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            var preflight = JSONDecodePreflight(
                data: data,
                maximumNestingDepth: maximumJSONNestingDepth
            )
            try preflight.validate()
        } catch let failure as JSONDecodePreflight.Failure {
            throw DecodingError.dataCorrupted(
                .init(codingPath: [], debugDescription: failure.debugDescription)
            )
        }
        return try decoder().decode(type, from: data)
    }
}

private struct JSONDecodePreflight {
    enum Failure: Error {
        case invalidJSON
        case duplicateObjectKey
        case nestingDepthExceeded(Int)

        var debugDescription: String {
            switch self {
            case .invalidJSON:
                return "JSON preflight rejected malformed input"
            case .duplicateObjectKey:
                return "JSON preflight rejected a duplicate object key"
            case .nestingDepthExceeded(let maximum):
                return "JSON nesting exceeds the maximum depth of \(maximum)"
            }
        }
    }

    private let bytes: [UInt8]
    private let maximumNestingDepth: Int
    private let canonicalNumbersOnly: Bool
    private var index = 0

    init(
        data: Data,
        maximumNestingDepth: Int,
        canonicalNumbersOnly: Bool = false
    ) {
        bytes = Array(data)
        self.maximumNestingDepth = maximumNestingDepth
        self.canonicalNumbersOnly = canonicalNumbersOnly
    }

    mutating func validate() throws {
        skipWhitespace()
        try parseValue(atDepth: 0)
        skipWhitespace()
        guard index == bytes.count else {
            throw Failure.invalidJSON
        }
    }

    private mutating func parseValue(atDepth depth: Int) throws {
        skipWhitespace()
        guard let byte = currentByte else {
            throw Failure.invalidJSON
        }

        switch byte {
        case 0x7B: // {
            try beginContainer(atDepth: depth)
            try parseObject(atDepth: depth + 1)
        case 0x5B: // [
            try beginContainer(atDepth: depth)
            try parseArray(atDepth: depth + 1)
        case 0x22: // "
            _ = try parseString(capturingValue: false)
        case 0x74: // true
            try consumeLiteral([0x74, 0x72, 0x75, 0x65])
        case 0x66: // false
            try consumeLiteral([0x66, 0x61, 0x6C, 0x73, 0x65])
        case 0x6E: // null
            try consumeLiteral([0x6E, 0x75, 0x6C, 0x6C])
        case 0x2D, 0x30 ... 0x39: // - or digit
            try parseNumber()
        default:
            throw Failure.invalidJSON
        }
    }

    private func beginContainer(atDepth depth: Int) throws {
        guard depth < maximumNestingDepth else {
            throw Failure.nestingDepthExceeded(maximumNestingDepth)
        }
    }

    private mutating func parseObject(atDepth depth: Int) throws {
        try consume(0x7B)
        skipWhitespace()
        if consumeIfPresent(0x7D) {
            return
        }

        var keys = Set<String>()
        while true {
            skipWhitespace()
            guard currentByte == 0x22,
                  let key = try parseString(capturingValue: true) else {
                throw Failure.invalidJSON
            }
            guard keys.insert(key).inserted else {
                throw Failure.duplicateObjectKey
            }

            skipWhitespace()
            try consume(0x3A) // :
            try parseValue(atDepth: depth)
            skipWhitespace()

            if consumeIfPresent(0x7D) {
                return
            }
            try consume(0x2C) // ,
        }
    }

    private mutating func parseArray(atDepth depth: Int) throws {
        try consume(0x5B)
        skipWhitespace()
        if consumeIfPresent(0x5D) {
            return
        }

        while true {
            try parseValue(atDepth: depth)
            skipWhitespace()
            if consumeIfPresent(0x5D) {
                return
            }
            try consume(0x2C) // ,
        }
    }

    private mutating func parseString(capturingValue: Bool) throws -> String? {
        try consume(0x22)
        var captured: [UInt8] = []

        while let byte = currentByte {
            index += 1
            switch byte {
            case 0x22:
                guard capturingValue else {
                    return nil
                }
                guard let value = String(bytes: captured, encoding: .utf8) else {
                    throw Failure.invalidJSON
                }
                return value
            case 0x00 ... 0x1F:
                throw Failure.invalidJSON
            case 0x5C: // \
                try parseEscape(capturingValue: capturingValue, into: &captured)
            default:
                if capturingValue {
                    captured.append(byte)
                }
            }
        }
        throw Failure.invalidJSON
    }

    private mutating func parseEscape(
        capturingValue: Bool,
        into captured: inout [UInt8]
    ) throws {
        guard let escaped = currentByte else {
            throw Failure.invalidJSON
        }
        index += 1

        let decoded: UInt8?
        switch escaped {
        case 0x22: decoded = 0x22 // "
        case 0x5C: decoded = 0x5C // \
        case 0x2F: decoded = 0x2F // /
        case 0x62: decoded = 0x08 // b
        case 0x66: decoded = 0x0C // f
        case 0x6E: decoded = 0x0A // n
        case 0x72: decoded = 0x0D // r
        case 0x74: decoded = 0x09 // t
        case 0x75: // u
            let first = try consumeHexCodeUnit()
            let scalar: UInt32
            if (0xD800 ... 0xDBFF).contains(first) {
                guard consumeIfPresent(0x5C), consumeIfPresent(0x75) else {
                    throw Failure.invalidJSON
                }
                let second = try consumeHexCodeUnit()
                guard (0xDC00 ... 0xDFFF).contains(second) else {
                    throw Failure.invalidJSON
                }
                scalar = 0x10000
                    + (UInt32(first - 0xD800) << 10)
                    + UInt32(second - 0xDC00)
            } else {
                guard !(0xDC00 ... 0xDFFF).contains(first) else {
                    throw Failure.invalidJSON
                }
                scalar = UInt32(first)
            }
            if capturingValue {
                appendUTF8(scalar, to: &captured)
            }
            return
        default:
            throw Failure.invalidJSON
        }

        if let decoded, capturingValue {
            captured.append(decoded)
        }
    }

    private mutating func consumeHexCodeUnit() throws -> UInt16 {
        var value: UInt16 = 0
        for _ in 0 ..< 4 {
            guard let byte = currentByte, let digit = hexValue(byte) else {
                throw Failure.invalidJSON
            }
            index += 1
            value = (value << 4) | UInt16(digit)
        }
        return value
    }

    private func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30 ... 0x39: return byte - 0x30
        case 0x41 ... 0x46: return byte - 0x41 + 10
        case 0x61 ... 0x66: return byte - 0x61 + 10
        default: return nil
        }
    }

    private func appendUTF8(_ scalar: UInt32, to bytes: inout [UInt8]) {
        switch scalar {
        case 0 ... 0x7F:
            bytes.append(UInt8(scalar))
        case 0x80 ... 0x7FF:
            bytes.append(0xC0 | UInt8(scalar >> 6))
            bytes.append(0x80 | UInt8(scalar & 0x3F))
        case 0x800 ... 0xFFFF:
            bytes.append(0xE0 | UInt8(scalar >> 12))
            bytes.append(0x80 | UInt8((scalar >> 6) & 0x3F))
            bytes.append(0x80 | UInt8(scalar & 0x3F))
        default:
            bytes.append(0xF0 | UInt8(scalar >> 18))
            bytes.append(0x80 | UInt8((scalar >> 12) & 0x3F))
            bytes.append(0x80 | UInt8((scalar >> 6) & 0x3F))
            bytes.append(0x80 | UInt8(scalar & 0x3F))
        }
    }

    private mutating func parseNumber() throws {
        let start = index
        _ = consumeIfPresent(0x2D)
        guard let byte = currentByte else {
            throw Failure.invalidJSON
        }
        if byte == 0x30 {
            index += 1
            if let next = currentByte, (0x30 ... 0x39).contains(next) {
                throw Failure.invalidJSON
            }
        } else if (0x31 ... 0x39).contains(byte) {
            consumeDigits()
        } else {
            throw Failure.invalidJSON
        }

        if consumeIfPresent(0x2E) {
            guard let digit = currentByte, (0x30 ... 0x39).contains(digit) else {
                throw Failure.invalidJSON
            }
            consumeDigits()
        }

        if currentByte == 0x65 || currentByte == 0x45 {
            index += 1
            if currentByte == 0x2B || currentByte == 0x2D {
                index += 1
            }
            guard let digit = currentByte, (0x30 ... 0x39).contains(digit) else {
                throw Failure.invalidJSON
            }
            consumeDigits()
        }

        let number = String(decoding: bytes[start..<index], as: UTF8.self)
        guard let value = Double(number), value.isFinite else {
            throw Failure.invalidJSON
        }
        if canonicalNumbersOnly {
            guard !number.contains("."),
                  !number.contains("e"),
                  !number.contains("E"),
                  number != "-0" else {
                throw Failure.invalidJSON
            }
        }
    }

    private mutating func consumeDigits() {
        while let byte = currentByte, (0x30 ... 0x39).contains(byte) {
            index += 1
        }
    }

    private mutating func consumeLiteral(_ literal: [UInt8]) throws {
        guard index + literal.count <= bytes.count,
              bytes[index ..< index + literal.count].elementsEqual(literal) else {
            throw Failure.invalidJSON
        }
        index += literal.count
    }

    private mutating func consume(_ expected: UInt8) throws {
        guard consumeIfPresent(expected) else {
            throw Failure.invalidJSON
        }
    }

    @discardableResult
    private mutating func consumeIfPresent(_ expected: UInt8) -> Bool {
        guard currentByte == expected else {
            return false
        }
        index += 1
        return true
    }

    private mutating func skipWhitespace() {
        while let byte = currentByte,
              byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D {
            index += 1
        }
    }

    private var currentByte: UInt8? {
        index < bytes.count ? bytes[index] : nil
    }
}

extension Data {
    var base64String: String {
        base64EncodedString()
    }

    static func + (lhs: Data, rhs: Data) -> Data {
        var data = lhs
        data.append(rhs)
        return data
    }
}

extension SymmetricKey {
    var dataRepresentation: Data {
        withUnsafeBytes { Data($0) }
    }
}
