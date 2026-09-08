// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

enum CBORKey: Hashable {
    case integer(Int64), text(String)
}

indirect enum CBORValue {
    case integer(Int64), bytes(Data), text(String), array([CBORValue]), map([CBORKey: CBORValue]), bool(Bool), null
    var bytes: Data? { if case .bytes(let value) = self { value } else { nil } }
    var integer: Int64? { if case .integer(let value) = self { value } else { nil } }
    var map: [CBORKey: CBORValue]? { if case .map(let value) = self { value } else { nil } }
}

/// The local verification boundary accepts only bounded, definite-length CTAP CBOR.
struct BoundedCBOR {
    let bytes: [UInt8]
    private(set) var offset: Int = 0

    init(_ data: Data) throws {
        guard data.count <= 65_536 else { throw SecurityKeyError.invalidResponse }
        bytes = Array(data)
    }

    mutating func parse(depth: Int = 0) throws -> CBORValue {
        guard depth <= 8 else { throw SecurityKeyError.invalidResponse }
        let initial = try takeByte()
        let major = initial >> 5
        let additional = initial & 31
        if major == 7 {
            switch additional {
            case 20: return .bool(false)
            case 21: return .bool(true)
            case 22: return .null
            default: throw SecurityKeyError.invalidResponse
            }
        }
        let length = try argument(additional)
        guard length <= UInt64(Int64.max) else { throw SecurityKeyError.invalidResponse }
        switch major {
        case 0: return .integer(Int64(length))
        case 1: return .integer(-1 - Int64(length))
        case 2: return .bytes(try take(Int(length)))
        case 3:
            guard let value = String(data: try take(Int(length)), encoding: .utf8) else {
                throw SecurityKeyError.invalidResponse
            }
            return .text(value)
        case 4:
            guard length <= 64 else { throw SecurityKeyError.invalidResponse }
            var values: [CBORValue] = []
            for _ in 0..<length { values.append(try parse(depth: depth + 1)) }
            return .array(values)
        case 5:
            guard length <= 64 else { throw SecurityKeyError.invalidResponse }
            var values: [CBORKey: CBORValue] = [:]
            for _ in 0..<length {
                let key: CBORKey
                switch try parse(depth: depth + 1) {
                case .integer(let value): key = .integer(value)
                case .text(let value): key = .text(value)
                default: throw SecurityKeyError.invalidResponse
                }
                guard values[key] == nil else { throw SecurityKeyError.invalidResponse }
                values[key] = try parse(depth: depth + 1)
            }
            return .map(values)
        default: throw SecurityKeyError.invalidResponse
        }
    }

    private mutating func takeByte() throws -> UInt8 {
        guard offset < bytes.count else { throw SecurityKeyError.invalidResponse }
        defer { offset += 1 }
        return bytes[offset]
    }

    private mutating func take(_ count: Int) throws -> Data {
        guard count >= 0, count <= bytes.count - offset else { throw SecurityKeyError.invalidResponse }
        defer { offset += count }
        return Data(bytes[offset..<(offset + count)])
    }

    private mutating func argument(_ value: UInt8) throws -> UInt64 {
        if value < 24 { return UInt64(value) }
        let count: Int
        switch value {
        case 24: count = 1
        case 25: count = 2
        case 26: count = 4
        case 27: count = 8
        default: throw SecurityKeyError.invalidResponse
        }
        var result: UInt64 = 0
        for _ in 0..<count { result = (result << 8) | UInt64(try takeByte()) }
        let minimum: UInt64 = count == 1 ? 24 : count == 2 ? 256 : count == 4 ? 65_536 : 4_294_967_296
        guard result >= minimum else { throw SecurityKeyError.invalidResponse }
        return result
    }
}
