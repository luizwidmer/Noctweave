import Foundation

enum PaddedMessagePlaintext {
    static let minimumPaddedBytes = 512
    static let maximumPaddedBytes = 65_536
    private static let wirePayloadV2Magic = Data([0x4E, 0x50, 0x41, 0x44, 0x02]) // NPAD v2
    private static let headerBytes = 9

    static func encodeWirePayloadV2(_ payload: WirePayloadV2) throws -> Data {
        guard payload.isStructurallyValid else { throw WirePayloadV2Error.invalidPayload }
        return try encode(payload, magic: wirePayloadV2Magic)
    }

    static func decodeWirePayloadV2(_ data: Data) throws -> WirePayloadV2 {
        let payload = try decode(WirePayloadV2.self, from: data, magic: wirePayloadV2Magic)
        guard payload.isStructurallyValid else { throw WirePayloadV2Error.invalidPayload }
        return payload
    }

    private static func encode<T: Encodable>(_ body: T, magic: Data) throws -> Data {
        var bodyData = try NoctweaveCoder.encode(body, sortedKeys: true)
        defer { bodyData.secureWipe() }
        let paddedSize = paddedSize(for: bodyData.count)
        guard paddedSize <= maximumPaddedBytes,
              bodyData.count <= UInt32.max,
              paddedSize >= headerBytes + bodyData.count else {
            throw CryptoError.invalidPayload
        }
        let paddingCount = paddedSize - headerBytes - bodyData.count
        var data = Data()
        data.reserveCapacity(paddedSize)
        data.append(magic)
        data.append(contentsOf: UInt32(bodyData.count).bigEndianBytes)
        data.append(bodyData)
        if paddingCount > 0 {
            var generator = SystemRandomNumberGenerator()
            var padding = [UInt8](repeating: 0, count: paddingCount)
            for index in padding.indices {
                padding[index] = UInt8.random(in: .min ... .max, using: &generator)
            }
            data.append(contentsOf: padding)
        }
        return data
    }

    private static func decode<T: Decodable>(_ type: T.Type, from data: Data, magic: Data) throws -> T {
        guard data.count >= headerBytes,
              data.count <= maximumPaddedBytes,
              data.count >= minimumPaddedBytes,
              data.count.isPowerOfTwo,
              data.prefix(magic.count) == magic else {
            throw CryptoError.invalidPayload
        }
        let lengthStart = magic.count
        let lengthEnd = lengthStart + 4
        let bodyLength = Int(UInt32(bigEndianBytes: data[lengthStart..<lengthEnd]))
        let bodyStart = lengthEnd
        let bodyEnd = bodyStart + bodyLength
        guard bodyLength > 0,
              bodyEnd <= data.count,
              paddedSize(for: bodyLength) == data.count else {
            throw CryptoError.invalidPayload
        }
        var bodyData = Data(data[bodyStart..<bodyEnd])
        defer { bodyData.secureWipe() }
        return try NoctweaveCoder.decode(type, from: bodyData)
    }

    private static func paddedSize(for bodyBytes: Int) -> Int {
        let required = max(minimumPaddedBytes, bodyBytes + headerBytes)
        var size = minimumPaddedBytes
        while size < required && size < maximumPaddedBytes {
            size *= 2
        }
        return size
    }
}

private extension Int {
    var isPowerOfTwo: Bool {
        self > 0 && (self & (self - 1)) == 0
    }
}

private extension UInt32 {
    var bigEndianBytes: [UInt8] {
        [
            UInt8((self >> 24) & 0xff),
            UInt8((self >> 16) & 0xff),
            UInt8((self >> 8) & 0xff),
            UInt8(self & 0xff)
        ]
    }

    init(bigEndianBytes bytes: Data.SubSequence) {
        var value: UInt32 = 0
        for byte in bytes {
            value = (value << 8) | UInt32(byte)
        }
        self = value
    }
}
