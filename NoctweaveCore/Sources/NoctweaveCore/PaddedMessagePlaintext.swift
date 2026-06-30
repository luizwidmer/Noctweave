import Foundation

enum PaddedMessagePlaintext {
    static let minimumPaddedBytes = 512
    static let maximumPaddedBytes = 65_536
    private static let magic = Data([0x4E, 0x50, 0x41, 0x44, 0x01]) // NPAD v1
    private static let headerBytes = 9

    static func encode(_ body: MessageBody) throws -> Data {
        let bodyData = try NoctweaveCoder.encode(body, sortedKeys: true)
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
            data.append(contentsOf: (0..<paddingCount).map { _ in UInt8.random(in: 0...255) })
        }
        return data
    }

    static func decode(_ data: Data) throws -> MessageBody {
        if data.count >= headerBytes,
           data.prefix(magic.count) == magic {
            let lengthStart = magic.count
            let lengthEnd = lengthStart + 4
            let bodyLength = Int(UInt32(bigEndianBytes: data[lengthStart..<lengthEnd]))
            let bodyStart = lengthEnd
            let bodyEnd = bodyStart + bodyLength
            guard bodyLength >= 0, bodyEnd <= data.count else {
                throw CryptoError.invalidPayload
            }
            return try NoctweaveCoder.decode(MessageBody.self, from: Data(data[bodyStart..<bodyEnd]))
        }
        return try NoctweaveCoder.decode(MessageBody.self, from: data)
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
