import Foundation
import Crypto

enum InboxAddress {
    static let hrp = "piccp"
    private static let dataLength = 32

    static func generate() -> String {
        var bytes = [UInt8](repeating: 0, count: dataLength)
        for index in bytes.indices {
            bytes[index] = UInt8.random(in: 0...255)
        }
        return Bech32.encode(hrp: hrp, data: bytes)
    }

    static func derived(from accessPublicKey: Data) -> String {
        Bech32.encode(hrp: hrp, data: Array(SHA256.hash(data: accessPublicKey)))
    }

    static func isBound(_ address: String, to accessPublicKey: Data) -> Bool {
        address.lowercased() == derived(from: accessPublicKey)
    }

    static func decode(_ address: String) -> Data? {
        guard let decoded = Bech32.decode(address), decoded.hrp == hrp else {
            return nil
        }
        guard decoded.data.count == dataLength else {
            return nil
        }
        return Data(decoded.data)
    }

    static func isValid(_ address: String) -> Bool {
        decode(address) != nil
    }
}

enum Bech32 {
    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
    private static let generator: [UInt32] = [
        0x3b6a57b2,
        0x26508e6d,
        0x1ea119fa,
        0x3d4233dd,
        0x2a1462b3
    ]

    static func encode(hrp: String, data: [UInt8]) -> String {
        let lowerHrp = hrp.lowercased()
        let data5 = convertBits(data, from: 8, to: 5, pad: true) ?? []
        let checksum = createChecksum(hrp: lowerHrp, data: data5)
        let combined = data5 + checksum
        let payload = combined.map { charset[Int($0)] }
        return lowerHrp + "1" + String(payload)
    }

    static func decode(_ value: String) -> (hrp: String, data: [UInt8])? {
        guard !value.isEmpty else { return nil }
        let hasLower = value.rangeOfCharacter(from: CharacterSet.lowercaseLetters) != nil
        let hasUpper = value.rangeOfCharacter(from: CharacterSet.uppercaseLetters) != nil
        if hasLower && hasUpper {
            return nil
        }
        let bech = value.lowercased()
        guard let separatorIndex = bech.lastIndex(of: "1") else { return nil }
        let hrp = String(bech[..<separatorIndex])
        let dataPart = bech[bech.index(after: separatorIndex)...]
        guard !hrp.isEmpty, dataPart.count >= 6 else { return nil }

        var data: [UInt8] = []
        data.reserveCapacity(dataPart.count)
        for char in dataPart {
            guard let index = charset.firstIndex(of: char) else { return nil }
            data.append(UInt8(index))
        }

        guard verifyChecksum(hrp: hrp, data: data) else { return nil }
        let payload = Array(data.dropLast(6))
        guard let decoded = convertBits(payload, from: 5, to: 8, pad: false) else { return nil }
        return (hrp, decoded)
    }

    private static func verifyChecksum(hrp: String, data: [UInt8]) -> Bool {
        var values = hrpExpand(hrp)
        values.append(contentsOf: data)
        return bech32Polymod(values) == 1
    }

    private static func createChecksum(hrp: String, data: [UInt8]) -> [UInt8] {
        var values = hrpExpand(hrp)
        values.append(contentsOf: data)
        values.append(contentsOf: Array(repeating: 0, count: 6))
        let polymod = bech32Polymod(values) ^ 1
        var checksum: [UInt8] = []
        checksum.reserveCapacity(6)
        for i in 0..<6 {
            let shift = UInt32(5 * (5 - i))
            checksum.append(UInt8((polymod >> shift) & 0x1f))
        }
        return checksum
    }

    private static func hrpExpand(_ hrp: String) -> [UInt8] {
        let bytes = Array(hrp.utf8)
        var expanded: [UInt8] = []
        expanded.reserveCapacity(bytes.count * 2 + 1)
        for byte in bytes {
            expanded.append(byte >> 5)
        }
        expanded.append(0)
        for byte in bytes {
            expanded.append(byte & 31)
        }
        return expanded
    }

    private static func bech32Polymod(_ values: [UInt8]) -> UInt32 {
        var chk: UInt32 = 1
        for value in values {
            let top = chk >> 25
            chk = (chk & 0x1ffffff) << 5
            chk ^= UInt32(value)
            for i in 0..<5 {
                if ((top >> i) & 1) != 0 {
                    chk ^= generator[i]
                }
            }
        }
        return chk
    }

    private static func convertBits(_ data: [UInt8], from: Int, to: Int, pad: Bool) -> [UInt8]? {
        var acc = 0
        var bits = 0
        let maxv = (1 << to) - 1
        var result: [UInt8] = []
        for value in data {
            if value >> from != 0 {
                return nil
            }
            acc = (acc << from) | Int(value)
            bits += from
            while bits >= to {
                bits -= to
                result.append(UInt8((acc >> bits) & maxv))
            }
        }
        if pad {
            if bits > 0 {
                result.append(UInt8((acc << (to - bits)) & maxv))
            }
        } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
            return nil
        }
        return result
    }
}
