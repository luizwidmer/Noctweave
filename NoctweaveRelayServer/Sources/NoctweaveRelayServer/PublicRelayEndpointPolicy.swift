import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

enum PublicRelayEndpointPolicy {
    static func permits(_ endpoint: RelayEndpoint) -> Bool {
        let host = endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !host.isEmpty,
              host != "localhost",
              !host.hasSuffix(".localhost"),
              !host.hasSuffix(".local"),
              !host.hasSuffix(".internal"),
              !host.hasSuffix(".lan") else {
            return false
        }
        guard let addresses = resolvedAddresses(host: host), !addresses.isEmpty else {
            return false
        }
        return addresses.allSatisfy(isPubliclyRoutable)
    }

    private enum Address {
        case v4([UInt8])
        case v6([UInt8])
    }

    private static func resolvedAddresses(host: String) -> [Address]? {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        #if canImport(Glibc)
        hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        #else
        hints.ai_socktype = SOCK_STREAM
        #endif
        hints.ai_protocol = Int32(IPPROTO_TCP)
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0 else {
            return nil
        }
        defer { freeaddrinfo(result) }

        var addresses: [Address] = []
        var cursor = result
        while let current = cursor?.pointee {
            if current.ai_family == AF_INET, let socketAddress = current.ai_addr {
                var address = socketAddress.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                    $0.pointee.sin_addr
                }
                addresses.append(.v4(withUnsafeBytes(of: &address) { Array($0) }))
            } else if current.ai_family == AF_INET6, let socketAddress = current.ai_addr {
                var address = socketAddress.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
                    $0.pointee.sin6_addr
                }
                addresses.append(.v6(withUnsafeBytes(of: &address) { Array($0) }))
            }
            cursor = current.ai_next
        }
        return addresses
    }

    private static func isPubliclyRoutable(_ address: Address) -> Bool {
        switch address {
        case .v4(let bytes):
            return isPublicIPv4(bytes)
        case .v6(let bytes):
            guard bytes.count == 16 else { return false }
            if bytes.prefix(10).allSatisfy({ $0 == 0 }),
               bytes[10] == 0xff, bytes[11] == 0xff {
                return isPublicIPv4(Array(bytes[12...15]))
            }
            if bytes.prefix(12).elementsEqual([0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]) {
                return isPublicIPv4(Array(bytes[12...15]))
            }
            guard bytes[0] & 0xe0 == 0x20 else { return false }
            if bytes[0] == 0x20, bytes[1] == 0x01, bytes[2] == 0x0d, bytes[3] == 0xb8 {
                return false
            }
            if bytes[0] == 0x20, bytes[1] == 0x01, bytes[2] == 0x00, bytes[3] == 0x00 {
                return false
            }
            if bytes[0] == 0x20, bytes[1] == 0x01, bytes[2] == 0x00, bytes[3] == 0x02 {
                return false
            }
            if bytes[0] == 0x20, bytes[1] == 0x02 {
                return isPublicIPv4(Array(bytes[2...5]))
            }
            if bytes[0] == 0x3f, bytes[1] & 0xf0 == 0xf0 {
                return false
            }
            return true
        }
    }

    private static func isPublicIPv4(_ bytes: [UInt8]) -> Bool {
        guard bytes.count == 4 else { return false }
        let a = bytes[0], b = bytes[1], c = bytes[2]
        if a == 0 || a == 10 || a == 127 || a >= 224 { return false }
        if a == 100, (64...127).contains(b) { return false }
        if a == 169, b == 254 { return false }
        if a == 172, (16...31).contains(b) { return false }
        if a == 192, b == 168 { return false }
        if a == 192, b == 0 { return false }
        if a == 192, b == 88, c == 99 { return false }
        if a == 198, b == 18 || b == 19 { return false }
        if a == 198, b == 51, c == 100 { return false }
        if a == 203, b == 0, c == 113 { return false }
        return true
    }
}
