import Foundation

extension Data {
    /// Best-effort in-place clearing for temporary secret buffers owned by this value.
    /// Swift and Foundation may retain copies outside this buffer, so callers must not
    /// treat this as a guarantee against a hostile process or operating system.
    mutating func secureWipe() {
        guard !isEmpty else { return }
        let byteCount = count
        withUnsafeMutableBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            #if canImport(Darwin)
            _ = memset_s(baseAddress, byteCount, 0, byteCount)
            #else
            _ = memset(baseAddress, 0, byteCount)
            #endif
        }
        removeAll(keepingCapacity: false)
    }
}
