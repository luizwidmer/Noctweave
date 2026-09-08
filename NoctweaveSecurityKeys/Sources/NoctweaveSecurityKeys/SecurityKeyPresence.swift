// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
#if os(macOS)
import IOKit
#endif

/// Temporary OS attachment identity, captured from the connection that verified the key.
/// Never persisted. A disconnect/reconnect creates a different registry identity.
public struct SecurityKeyPresence: Equatable, Sendable {
    public let registryEntryID: UInt64

    public init(registryEntryID: UInt64) { self.registryEntryID = registryEntryID }

    public static var isSupported: Bool {
        #if os(macOS)
        true
        #else
        false
        #endif
    }

    public var isConnected: Bool {
        #if os(macOS)
        guard registryEntryID != 0, let matching = IORegistryEntryIDMatching(registryEntryID) else { return false }
        let service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
        guard service != 0 else { return false }
        defer { IOObjectRelease(service) }
        var observed: UInt64 = 0
        return IORegistryEntryGetRegistryEntryID(service, &observed) == KERN_SUCCESS && observed == registryEntryID
        #else
        return false
        #endif
    }
}
