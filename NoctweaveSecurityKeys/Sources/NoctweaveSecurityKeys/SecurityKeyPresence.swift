// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
#if os(macOS)
import IOKit
import IOKit.hid
#elseif os(iOS)
import YubiKit
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

    /// Discovery only: attachment never establishes credential ownership or grants access.
    /// Tokens are ephemeral, stay local, and change across USB detach/attach events.
    public static func attachedDeviceTokens() async -> [String] {
        #if os(macOS)
        var iterator: io_iterator_t = 0
        guard IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching(kIOHIDDeviceKey), &iterator) == KERN_SUCCESS else { return [] }
        defer { IOObjectRelease(iterator) }
        var result = Set<String>()
        while case let service = IOIteratorNext(iterator), service != 0 {
            defer { IOObjectRelease(service) }
            let page = IORegistryEntryCreateCFProperty(service, kIOHIDPrimaryUsagePageKey as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? NSNumber
            let usage = IORegistryEntryCreateCFProperty(service, kIOHIDPrimaryUsageKey as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? NSNumber
            guard page?.intValue == 0xF1D0, usage?.intValue == 1 else { continue }
            var identity: UInt64 = 0
            if IORegistryEntryGetRegistryEntryID(service, &identity) == KERN_SUCCESS, identity != 0 {
                result.insert(String(identity))
            }
            if result.count == 32 { break }
        }
        return result.sorted()
        #elseif os(iOS)
        return (try? await USBSmartCardConnection.availableDevices().prefix(32).map { String(describing: $0) }.sorted()) ?? []
        #else
        return []
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
