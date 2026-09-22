// SPDX-License-Identifier: AGPL-3.0-or-later

/// Fixed local page identities. Branding and callbacks never accept user-supplied HTML.
/// Apps share the browser's localhost RP namespace, but not credential storage.
public enum LocalSecurityKeyApp: Sendable, CaseIterable {
    case noctGallery
    case noctweave

    var application: SecurityKeyApplication {
        switch self {
        case .noctGallery: .noctGalleryLocal
        case .noctweave: .noctweaveLocal
        }
    }

    var name: String {
        switch self {
        case .noctGallery: "Noct Gallery"
        case .noctweave: "Noctweave"
        }
    }

    var callbackScheme: String {
        switch self {
        case .noctGallery: "noctgallery-local-fido"
        case .noctweave: "noctweave-local-fido"
        }
    }
}
