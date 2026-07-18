import Foundation

/// A process-local guard that binds an in-flight construction operation to the
/// local persona that began it.
///
/// The token is intentionally not `Codable` and contains no protocol identity,
/// cryptographic authority, relay address, or cross-client identifier. Mint it
/// immediately before constructing a relationship or group outside the client,
/// then present it when inserting the completed local state.
public struct LocalPersonaScopeToken: Sendable, Equatable, Hashable {
    let personaID: UUID
    let clientInstanceNonce: UUID

    init(personaID: UUID, clientInstanceNonce: UUID) {
        self.personaID = personaID
        self.clientInstanceNonce = clientInstanceNonce
    }
}
