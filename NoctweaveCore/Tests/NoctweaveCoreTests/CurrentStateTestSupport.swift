import Foundation
@testable import NoctweaveCore

func makeCurrentIdentityProfile(
    identity: Identity,
    relay: RelayEndpoint,
    contacts: [Contact] = [],
    conversations: [Conversation] = [],
    groups: [GroupConversation] = [],
    selectedRelayId: UUID? = nil,
    prekeys: PrekeyState? = nil,
    createdAt: Date = Date()
) throws -> IdentityProfile {
    let inboxAccessKey = try SigningKeyPair.generate()
    var profile = try IdentityProfile.create(
        identity: identity,
        relay: relay,
        inboxAccessKey: inboxAccessKey,
        selectedRelayId: selectedRelayId,
        prekeys: prekeys,
        createdAt: createdAt
    )
    profile.contacts = contacts
    profile.conversations = conversations
    profile.groups = groups
    return profile
}

func makeCurrentClientState(
    identity: Identity,
    relay: RelayEndpoint,
    prekeys: PrekeyState? = nil
) throws -> ClientState {
    try ClientState(
        identity: identity,
        relay: relay,
        inboxAccessKey: SigningKeyPair.generate(),
        prekeys: prekeys
    )
}
