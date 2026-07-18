import Foundation
import NoctweaveCore

#if os(Linux)
import Glibc
#else
import Darwin
#endif

@main
struct NoctweaveCLI {
    static func main() async {
        do {
            try await CommandRunner(arguments: Array(CommandLine.arguments.dropFirst())).run()
        } catch let error as CLIError {
            FileHandle.standardError.writeLine(error.message)
            exit(Int32(error.exitCode))
        } catch {
            FileHandle.standardError.writeLine(error.localizedDescription)
            exit(1)
        }
    }
}

private struct CommandRunner {
    private static let maximumRawRequestBytes = 512 * 1_024
    let arguments: [String]

    func run() async throws {
        guard let command = arguments.first else {
            printHelp()
            return
        }
        let options = try ParsedOptions(Array(arguments.dropFirst()))
        switch command {
        case "help", "--help", "-h":
            printHelp()
        case "init":
            try await initialize(options)
        case "status":
            try await status(options)
        case "relationships":
            let client = try await headlessClient(options)
            try writeJSON(await client.activePersona().relationships)
        case "prepare-participant":
            try await prepareParticipant(options)
        case "pairing-invitation":
            try await pairingInvitation(options)
        case "send":
            try await sendText(options)
        case "sync":
            try await sync(options)
        case "burn-persona":
            try await burnPersona(options)
        case "endpoint":
            try writeJSON(try endpoint(options))
        case "health", "relay-health":
            try await sendRelay(.health(), options: options)
        case "info", "relay-info":
            try await sendRelay(.info(), options: options)
        case "raw", "send-raw":
            try await sendRelay(try relayRequest(options), options: options)
        default:
            throw CLIError("Unknown command: \(command). Run `NoctweaveCLI help`.")
        }
    }

    private func initialize(_ options: ParsedOptions) async throws {
        let name = try required(options, "--display-name")
        let store = try stateStore(options)
        if try await store.load() != nil {
            throw CLIError("State already exists.")
        }
        let client = try await HeadlessMessagingClient.open(
            stateStore: store,
            displayName: name
        )
        try writeJSON(await client.snapshot())
    }

    private func status(_ options: ParsedOptions) async throws {
        let client = try await headlessClient(options)
        try writeJSON(await client.snapshot())
    }

    private func prepareParticipant(_ options: ParsedOptions) async throws {
        let output = try required(options, "--out")
        let client = try await headlessClient(options)
        let pending = try await client.prepareContactParticipant(
            relay: try endpoint(options),
            relationshipPseudonym: options.value("--relationship-pseudonym")
                ?? "Noctweave peer"
        )
        let prepared = try await client.activateContactParticipant(pending)
        try writeSensitiveJSON(prepared, to: output)
        FileHandle.standardOutput.writeLine(output)
    }

    private func pairingInvitation(_ options: ParsedOptions) async throws {
        let output = try required(options, "--out")
        let lifetime = try options.int("--lifetime") ?? 600
        guard (30...3_600).contains(lifetime) else {
            throw CLIError("Pairing invitation lifetime must be between 30 and 3600 seconds.")
        }
        let client = try await headlessClient(options)
        let createdAt = Date()
        let result = try await client.makeContactPairingInvitation(
            createdAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(TimeInterval(lifetime))
        )
        try writeSensitiveJSON(PairingOfferFile(
            pending: result.pending,
            invitation: result.invitation
        ), to: output)
        FileHandle.standardOutput.writeLine(try result.invitation.encoded())
    }

    private func sendText(_ options: ParsedOptions) async throws {
        let relationshipID = try relationshipIdentifier(options)
        let text = try required(options, "--text")
        try writeJSON(try await headlessClient(options).sendText(
            text,
            relationshipID: relationshipID
        ))
    }

    private func sync(_ options: ParsedOptions) async throws {
        let relationshipID = try relationshipIdentifier(options)
        let maximum = try options.int("--max") ?? 128
        guard let limit = UInt16(exactly: maximum), limit > 0 else {
            throw CLIError("Sync maximum must be a positive 16-bit integer.")
        }
        try writeJSON(try await headlessClient(options).sync(
            relationshipID: relationshipID,
            maximumPackets: limit
        ))
    }

    private func burnPersona(_ options: ParsedOptions) async throws {
        guard options.value("--confirm") == "BURN" else {
            throw CLIError("Persona burn requires `--confirm BURN`.")
        }
        let replacementName = try required(options, "--replacement-name")
        try writeJSON(try await headlessClient(options).burnActivePersona(
            replacementDisplayName: replacementName
        ))
    }

    private func headlessClient(_ options: ParsedOptions) async throws -> HeadlessMessagingClient {
        let store = try stateStore(options)
        guard let state = try await store.load() else {
            throw CLIError("No state exists. Run `NoctweaveCLI init` first.")
        }
        return try HeadlessMessagingClient(stateStore: store, initialState: state)
    }

    private func stateStore(_ options: ParsedOptions) throws -> ClientStateStore {
        let path = options.value("--state") ?? "./noctweave-state.json"
        let plaintext = try options.bool("--plaintext") ?? false
        return ClientStateStore(
            fileURL: URL(fileURLWithPath: path),
            useEncryption: !plaintext
        )
    }

    private func relationshipIdentifier(_ options: ParsedOptions) throws -> UUID {
        let raw = try required(options, "--relationship")
        guard let id = UUID(uuidString: raw) else {
            throw CLIError("Relationship identifier must be a UUID.")
        }
        return id
    }

    private func endpoint(_ options: ParsedOptions) throws -> RelayEndpoint {
        try RelayEndpointParser.parse(try required(options, "--relay"))
    }

    private func sendRelay(_ request: RelayRequest, options: ParsedOptions) async throws {
        let timeout = try options.double("--timeout") ?? RelayClient.defaultTimeout
        let response = try await RelayClient(
            endpoint: try endpoint(options),
            authToken: try authToken(options)
        ).send(request, timeout: timeout)
        try writeJSON(response)
    }

    private func relayRequest(_ options: ParsedOptions) throws -> RelayRequest {
        let raw = try required(options, "--request")
        let data: Data
        if raw.hasPrefix("@") {
            let path = String(raw.dropFirst())
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            guard let size = attributes[.size] as? NSNumber,
                  size.intValue <= Self.maximumRawRequestBytes else {
                throw CLIError("Relay request file exceeds the size limit.")
            }
            data = try Data(contentsOf: URL(fileURLWithPath: path))
        } else {
            data = Data(raw.utf8)
        }
        guard !data.isEmpty, data.count <= Self.maximumRawRequestBytes else {
            throw CLIError("Relay request is empty or exceeds the size limit.")
        }
        return try NoctweaveCoder.decode(RelayRequest.self, from: data)
    }

    private func authToken(_ options: ParsedOptions) throws -> String? {
        guard let path = options.value("--auth-file") else { return nil }
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        guard let size = attributes[.size] as? NSNumber, size.intValue <= 4_096 else {
            throw CLIError("Relay authentication file exceeds the size limit.")
        }
        let value = try String(contentsOfFile: path, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { throw CLIError("Relay authentication file is empty.") }
        return value
    }

    private func required(_ options: ParsedOptions, _ name: String) throws -> String {
        guard let value = options.value(name), !value.isEmpty else {
            throw CLIError("Missing required option `\(name)`.")
        }
        return value
    }

    private func writeJSON<T: Encodable>(_ value: T) throws {
        var data = try NoctweaveCoder.encode(value)
        defer { data.wipeCLIOutputBuffer() }
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([0x0a]))
    }

    private func writeSensitiveJSON<T: Encodable>(_ value: T, to path: String) throws {
        var data = try NoctweaveCoder.encode(value)
        defer { data.wipeCLIOutputBuffer() }
        let url = URL(fileURLWithPath: path)
        try data.write(to: url, options: Data.WritingOptions.atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: url.path
        )
    }

    private func printHelp() {
        FileHandle.standardOutput.writeLine("""
        NoctweaveCLI — pairwise-private Noctweave 1.0 architecture

          init --display-name <local-label> [--state path] [--plaintext true]
          status [--state path] [--plaintext true]
          relationships [--state path] [--plaintext true]
          prepare-participant --relay <https|wss|tls URL> --out <private-file> [--relationship-pseudonym label]
          pairing-invitation --out <private-file> [--lifetime seconds]
          send --relationship <uuid> --text <message>
          sync --relationship <uuid> [--max packets]
          burn-persona --confirm BURN --replacement-name <local-label>
          endpoint --relay <url|host:port>
          health --relay <url|host:port> [--auth-file path] [--timeout seconds]
          info --relay <url|host:port> [--auth-file path] [--timeout seconds]
          raw --relay <url|host:port> --request '<json|@path>'

        Personas are local containers. Pairing creates independent, unlinkable
        relationship identities and opaque relay routes. Personas never become
        network identifiers.
        """)
    }
}

private struct PairingOfferFile: Codable {
    let pending: PendingRendezvousOfferV2
    let invitation: ContactPairingInvitationV2
}

private struct ParsedOptions {
    private let values: [String: String]

    init(_ arguments: [String]) throws {
        var parsed: [String: String] = [:]
        var index = 0
        while index < arguments.count {
            let key = arguments[index]
            guard key.hasPrefix("--"), parsed[key] == nil else {
                throw CLIError("Invalid or duplicate option: \(key)")
            }
            guard index + 1 < arguments.count else {
                throw CLIError("Option requires a value: \(key)")
            }
            parsed[key] = arguments[index + 1]
            index += 2
        }
        values = parsed
    }

    func value(_ key: String) -> String? { values[key] }

    func int(_ key: String) throws -> Int? {
        guard let raw = value(key) else { return nil }
        guard let value = Int(raw) else { throw CLIError("Invalid integer for `\(key)`.") }
        return value
    }

    func double(_ key: String) throws -> Double? {
        guard let raw = value(key) else { return nil }
        guard let value = Double(raw), value.isFinite else {
            throw CLIError("Invalid number for `\(key)`.")
        }
        return value
    }

    func bool(_ key: String) throws -> Bool? {
        guard let raw = value(key)?.lowercased() else { return nil }
        switch raw {
        case "true", "1", "yes": return true
        case "false", "0", "no": return false
        default: throw CLIError("Invalid boolean for `\(key)`.")
        }
    }
}

private struct CLIError: Error {
    let message: String
    let exitCode: Int

    init(_ message: String, exitCode: Int = 1) {
        self.message = message
        self.exitCode = exitCode
    }
}

private extension FileHandle {
    func writeLine(_ value: String) {
        write(Data((value + "\n").utf8))
    }
}

private extension Data {
    mutating func wipeCLIOutputBuffer() {
        withUnsafeMutableBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            memset(baseAddress, 0, rawBuffer.count)
        }
        removeAll(keepingCapacity: false)
    }
}
