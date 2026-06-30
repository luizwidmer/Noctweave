import Foundation
import NoctweaveCore

#if os(Linux)
import Glibc
#else
import Darwin
#endif

@main
struct NoctyraCLI {
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
    let arguments: [String]

    func run() async throws {
        guard let command = arguments.first else {
            printHelp()
            return
        }

        let options = try ParsedOptions(arguments: Array(arguments.dropFirst()))
        switch command {
        case "help", "--help", "-h":
            printHelp()
        case "init":
            try await initialize(options: options)
        case "register":
            try await headlessClient(from: options).registerInbox()
            FileHandle.standardOutput.writeLine("registered")
        case "status":
            try await writeJSON(headlessClient(from: options).status())
        case "export-contact":
            try await exportContact(options: options)
        case "import-contact":
            let contact = try await importContact(options: options)
            try writeJSON(contact)
        case "contacts":
            try await writeJSON(headlessClient(from: options).contacts())
        case "send":
            try await sendText(options: options)
        case "receive":
            try await receive(options: options)
        case "allow-identity-reset":
            try await allowIdentityReset(options: options)
        case "rotate-identity":
            try await rotateIdentity(options: options)
        case "burn-identity":
            try await burnIdentity(options: options)
        case "endpoint":
            let endpoint = try endpoint(from: options)
            try writeJSON(endpoint)
        case "health", "relay-health":
            try await send(.health(), options: options)
        case "info", "relay-info":
            try await send(.info(), options: options)
        case "raw", "send-raw":
            let request = try request(from: options)
            try await send(request, options: options)
        default:
            throw CLIError("Unknown command: \(command). Run `NoctyraCLI help`.")
        }
    }

    private func initialize(options: ParsedOptions) async throws {
        guard let displayName = options.value(for: "--display-name") ?? options.value(for: "--name") else {
            throw CLIError("Missing display name. Use `--display-name <name>`.")
        }
        let relay = try endpoint(from: options)
        let client = try headlessClient(from: options)
        let status = try await client.createState(
            displayName: displayName,
            relay: relay,
            overwrite: try options.boolValue(for: "--overwrite") ?? false
        )
        if try options.boolValue(for: "--register") ?? true {
            try await client.registerInbox()
        }
        try writeJSON(status)
    }

    private func exportContact(options: ParsedOptions) async throws {
        let client = try headlessClient(from: options)
        if let password = options.value(for: "--password") {
            let data = try await client.exportContactPackage(password: password)
            guard let out = options.value(for: "--out") else {
                throw CLIError("Password-protected exports require `--out <path>` to avoid binary data in the terminal.")
            }
            try data.write(to: URL(fileURLWithPath: out), options: [.atomic])
            FileHandle.standardOutput.writeLine(out)
            return
        }
        FileHandle.standardOutput.writeLine(try await client.exportContactCode())
    }

    private func importContact(options: ParsedOptions) async throws -> Contact {
        let client = try headlessClient(from: options)
        if let code = options.value(for: "--code") {
            return try await client.importContactCode(code)
        }
        guard let file = options.value(for: "--file") else {
            throw CLIError("Missing contact input. Use `--code <base64>` or `--file <path> --password <password>`.")
        }
        guard let password = options.value(for: "--password") else {
            throw CLIError("Password-protected contact files require `--password <password>`.")
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: file))
        return try await client.importContactPackage(data, password: password)
    }

    private func sendText(options: ParsedOptions) async throws {
        guard let selector = options.value(for: "--to") else {
            throw CLIError("Missing recipient. Use `--to <contact-name|fingerprint|uuid>`.")
        }
        guard let text = options.value(for: "--text") else {
            throw CLIError("Missing message text. Use `--text <message>`.")
        }
        let sent = try await headlessClient(from: options).sendText(to: selector, text: text)
        try writeJSON(sent)
    }

    private func receive(options: ParsedOptions) async throws {
        let maxCount = try options.intValue(for: "--max") ?? 25
        let longPoll = try options.intValue(for: "--long-poll")
        let acknowledge = !(try options.boolValue(for: "--no-ack") ?? false)
        let messages = try await headlessClient(from: options).receive(
            maxCount: maxCount,
            longPollTimeoutSeconds: longPoll,
            acknowledge: acknowledge
        )
        try writeJSON(messages)
    }

    private func allowIdentityReset(options: ParsedOptions) async throws {
        guard let selector = options.value(for: "--contact") else {
            throw CLIError("Missing contact. Use `--contact <contact-name|fingerprint|uuid>`.")
        }
        let allow = try options.boolValue(for: "--allow") ?? true
        let contact = try await headlessClient(from: options).setContactIdentityReset(selector: selector, allow: allow)
        try writeJSON(contact)
    }

    private func rotateIdentity(options: ParsedOptions) async throws {
        try requireConfirmation(options, key: "--confirm", expected: "ROTATE")
        let result = try await headlessClient(from: options).rotateIdentity()
        try writeJSON(result)
    }

    private func burnIdentity(options: ParsedOptions) async throws {
        try requireConfirmation(options, key: "--confirm", expected: "BURN")
        let result = try await headlessClient(from: options).burnIdentity()
        try writeJSON(result)
    }

    private func send(_ request: RelayRequest, options: ParsedOptions) async throws {
        let endpoint = try endpoint(from: options)
        let authToken = options.value(for: "--auth")
        let timeout = try options.doubleValue(for: "--timeout") ?? RelayClient.defaultTimeout
        let client = RelayClient(endpoint: endpoint, authToken: authToken)
        let response = try await client.send(request, timeout: timeout)
        try writeJSON(response)
    }

    private func endpoint(from options: ParsedOptions) throws -> RelayEndpoint {
        guard let relay = options.value(for: "--relay") ?? options.value(for: "-r") else {
            throw CLIError("Missing relay endpoint. Use `--relay <url|host:port>`.")
        }
        return try RelayEndpointParser.parse(relay)
    }

    private func request(from options: ParsedOptions) throws -> RelayRequest {
        guard let raw = options.value(for: "--request") ?? options.value(for: "--json") else {
            throw CLIError("Missing request JSON. Use `--request '<json>'`, `--request @path`, or `--request -`.")
        }
        let data: Data
        if raw == "-" {
            data = FileHandle.standardInput.readDataToEndOfFile()
        } else if raw.hasPrefix("@") {
            let path = String(raw.dropFirst())
            guard !path.isEmpty else {
                throw CLIError("Request file path is empty.")
            }
            data = try Data(contentsOf: URL(fileURLWithPath: path))
        } else {
            data = Data(raw.utf8)
        }
        return try NoctweaveCoder.decode(RelayRequest.self, from: data)
    }

    private func headlessClient(from options: ParsedOptions) throws -> HeadlessMessagingClient {
        HeadlessMessagingClient(
            stateURL: stateURL(from: options),
            useEncryptedStore: try options.boolValue(for: "--encrypted-state") ?? false,
            authToken: options.value(for: "--auth"),
            timeout: try options.doubleValue(for: "--timeout") ?? RelayClient.defaultTimeout
        )
    }

    private func stateURL(from options: ParsedOptions) -> URL {
        if let path = options.value(for: "--state") {
            return URL(fileURLWithPath: path)
        }
        if let path = ProcessInfo.processInfo.environment["NOCTYRA_CLI_STATE"], !path.isEmpty {
            return URL(fileURLWithPath: path)
        }
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home
            .appendingPathComponent(".noctyra", isDirectory: true)
            .appendingPathComponent("headless-state.json")
    }

    private func writeJSON<T: Encodable>(_ value: T) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(value)
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.writeLine("")
    }

    private func requireConfirmation(_ options: ParsedOptions, key: String, expected: String) throws {
        guard options.value(for: key) == expected else {
            throw CLIError("Missing confirmation. Use `\(key) \(expected)`.")
        }
    }

    private func printHelp() {
        FileHandle.standardOutput.writeLine("""
        NoctyraCLI

        Usage:
          NoctyraCLI init --display-name <name> --relay <url|host:port> [--state path]
          NoctyraCLI register [--state path] [--auth token]
          NoctyraCLI status [--state path]
          NoctyraCLI export-contact [--state path]
          NoctyraCLI export-contact --password <password> --out contact.noctweave [--state path]
          NoctyraCLI import-contact --code <contact-code> [--state path]
          NoctyraCLI import-contact --file contact.noctweave --password <password> [--state path]
          NoctyraCLI contacts [--state path]
          NoctyraCLI send --to <contact-name|fingerprint|uuid> --text <message> [--state path]
          NoctyraCLI receive [--max count] [--long-poll seconds] [--state path]
          NoctyraCLI allow-identity-reset --contact <contact> --allow true [--state path]
          NoctyraCLI rotate-identity --confirm ROTATE [--state path]
          NoctyraCLI burn-identity --confirm BURN [--state path]
          NoctyraCLI endpoint --relay <url|host:port>
          NoctyraCLI health --relay <url|host:port> [--auth token] [--timeout seconds]
          NoctyraCLI info --relay <url|host:port> [--auth token] [--timeout seconds]
          NoctyraCLI raw --relay <url|host:port> --request '<relay-request-json>'
          NoctyraCLI raw --relay <url|host:port> --request @request.json

        Relay endpoint examples:
          127.0.0.1:9339
          http://127.0.0.1:9339
          https://relay.example
          ws://127.0.0.1:9339
          wss://relay.example
          tcp://relay.local:9339
          tls://relay.example:9339

        Headless client state:
          --state defaults to ~/.noctyra/headless-state.json or NOCTYRA_CLI_STATE.
          State contains private identity keys. Protect it with filesystem permissions.
        """)
    }
}

private struct ParsedOptions {
    private let values: [String: String]

    init(arguments: [String]) throws {
        var parsed: [String: String] = [:]
        var index = arguments.startIndex
        while index < arguments.endIndex {
            let key = arguments[index]
            guard key.hasPrefix("-") else {
                throw CLIError("Unexpected argument: \(key).")
            }
            let valueIndex = arguments.index(after: index)
            guard valueIndex < arguments.endIndex else {
                throw CLIError("Missing value for \(key).")
            }
            parsed[key] = arguments[valueIndex]
            index = arguments.index(after: valueIndex)
        }
        values = parsed
    }

    func value(for key: String) -> String? {
        values[key]
    }

    func doubleValue(for key: String) throws -> Double? {
        guard let value = values[key] else { return nil }
        guard let parsed = Double(value), parsed > 0 else {
            throw CLIError("Invalid numeric value for \(key): \(value).")
        }
        return parsed
    }

    func intValue(for key: String) throws -> Int? {
        guard let value = values[key] else { return nil }
        guard let parsed = Int(value), parsed > 0 else {
            throw CLIError("Invalid integer value for \(key): \(value).")
        }
        return parsed
    }

    func boolValue(for key: String) throws -> Bool? {
        guard let value = values[key]?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() else {
            return nil
        }
        switch value {
        case "1", "true", "yes", "y", "on":
            return true
        case "0", "false", "no", "n", "off":
            return false
        default:
            throw CLIError("Invalid boolean value for \(key): \(value).")
        }
    }
}

private struct CLIError: Error {
    let message: String
    let exitCode: Int

    init(_ message: String, exitCode: Int = 2) {
        self.message = message
        self.exitCode = exitCode
    }
}

private extension FileHandle {
    func writeLine(_ line: String) {
        write(Data((line + "\n").utf8))
    }
}
