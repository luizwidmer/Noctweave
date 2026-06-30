import Foundation
import PICCPCore

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
        return try PICCPCoder.decode(RelayRequest.self, from: data)
    }

    private func writeJSON<T: Encodable>(_ value: T) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(value)
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.writeLine("")
    }

    private func printHelp() {
        FileHandle.standardOutput.writeLine("""
        NoctyraCLI

        Usage:
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
