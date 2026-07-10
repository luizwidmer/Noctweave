import Foundation
import CryptoKit
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
    private static let maximumContactPackageBytes = 512 * 1024
    private static let maximumRawRequestBytes = 512 * 1024
    private static let maximumAttachmentBytes = AttachmentDescriptor.maximumTransportBytes

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
        case "group-create":
            try await createGroup(options: options)
        case "groups":
            try await listGroups(options: options)
        case "group-send":
            try await sendGroupText(options: options)
        case "group-send-attachment":
            try await sendGroupAttachment(options: options, voice: false)
        case "group-send-voice":
            try await sendGroupAttachment(options: options, voice: true)
        case "group-receive":
            try await receiveGroupMessages(options: options)
        case "continuity-audit":
            try await writeJSON(headlessClient(from: options).continuityAudit())
        case "purge-continuity-audit":
            try await purgeContinuityAudit(options: options)
        case "send":
            try await sendText(options: options)
        case "send-attachment":
            try await sendAttachment(options: options, voice: false)
        case "send-voice":
            try await sendAttachment(options: options, voice: true)
        case "receive":
            try await receive(options: options)
        case "download-attachment":
            try await downloadAttachment(options: options)
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
        if let password = try contactPassword(from: options) {
            var data = try await client.exportContactPackage(password: password)
            defer { data.secureWipe() }
            guard let out = options.value(for: "--out") else {
                throw CLIError("Password-protected exports require `--out <path>` to avoid binary data in the terminal.")
            }
            try data.write(to: URL(fileURLWithPath: out), options: [.atomic])
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: URL(fileURLWithPath: out).path
            )
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
            throw CLIError("Missing contact input. Use `--code <contact-code>` or `--file <path> --password-file <path>`.")
        }
        guard let password = try contactPassword(from: options) else {
            throw CLIError("Password-protected contact files require `--password-file <path>` or `--password <password>`.")
        }
        var data = try readBoundedFile(
            at: URL(fileURLWithPath: file),
            maximumBytes: Self.maximumContactPackageBytes,
            label: "Contact package"
        )
        defer { data.secureWipe() }
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

    private func sendAttachment(options: ParsedOptions, voice: Bool) async throws {
        guard let selector = options.value(for: "--to") else {
            throw CLIError("Missing recipient. Use `--to <contact-name|fingerprint|uuid>`.")
        }
        var input = try attachmentInput(from: options, voice: voice)
        defer { input.data.secureWipe() }
        let client = try headlessClient(from: options)
        let sent: HeadlessSentAttachment
        if voice {
            sent = try await client.sendVoice(
                to: selector,
                data: input.data,
                fileName: input.fileName,
                mimeType: input.mimeType,
                chunkSize: input.chunkSize,
                ttlSeconds: input.ttlSeconds
            )
        } else {
            sent = try await client.sendAttachment(
                to: selector,
                data: input.data,
                fileName: input.fileName,
                mimeType: input.mimeType,
                chunkSize: input.chunkSize,
                ttlSeconds: input.ttlSeconds
            )
        }
        try writeJSON(sent)
    }

    private func createGroup(options: ParsedOptions) async throws {
        guard let title = options.value(for: "--title") else {
            throw CLIError("Missing group title. Use `--title <name>`.")
        }
        let members = memberSelectors(from: options)
        guard !members.isEmpty else {
            throw CLIError("Missing members. Use `--members <contact-a,contact-b>`.")
        }
        let group = try await headlessClient(from: options).createGroup(title: title, memberSelectors: members)
        try writeJSON(group)
    }

    private func listGroups(options: ParsedOptions) async throws {
        let refresh = try options.boolValue(for: "--refresh") ?? true
        let limit = try options.intValue(for: "--limit") ?? 100
        let groups = try await headlessClient(from: options).groups(refreshFromRelay: refresh, limit: limit)
        try writeJSON(groups)
    }

    private func sendGroupText(options: ParsedOptions) async throws {
        guard let selector = options.value(for: "--group") else {
            throw CLIError("Missing group. Use `--group <title|uuid>`.")
        }
        guard let text = options.value(for: "--text") else {
            throw CLIError("Missing message text. Use `--text <message>`.")
        }
        let sent = try await headlessClient(from: options).sendGroupText(to: selector, text: text)
        try writeJSON(sent)
    }

    private func sendGroupAttachment(options: ParsedOptions, voice: Bool) async throws {
        guard let selector = options.value(for: "--group") else {
            throw CLIError("Missing group. Use `--group <title|uuid>`.")
        }
        var input = try attachmentInput(from: options, voice: voice)
        defer { input.data.secureWipe() }
        let client = try headlessClient(from: options)
        let sent: HeadlessSentAttachment
        if voice {
            sent = try await client.sendGroupVoice(
                to: selector,
                data: input.data,
                fileName: input.fileName,
                mimeType: input.mimeType,
                chunkSize: input.chunkSize,
                ttlSeconds: input.ttlSeconds
            )
        } else {
            sent = try await client.sendGroupAttachment(
                to: selector,
                data: input.data,
                fileName: input.fileName,
                mimeType: input.mimeType,
                chunkSize: input.chunkSize,
                ttlSeconds: input.ttlSeconds
            )
        }
        try writeJSON(sent)
    }

    private func receiveGroupMessages(options: ParsedOptions) async throws {
        let maxCount = try options.intValue(for: "--max") ?? 25
        let longPoll = try options.intValue(for: "--long-poll")
        let acknowledge = !(try options.boolValue(for: "--no-ack") ?? false)
        let messages = try await headlessClient(from: options).receiveGroupMessages(
            group: options.value(for: "--group"),
            maxCount: maxCount,
            longPollTimeoutSeconds: longPoll,
            acknowledge: acknowledge
        )
        try writeJSON(messages)
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

    private func downloadAttachment(options: ParsedOptions) async throws {
        guard let rawId = options.value(for: "--id"),
              let attachmentId = UUID(uuidString: rawId) else {
            throw CLIError("Missing or invalid attachment id. Use `--id <uuid>`.")
        }
        guard let out = options.value(for: "--out") else {
            throw CLIError("Missing output path. Use `--out <path-or-directory>`.")
        }
        let fetched = try await headlessClient(from: options).fetchAttachment(id: attachmentId)
        guard fetched.descriptor.isStructurallyValid() else {
            throw CLIError("Attachment metadata is malformed or exceeds transport limits.")
        }
        let outputURL = try resolvedAttachmentOutputURL(
            rawPath: out,
            descriptor: fetched.descriptor,
            attachmentId: attachmentId
        )
        try FileManager.default.createDirectory(
            at: outputURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        if FileManager.default.fileExists(atPath: outputURL.path),
           !(try options.boolValue(for: "--overwrite") ?? false) {
            throw CLIError("Output file already exists. Use `--overwrite true` to replace it.")
        }
        var outputData = fetched.data
        defer { outputData.secureWipe() }
        try outputData.write(to: outputURL, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outputURL.path)
        try writeJSON(
            CLIDownloadedAttachment(
                attachmentId: attachmentId,
                outputPath: outputURL.path,
                byteCount: outputData.count,
                sha256Base64: AttachmentCrypto.sha256(outputData).base64EncodedString(),
                descriptor: fetched.descriptor
            )
        )
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

    private func purgeContinuityAudit(options: ParsedOptions) async throws {
        try requireConfirmation(options, key: "--confirm", expected: "PURGE")
        let result = try await headlessClient(from: options).purgeContinuityAudit()
        try writeJSON(result)
    }

    private func send(_ request: RelayRequest, options: ParsedOptions) async throws {
        let endpoint = try endpoint(from: options)
        let authToken = try relayAuthToken(from: options)
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
            data = try readBoundedStandardInput(maximumBytes: Self.maximumRawRequestBytes)
        } else if raw.hasPrefix("@") {
            let path = String(raw.dropFirst())
            guard !path.isEmpty else {
                throw CLIError("Request file path is empty.")
            }
            data = try readBoundedFile(
                at: URL(fileURLWithPath: path),
                maximumBytes: Self.maximumRawRequestBytes,
                label: "Relay request"
            )
        } else {
            data = Data(raw.utf8)
        }
        guard data.count <= Self.maximumRawRequestBytes else {
            throw CLIError("Relay request exceeds the 512 KB limit.")
        }
        return try NoctweaveCoder.decode(RelayRequest.self, from: data)
    }

    private func headlessClient(from options: ParsedOptions) throws -> HeadlessMessagingClient {
        let stateURL = stateURL(from: options)
        let encrypted = try options.boolValue(for: "--encrypted-state") ?? true
        let stateKey = try stateEncryptionKey(
            from: options,
            stateURL: stateURL,
            encrypted: encrypted
        )
        return HeadlessMessagingClient(
            stateURL: stateURL,
            useEncryptedStore: encrypted,
            stateEncryptionKey: stateKey,
            authToken: try relayAuthToken(from: options),
            timeout: try options.doubleValue(for: "--timeout") ?? RelayClient.defaultTimeout
        )
    }

    private func stateEncryptionKey(
        from options: ParsedOptions,
        stateURL: URL,
        encrypted: Bool
    ) throws -> SymmetricKey? {
        guard encrypted else { return nil }
        let configuredPath = (
            options.value(for: "--state-key-file")
                ?? ProcessInfo.processInfo.environment["NOCTYRA_CLI_STATE_KEY_FILE"]
        ).flatMap { $0.isEmpty ? nil : $0 }
        #if os(Linux)
        let keyURL = configuredPath.map(URL.init(fileURLWithPath:)) ?? defaultStateKeyURL(for: stateURL)
        return try loadOrCreateStateKey(
            at: keyURL,
            allowCreate: arguments.first == "init"
        )
        #else
        guard let configuredPath, !configuredPath.isEmpty else {
            return nil
        }
        return try loadOrCreateStateKey(
            at: URL(fileURLWithPath: configuredPath),
            allowCreate: arguments.first == "init"
        )
        #endif
    }

    private func defaultStateKeyURL(for stateURL: URL) -> URL {
        stateURL.deletingPathExtension().appendingPathExtension("key")
    }

    private func loadOrCreateStateKey(at keyURL: URL, allowCreate: Bool) throws -> SymmetricKey {
        let fileManager = FileManager.default
        if fileManager.fileExists(atPath: keyURL.path) {
            let attributes = try fileManager.attributesOfItem(atPath: keyURL.path)
            if let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue,
               mode & 0o077 != 0 {
                throw CLIError("State key file must not be readable by group or other users (chmod 600).")
            }
            var encoded = try readBoundedFile(at: keyURL, maximumBytes: 256, label: "State key file")
            defer { encoded.secureWipe() }
            var keyData: Data
            if encoded.count == 32 {
                keyData = encoded
            } else {
                guard let text = String(data: encoded, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                      let decoded = Data(base64Encoded: text),
                      decoded.count == 32,
                      decoded.base64EncodedString() == text else {
                    throw CLIError("State key file must contain exactly 32 raw bytes or canonical base64 for 32 bytes.")
                }
                keyData = decoded
            }
            defer { keyData.secureWipe() }
            return SymmetricKey(data: keyData)
        }
        guard allowCreate else {
            throw CLIError("Encrypted state key is missing. Restore the key file or run `init` with a new state path.")
        }
        let directory = keyURL.deletingLastPathComponent()
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        let key = SymmetricKey(size: .bits256)
        var keyData = key.withUnsafeBytes { Data($0) }
        defer { keyData.secureWipe() }
        var encoded = Data((keyData.base64EncodedString() + "\n").utf8)
        defer { encoded.secureWipe() }
        try encoded.write(to: keyURL, options: [.atomic])
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)
        return key
    }

    private func contactPassword(from options: ParsedOptions) throws -> String? {
        if let path = options.value(for: "--password-file") {
            return try readSecret(at: URL(fileURLWithPath: path), label: "Contact password")
        }
        if let password = ProcessInfo.processInfo.environment["NOCTYRA_CONTACT_PASSWORD"], !password.isEmpty {
            return password
        }
        return options.value(for: "--password")
    }

    private func relayAuthToken(from options: ParsedOptions) throws -> String? {
        if let path = options.value(for: "--auth-file") {
            return try readSecret(at: URL(fileURLWithPath: path), label: "Relay auth token")
        }
        if let token = ProcessInfo.processInfo.environment["NOCTYRA_RELAY_AUTH_TOKEN"], !token.isEmpty {
            return token
        }
        return options.value(for: "--auth")
    }

    private func readSecret(at url: URL, label: String) throws -> String {
        var data = try readBoundedFile(at: url, maximumBytes: 4_096, label: label)
        defer { data.secureWipe() }
        guard let value = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .newlines),
              !value.isEmpty,
              !value.unicodeScalars.contains(where: { $0.value == 0 }) else {
            throw CLIError("\(label) file is empty or malformed.")
        }
        return value
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

    private func memberSelectors(from options: ParsedOptions) -> [String] {
        (options.value(for: "--members") ?? options.value(for: "--member") ?? "")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    private func attachmentInput(from options: ParsedOptions, voice: Bool) throws -> CLIAttachmentInput {
        guard let file = options.value(for: "--file") else {
            throw CLIError("Missing file. Use `--file <path>`.")
        }
        let fileURL = URL(fileURLWithPath: file)
        let data = try readBoundedFile(
            at: fileURL,
            maximumBytes: Self.maximumAttachmentBytes,
            label: "Attachment"
        )
        let mimeType = options.value(for: "--mime") ?? defaultMIMEType(for: fileURL, voice: voice)
        let chunkSize = try options.intValue(for: "--chunk-size") ?? 64 * 1024
        let ttlSeconds = try options.intValue(for: "--ttl")
        return CLIAttachmentInput(
            data: data,
            fileName: nil,
            mimeType: mimeType,
            chunkSize: chunkSize,
            ttlSeconds: ttlSeconds
        )
    }

    private func resolvedAttachmentOutputURL(
        rawPath: String,
        descriptor: AttachmentDescriptor,
        attachmentId: UUID
    ) throws -> URL {
        let url = URL(fileURLWithPath: rawPath)
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory),
           isDirectory.boolValue {
            return url.appendingPathComponent("\(attachmentId.uuidString).bin", isDirectory: false)
        }
        return url
    }

    private func readBoundedFile(at url: URL, maximumBytes: Int, label: String) throws -> Data {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              let size = attributes[.size] as? NSNumber,
              size.intValue >= 0,
              size.intValue <= maximumBytes else {
            throw CLIError("\(label) exceeds the \(maximumBytes) byte limit.")
        }
        let data = try Data(contentsOf: url, options: [.uncached])
        guard data.count <= maximumBytes else {
            throw CLIError("\(label) exceeds the \(maximumBytes) byte limit.")
        }
        return data
    }

    private func readBoundedStandardInput(maximumBytes: Int) throws -> Data {
        var data = Data()
        while true {
            let remaining = maximumBytes + 1 - data.count
            if remaining <= 0 {
                throw CLIError("Relay request exceeds the 512 KB limit.")
            }
            guard let chunk = try FileHandle.standardInput.read(upToCount: min(64 * 1024, remaining)),
                  !chunk.isEmpty else {
                return data
            }
            data.append(chunk)
        }
    }

    private func defaultMIMEType(for url: URL, voice: Bool) -> String {
        if voice {
            return "audio/m4a"
        }
        switch url.pathExtension.lowercased() {
        case "jpg", "jpeg":
            return "image/jpeg"
        case "png":
            return "image/png"
        case "gif":
            return "image/gif"
        case "webp":
            return "image/webp"
        case "m4a":
            return "audio/m4a"
        case "mp3":
            return "audio/mpeg"
        case "wav":
            return "audio/wav"
        case "txt":
            return "text/plain"
        case "json":
            return "application/json"
        case "pdf":
            return "application/pdf"
        default:
            return "application/octet-stream"
        }
    }

    private func printHelp() {
        FileHandle.standardOutput.writeLine("""
        NoctyraCLI

        Usage:
          NoctyraCLI init --display-name <name> --relay <url|host:port> [--state path]
          NoctyraCLI register [--state path] [--auth-file path]
          NoctyraCLI status [--state path]
          NoctyraCLI export-contact [--state path]
          NoctyraCLI export-contact --password-file <path> --out contact.noctweave [--state path]
          NoctyraCLI import-contact --code <contact-code> [--state path]
          NoctyraCLI import-contact --file contact.noctweave --password-file <path> [--state path]
          NoctyraCLI contacts [--state path]
          NoctyraCLI group-create --title <name> --members <contact-a,contact-b> [--state path]
          NoctyraCLI groups [--refresh true] [--limit count] [--state path]
          NoctyraCLI group-send --group <title|uuid> --text <message> [--state path]
          NoctyraCLI group-send-attachment --group <title|uuid> --file <path> [--mime type] [--ttl seconds] [--state path]
          NoctyraCLI group-send-voice --group <title|uuid> --file <path> [--mime audio/m4a] [--ttl seconds] [--state path]
          NoctyraCLI group-receive [--group <title|uuid>] [--max count] [--long-poll seconds] [--state path]
          NoctyraCLI continuity-audit [--state path]
          NoctyraCLI purge-continuity-audit --confirm PURGE [--state path]
          NoctyraCLI send --to <contact-name|fingerprint|uuid> --text <message> [--state path]
          NoctyraCLI send-attachment --to <contact> --file <path> [--mime type] [--ttl seconds] [--state path]
          NoctyraCLI send-voice --to <contact> --file <path> [--mime audio/m4a] [--ttl seconds] [--state path]
          NoctyraCLI receive [--max count] [--long-poll seconds] [--state path]
          NoctyraCLI download-attachment --id <uuid> --out <path-or-directory> [--overwrite true] [--state path]
          NoctyraCLI allow-identity-reset --contact <contact> --allow true [--state path]
          NoctyraCLI rotate-identity --confirm ROTATE [--state path]
          NoctyraCLI burn-identity --confirm BURN [--state path]
          NoctyraCLI endpoint --relay <url|host:port>
          NoctyraCLI health --relay <url|host:port> [--auth-file path] [--timeout seconds]
          NoctyraCLI info --relay <url|host:port> [--auth-file path] [--timeout seconds]
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
          State is encrypted by default. Apple platforms use Keychain; Linux uses a 0600 key file.
          Override the Linux key path with --state-key-file or NOCTYRA_CLI_STATE_KEY_FILE.
          Use --encrypted-state false only for explicitly accepted plaintext development state.

        Secret input:
          Prefer --password-file and --auth-file so secrets do not appear in process arguments.
          NOCTYRA_CONTACT_PASSWORD and NOCTYRA_RELAY_AUTH_TOKEN are also supported.
        """)
    }
}

private struct CLIAttachmentInput {
    var data: Data
    let fileName: String?
    let mimeType: String
    let chunkSize: Int
    let ttlSeconds: Int?
}

private struct CLIDownloadedAttachment: Codable {
    let attachmentId: UUID
    let outputPath: String
    let byteCount: Int
    let sha256Base64: String
    let descriptor: AttachmentDescriptor
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
        guard let parsed = Double(value), parsed.isFinite, parsed > 0 else {
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

private extension Data {
    mutating func secureWipe() {
        guard !isEmpty else { return }
        let byteCount = count
        withUnsafeMutableBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            #if os(Linux)
            _ = memset(baseAddress, 0, byteCount)
            #else
            _ = memset_s(baseAddress, byteCount, 0, byteCount)
            #endif
        }
        removeAll(keepingCapacity: false)
    }
}
