// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import Darwin
import NoctweaveSecurityKeys

/// One bounded request over inherited pipes. PINs and PRF output never use arguments or files.
@main
struct SecurityKeyBridge {
    static func main() async {
        do {
            var input = Data()
            while let chunk = try FileHandle.standardInput.read(upToCount: 4_096), !chunk.isEmpty {
                input.append(chunk)
                guard input.count <= 65_536 else { throw SecurityKeyError.invalidResponse }
            }
            guard !input.isEmpty,
                  let request = try JSONSerialization.jsonObject(with: input) as? [String: Any],
                  Set(request.keys).isSubset(of: ["operation", "options", "pin"]),
                  let operation = request["operation"] as? String else { throw SecurityKeyError.invalidResponse }
            if operation == "capabilities" {
                write(["available": true, "rpID": SecurityKeyApplication.noctweaveJS.relyingPartyID,
                       "origin": SecurityKeyApplication.noctweaveJS.origin,
                       "continuousPresence": SecurityKeyPresence.isSupported])
                return
            }
            guard let options = request["options"] as? [String: Any],
                   request["pin"] == nil || request["pin"] is String else { throw SecurityKeyError.invalidResponse }
            if operation == "watch-attached" {
                guard options.isEmpty, request["pin"] == nil else { throw SecurityKeyError.invalidResponse }
                let parent = getppid()
                while getppid() == parent {
                    write(["devices": await SecurityKeyPresence.attachedDeviceTokens()])
                    try await Task.sleep(for: .milliseconds(500))
                }
                return
            }
            if operation == "watch-presence" {
                guard request["pin"] == nil, Set(options.keys) == ["registryEntryID"],
                      let text = options["registryEntryID"] as? String, let identity = UInt64(text),
                      identity != 0, String(identity) == text else { throw SecurityKeyError.invalidResponse }
                let presence = SecurityKeyPresence(registryEntryID: identity)
                let parent = getppid()
                while presence.isConnected && getppid() == parent {
                    write(["present": true])
                    try await Task.sleep(for: .milliseconds(250))
                }
                write(["present": false])
                return
            }
            let pin = request["pin"] as? String ?? ""
            guard pin.utf8.count <= 63 else { throw SecurityKeyError.invalidResponse }
            let hardware = HardwareSecurityKey()
            let result = try await hardware.desktopRequest(
                operation: operation, optionsJSON: JSONSerialization.data(withJSONObject: options), pin: pin
            )
            let credential = try JSONSerialization.jsonObject(with: result)
            var response: [String: Any] = ["credential": credential]
            if operation == "get", let presence = await hardware.verifiedPresence(), presence.isConnected {
                response["presenceToken"] = String(presence.registryEntryID)
            }
            write(response)
        } catch {
            let code = (error as? SecurityKeyError) ?? .verificationFailed
            write(["error": code.rawValue, "message": code.localizedDescription])
        }
    }

    private static func write(_ object: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else { return }
        FileHandle.standardOutput.write(data + Data([10]))
    }
}
