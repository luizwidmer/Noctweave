import { constants } from "node:fs";
import { statSync } from "node:fs";

export type LauncherKeyProvider = () => Promise<Buffer>;

/** The packaged macOS helper stores this random key in the device-only Keychain. */
export function launcherKeyProvider(helperPath: string): LauncherKeyProvider {
  if (process.platform === "darwin") {
    return async () => {
      const status = statSync(helperPath);
      if (!status.isFile() || (status.mode & constants.S_IXUSR) === 0) {
        throw new Error("The packaged launcher Keychain helper is unavailable.");
      }
      const result = Bun.spawnSync([helperPath], {
        stdin: "ignore",
        stdout: "pipe",
        stderr: "pipe",
        env: {
          HOME: process.env.HOME ?? "",
          PATH: "/usr/bin:/bin"
        }
      });
      if (result.exitCode !== 0 || result.stdout.byteLength !== 32) {
        throw new Error("The device-only launcher key could not be read from Keychain.");
      }
      const key = Buffer.from(result.stdout);
      result.stdout.fill(0);
      return key;
    };
  }

  // Non-macOS source builds have no Apple Keychain. Their operator supplies a
  // separate random key through a secret manager/environment at startup.
  const encoded = process.env.NOCTWEAVE_RELAY_DESKTOP_KEY_HEX;
  delete process.env.NOCTWEAVE_RELAY_DESKTOP_KEY_HEX;
  if (!encoded || !/^[a-fA-F0-9]{64}$/u.test(encoded)) {
    return async () => { throw new Error("Set a 32-byte NOCTWEAVE_RELAY_DESKTOP_KEY_HEX before starting the launcher."); };
  }
  const key = Buffer.from(encoded, "hex");
  if (key.every((byte) => byte === key[0])) {
    key.fill(0);
    return async () => { throw new Error("The supplied launcher key is too weak."); };
  }
  process.once("exit", () => key.fill(0));
  return async () => Buffer.from(key);
}
