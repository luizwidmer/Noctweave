import { randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import { defaultSettings, validateSettings } from "./docker-relay.js";
import type { RelayLauncherSettings } from "../rpc.js";

type StoredLauncherState = {
  version: 2;
  adminToken: string;
  settings: RelayLauncherSettings;
};

export class LauncherStore {
  constructor(private readonly fileURL = launcherStatePath()) {}

  async load(): Promise<StoredLauncherState> {
    try {
      const decoded = JSON.parse(await readFile(this.fileURL, "utf8")) as Partial<StoredLauncherState>;
      const adminToken = decoded.adminToken;
      if (decoded.version !== 2 || !adminToken || !/^[a-f0-9]{64}$/u.test(adminToken) || !decoded.settings) {
        throw new Error("invalid launcher state");
      }
      return {
        version: 2,
        adminToken,
        settings: validateSettings(decoded.settings)
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      const initial: StoredLauncherState = {
        version: 2,
        adminToken: randomBytes(32).toString("hex"),
        settings: defaultSettings
      };
      await this.save(initial);
      return initial;
    }
  }

  async save(state: StoredLauncherState): Promise<void> {
    const validated: StoredLauncherState = {
      version: 2,
      adminToken: state.adminToken,
      settings: validateSettings(state.settings)
    };
    if (!/^[a-f0-9]{64}$/u.test(validated.adminToken)) {
      throw new Error("Refusing to persist an invalid operator token.");
    }
    await mkdir(dirname(this.fileURL), { recursive: true, mode: 0o700 });
    const temporary = `${this.fileURL}.${process.pid}.tmp`;
    await writeFile(temporary, `${JSON.stringify(validated, null, 2)}\n`, { mode: 0o600 });
    await chmod(temporary, 0o600);
    await rename(temporary, this.fileURL);
  }
}

function launcherStatePath(): string {
  if (process.platform === "darwin") {
    return join(homedir(), "Library", "Application Support", "Noctweave Relay", "launcher.json");
  }
  if (process.platform === "win32") {
    const appData = process.env.APPDATA ?? join(homedir(), "AppData", "Roaming");
    return join(appData, "Noctweave Relay", "launcher.json");
  }
  return join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "noctweave-relay", "launcher.json");
}
