import { randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import { defaultSettings, validateSettings } from "./docker-relay.js";
import type { RelayLauncherSettings } from "../rpc.js";

type StoredLauncherState = {
  version: 3;
  adminToken: string;
  publisherPassword: string;
  settings: RelayLauncherSettings;
};

type DecodedLauncherState = {
  version?: number;
  adminToken?: string;
  publisherPassword?: string;
  settings?: RelayLauncherSettings;
};

export class LauncherStore {
  constructor(private readonly fileURL = launcherStatePath()) {}

  async load(): Promise<StoredLauncherState> {
    try {
      const decoded = JSON.parse(await readFile(this.fileURL, "utf8")) as DecodedLauncherState;
      const adminToken = decoded.adminToken;
      if (!adminToken || !isToken(adminToken) || !decoded.settings) {
        throw new Error("invalid launcher state");
      }
      const settings = validateSettings(decoded.settings);
      if (decoded.version === 3 && decoded.publisherPassword && isToken(decoded.publisherPassword)) {
        return {
          version: 3,
          adminToken,
          publisherPassword: decoded.publisherPassword,
          settings
        };
      }
      if (decoded.version === 2) {
        const migrated: StoredLauncherState = {
          version: 3,
          adminToken,
          publisherPassword: randomToken(),
          settings
        };
        await this.save(migrated);
        return migrated;
      }
      throw new Error("invalid launcher state");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      const initial: StoredLauncherState = {
        version: 3,
        adminToken: randomToken(),
        publisherPassword: randomToken(),
        settings: defaultSettings
      };
      await this.save(initial);
      return initial;
    }
  }

  async save(state: StoredLauncherState): Promise<void> {
    const validated: StoredLauncherState = {
      version: 3,
      adminToken: state.adminToken,
      publisherPassword: state.publisherPassword,
      settings: validateSettings(state.settings)
    };
    if (!isToken(validated.adminToken) || !isToken(validated.publisherPassword)) {
      throw new Error("Refusing to persist invalid relay credentials.");
    }
    await mkdir(dirname(this.fileURL), { recursive: true, mode: 0o700 });
    const temporary = `${this.fileURL}.${process.pid}.tmp`;
    await writeFile(temporary, `${JSON.stringify(validated, null, 2)}\n`, { mode: 0o600 });
    await chmod(temporary, 0o600);
    await rename(temporary, this.fileURL);
  }
}

function randomToken(): string {
  return randomBytes(32).toString("hex");
}

function isToken(value: string): boolean {
  return /^[a-f0-9]{64}$/u.test(value);
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
