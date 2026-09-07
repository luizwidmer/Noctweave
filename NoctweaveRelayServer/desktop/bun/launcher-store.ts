import { randomBytes, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, rename, unlink } from "node:fs/promises";
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

const maximumStateBytes = 64 * 1024;

export class LauncherStore {
  constructor(private readonly fileURL = launcherStatePath()) {}

  async load(): Promise<StoredLauncherState> {
    await this.prepareDirectory();
    try {
      const decoded = JSON.parse(await this.readState()) as DecodedLauncherState;
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
    const bytes = Buffer.from(`${JSON.stringify(validated, null, 2)}\n`, "utf8");
    if (bytes.byteLength > maximumStateBytes) throw new Error("Launcher state exceeds its size limit.");
    await this.prepareDirectory();
    const temporary = `${this.fileURL}.${randomUUID()}.tmp`;
    // Exclusive creation must happen before writing any credential bytes.
    const handle = await open(temporary, "wx", 0o600);
    try {
      await handle.writeFile(bytes);
      await handle.sync();
      await handle.close();
      await rename(temporary, this.fileURL);
    } finally {
      await handle.close();
      await unlink(temporary).catch((error: NodeJS.ErrnoException) => {
        if (error.code !== "ENOENT") throw error;
      });
    }
  }

  private async prepareDirectory(): Promise<void> {
    const directory = dirname(this.fileURL);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const status = await lstat(directory);
    if (!status.isDirectory() || (process.getuid && status.uid !== process.getuid())) {
      throw new Error("Launcher state requires a private directory owned by the current user.");
    }
    await chmod(directory, 0o700);
  }

  private async readState(): Promise<string> {
    // lstat also rejects symlinks on platforms without O_NOFOLLOW.
    if (!(await lstat(this.fileURL)).isFile()) throw new Error("Launcher state must be a regular file.");
    const handle = await open(this.fileURL,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    try {
      const status = await handle.stat();
      if (!status.isFile() || status.nlink !== 1 || status.size > maximumStateBytes
          || (process.getuid && status.uid !== process.getuid())) {
        throw new Error("Launcher state is unsafe or exceeds its size limit.");
      }
      await handle.chmod(0o600);
      // Bound allocation even if another process grows the file after stat.
      const bytes = Buffer.alloc(maximumStateBytes + 1);
      let count = 0;
      while (count < bytes.length) {
        const { bytesRead } = await handle.read(bytes, count, bytes.length - count, null);
        if (bytesRead === 0) break;
        count += bytesRead;
      }
      if (count > maximumStateBytes) throw new Error("Launcher state exceeds its size limit.");
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, count));
    } finally {
      await handle.close();
    }
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
