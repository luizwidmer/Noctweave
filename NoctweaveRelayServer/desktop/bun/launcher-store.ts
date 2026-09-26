import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, rename, rmdir, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import { defaultSettings, validateSettings } from "./docker-relay.js";
import type { LauncherKeyProvider } from "./launcher-key.js";
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
const magic = Buffer.from("NWRL1", "ascii");
const nonceBytes = 12;
const tagBytes = 16;
const maximumEnvelopeBytes = maximumStateBytes + magic.length + nonceBytes + tagBytes;
const associatedData = Buffer.from("noctweave-relay-desktop-launcher-state-v1", "utf8");

export class LauncherStore {
  private lastCipherDigest: string | null = null;

  constructor(
    private readonly fileURL = launcherStatePath(),
    private readonly keyProvider: LauncherKeyProvider = async () => {
      throw new Error("A launcher encryption key provider is required.");
    }
  ) {}

  async load(): Promise<StoredLauncherState> {
    await this.prepareDirectory();
    let bytes: Buffer;
    try {
      bytes = await this.readState();
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

    let key: Buffer | undefined;
    let plaintext: Buffer | undefined;
    try {
      requireCurrentEnvelope(bytes);
      key = await this.keyProvider();
      requireKey(key);
      plaintext = decryptState(bytes, key);
      const decoded = JSON.parse(plaintext.toString("utf8")) as DecodedLauncherState;
      if (decoded.version !== 3 || !decoded.adminToken || !isToken(decoded.adminToken)
          || !decoded.publisherPassword || !isToken(decoded.publisherPassword)
          || !decoded.settings) {
        throw new Error("Decrypted launcher state is invalid.");
      }
      const state: StoredLauncherState = {
        version: 3,
        adminToken: decoded.adminToken,
        publisherPassword: decoded.publisherPassword,
        settings: validateSettings(decoded.settings)
      };
      this.lastCipherDigest = digest(bytes);
      return state;
    } finally {
      plaintext?.fill(0);
      key?.fill(0);
      bytes.fill(0);
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
    const plaintext = Buffer.from(JSON.stringify(validated), "utf8");
    if (plaintext.byteLength > maximumStateBytes) {
      plaintext.fill(0);
      throw new Error("Launcher state exceeds its size limit.");
    }

    await this.prepareDirectory();
    const lockURL = `${this.fileURL}.lock`;
    let lockHeld = false;
    let currentBytes: Buffer | undefined;
    let key: Buffer | undefined;
    let envelope: Buffer | undefined;
    let temporary: string | undefined;
    try {
      try {
        await mkdir(lockURL, { mode: 0o700 });
        lockHeld = true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") {
          throw new Error("Another launcher write is active, or a previous write was interrupted.");
        }
        throw error;
      }
      try {
        currentBytes = await this.readState();
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      if (currentBytes) requireCurrentEnvelope(currentBytes);
      if ((currentBytes ? digest(currentBytes) : null) !== this.lastCipherDigest) {
        throw new Error("Launcher state changed in another process; reload before saving.");
      }

      key = await this.keyProvider();
      requireKey(key);
      envelope = encryptState(plaintext, key);
      temporary = `${this.fileURL}.${randomUUID()}.tmp`;
      const handle = await open(temporary, "wx", 0o600);
      try {
        await handle.writeFile(envelope);
        await handle.sync();
      } finally {
        await handle.close();
      }
      await rename(temporary, this.fileURL);
      temporary = undefined;
      this.lastCipherDigest = digest(envelope);
    } finally {
      plaintext.fill(0);
      key?.fill(0);
      currentBytes?.fill(0);
      envelope?.fill(0);
      if (temporary) await unlink(temporary).catch((error: NodeJS.ErrnoException) => {
        if (error.code !== "ENOENT") throw error;
      });
      if (lockHeld) await rmdir(lockURL);
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

  private async readState(): Promise<Buffer> {
    // lstat also rejects symlinks on platforms without O_NOFOLLOW.
    if (!(await lstat(this.fileURL)).isFile()) throw new Error("Launcher state must be a regular file.");
    const handle = await open(this.fileURL,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    const bytes = Buffer.alloc(maximumEnvelopeBytes + 1);
    try {
      const status = await handle.stat();
      if (!status.isFile() || status.nlink !== 1 || status.size > maximumEnvelopeBytes
          || (process.getuid && status.uid !== process.getuid())) {
        throw new Error("Launcher state is unsafe or exceeds its size limit.");
      }
      await handle.chmod(0o600);
      let count = 0;
      while (count < bytes.length) {
        const { bytesRead } = await handle.read(bytes, count, bytes.length - count, null);
        if (bytesRead === 0) break;
        count += bytesRead;
      }
      if (count > maximumEnvelopeBytes) throw new Error("Launcher state exceeds its size limit.");
      return Buffer.from(bytes.subarray(0, count));
    } finally {
      bytes.fill(0);
      await handle.close();
    }
  }
}

function requireCurrentEnvelope(bytes: Buffer): void {
  if (bytes.subarray(0, magic.length).equals(magic)
      && bytes.length > magic.length + nonceBytes + tagBytes) return;
  if (bytes.subarray(0, 64).toString("utf8").trimStart().startsWith("{")) {
    throw new Error("Legacy plaintext launcher state was found. Preserve it and reset the unreleased launcher before continuing.");
  }
  throw new Error("Launcher state has an unsupported or damaged encrypted format.");
}

function requireKey(key: Buffer): void {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new Error("The launcher encryption key must be exactly 32 bytes.");
  }
}

function encryptState(plaintext: Buffer, key: Buffer): Buffer {
  const nonce = randomBytes(nonceBytes);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(associatedData);
  const first = cipher.update(plaintext);
  const last = cipher.final();
  const tag = cipher.getAuthTag();
  try {
    return Buffer.concat([magic, nonce, tag, first, last]);
  } finally {
    first.fill(0);
    last.fill(0);
  }
}

function decryptState(envelope: Buffer, key: Buffer): Buffer {
  const nonce = envelope.subarray(magic.length, magic.length + nonceBytes);
  const tag = envelope.subarray(magic.length + nonceBytes, magic.length + nonceBytes + tagBytes);
  const ciphertext = envelope.subarray(magic.length + nonceBytes + tagBytes);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(associatedData);
  decipher.setAuthTag(tag);
  let first: Buffer | undefined;
  let last: Buffer | undefined;
  try {
    first = decipher.update(ciphertext);
    last = decipher.final();
    return Buffer.concat([first, last]);
  } catch {
    throw new Error("Launcher state could not be decrypted with the current device key.");
  } finally {
    first?.fill(0);
    last?.fill(0);
  }
}

function digest(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
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
