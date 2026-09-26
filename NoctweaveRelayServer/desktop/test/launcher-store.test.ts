import { expect, test } from "bun:test";
import { mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LauncherStore } from "../bun/launcher-store.js";

const key = Buffer.alloc(32, 0x5a);
const anotherKey = Buffer.alloc(32, 0xa5);
const keyProvider = async () => Buffer.from(key);

test("launcher stores all credentials and settings inside an encrypted record", async () => {
  const directory = await mkdtemp(join(tmpdir(), "noctweave-relay-launcher-"));
  try {
    const fileURL = join(directory, "launcher.json");
    const store = new LauncherStore(fileURL, keyProvider);
    const initial = await store.load();
    const updated = {
      ...initial,
      settings: { ...initial.settings, relayName: "unique-relay-name-canary" }
    };
    await store.save(updated);
    const disk = await readFile(fileURL);
    expect(disk.subarray(0, 5).toString("ascii")).toBe("NWRL1");
    expect(disk.includes(Buffer.from(updated.adminToken))).toBe(false);
    expect(disk.includes(Buffer.from(updated.publisherPassword))).toBe(false);
    expect(disk.includes(Buffer.from("unique-relay-name-canary"))).toBe(false);
    expect((await stat(fileURL)).mode & 0o777).toBe(0o600);

    const restarted = await new LauncherStore(fileURL, keyProvider).load();
    expect(restarted).toEqual(updated);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("wrong key and altered ciphertext fail without replacing the store", async () => {
  const directory = await mkdtemp(join(tmpdir(), "noctweave-relay-launcher-"));
  try {
    const fileURL = join(directory, "launcher.json");
    await new LauncherStore(fileURL, keyProvider).load();
    const original = await readFile(fileURL);
    await expect(new LauncherStore(fileURL, async () => Buffer.from(anotherKey)).load())
      .rejects.toThrow("could not be decrypted");
    expect(await readFile(fileURL)).toEqual(original);

    const altered = Buffer.from(original);
    altered[altered.length - 1] ^= 1;
    await writeFile(fileURL, altered);
    await expect(new LauncherStore(fileURL, keyProvider).load())
      .rejects.toThrow("could not be decrypted");
    expect(await readFile(fileURL)).toEqual(altered);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("legacy plaintext state is rejected and preserved", async () => {
  const directory = await mkdtemp(join(tmpdir(), "noctweave-relay-launcher-"));
  try {
    const fileURL = join(directory, "launcher.json");
    const legacy = Buffer.from(` \n${JSON.stringify({ version: 2, adminToken: "a".repeat(64) })}`);
    await writeFile(fileURL, legacy);
    await expect(new LauncherStore(fileURL, keyProvider).load())
      .rejects.toThrow("Legacy plaintext launcher state");
    expect(await readFile(fileURL)).toEqual(legacy);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a stale launcher cannot overwrite a newer encrypted state", async () => {
  const directory = await mkdtemp(join(tmpdir(), "noctweave-relay-launcher-"));
  try {
    const fileURL = join(directory, "launcher.json");
    const first = new LauncherStore(fileURL, keyProvider);
    const original = await first.load();
    const second = new LauncherStore(fileURL, keyProvider);
    await second.load();
    await first.save({ ...original, settings: { ...original.settings, relayName: "new name" } });
    const disk = await readFile(fileURL);
    await expect(second.save(original)).rejects.toThrow("changed in another process");
    expect(await readFile(fileURL)).toEqual(disk);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("missing key, symlink, and oversized state fail closed", async () => {
  const directory = await mkdtemp(join(tmpdir(), "noctweave-relay-launcher-"));
  try {
    const fileURL = join(directory, "launcher.json");
    await expect(new LauncherStore(fileURL, async () => { throw new Error("Keychain unavailable"); }).load())
      .rejects.toThrow("Keychain unavailable");
    await expect(stat(fileURL)).rejects.toThrow();

    await new LauncherStore(fileURL, keyProvider).load();
    const alias = join(directory, "alias.json");
    await symlink(fileURL, alias);
    await expect(new LauncherStore(alias, keyProvider).load()).rejects.toThrow();
    await writeFile(fileURL, " ".repeat(65_570));
    await expect(new LauncherStore(fileURL, keyProvider).load()).rejects.toThrow();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
