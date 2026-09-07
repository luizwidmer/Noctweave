import { expect, test } from "bun:test";
import { mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LauncherStore } from "../bun/launcher-store.js";

test("saving credentials cannot overwrite a pre-existing temporary symlink", async () => {
  const directory = await mkdtemp(join(tmpdir(), "noctweave-relay-launcher-"));
  try {
    const fileURL = join(directory, "launcher.json");
    const store = new LauncherStore(fileURL);
    const state = await store.load();
    const victim = join(directory, "unrelated.txt");
    await writeFile(victim, "preserve this file");
    await symlink(victim, `${fileURL}.${process.pid}.tmp`);
    await store.save(state);
    expect(await readFile(victim, "utf8")).toBe("preserve this file");
    expect((await stat(fileURL)).mode & 0o777).toBe(0o600);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("loading credentials rejects symlinks and oversized state", async () => {
  const directory = await mkdtemp(join(tmpdir(), "noctweave-relay-launcher-"));
  try {
    const source = join(directory, "source.json");
    await new LauncherStore(source).load();
    const alias = join(directory, "alias.json");
    await symlink(source, alias);
    await expect(new LauncherStore(alias).load()).rejects.toThrow();
    await writeFile(source, " ".repeat(65_537));
    await expect(new LauncherStore(source).load()).rejects.toThrow();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("launcher state migrates v2 without losing settings", async () => {
  const directory = await mkdtemp(join(tmpdir(), "noctweave-relay-launcher-"));
  const fileURL = join(directory, "launcher.json");
  const adminToken = "a".repeat(64);
  try {
    await writeFile(fileURL, JSON.stringify({
      version: 2,
      adminToken,
      settings: {
        relayName: "Migrated Relay",
        exposure: "local",
        tcpPort: 9439,
        httpPort: 9440,
        adminPort: 9190,
        rendezvousTransportEnabled: true,
        trustedReverseProxyTLS: false
      }
    }));

    const state = await new LauncherStore(fileURL).load();
    expect(state.version).toBe(3);
    expect(state.adminToken).toBe(adminToken);
    expect(state.publisherPassword).toMatch(/^[a-f0-9]{64}$/);
    expect(state.settings.relayName).toBe("Migrated Relay");
    expect(state.settings.noctwebHostingEnabled).toBe(true);

    const persisted = JSON.parse(await readFile(fileURL, "utf8"));
    expect(persisted.version).toBe(3);
    expect(persisted.publisherPassword).toBe(state.publisherPassword);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
