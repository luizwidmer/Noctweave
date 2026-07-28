import { expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LauncherStore } from "../bun/launcher-store.js";

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
