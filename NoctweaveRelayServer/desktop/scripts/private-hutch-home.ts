import { lstatSync, mkdirSync } from "node:fs";
import { isAbsolute, join } from "node:path";

const MINIMUM_BUN_VERSION = [1, 4, 4] as const;

export function requirePatchedBun(version: string | undefined = process.versions.bun): void {
  const match = version?.match(/^(\d+)\.(\d+)\.(\d+)(?:\+[0-9A-Za-z.-]+)?$/);
  if (!match) throw new Error("Bun 1.4.4 or newer is required for desktop tooling.");
  for (let index = 0; index < MINIMUM_BUN_VERSION.length; index++) {
    const part = Number(match[index + 1]);
    if (!Number.isSafeInteger(part) || part < MINIMUM_BUN_VERSION[index]!) {
      throw new Error("Bun 1.4.4 or newer is required for desktop tooling.");
    }
    if (part > MINIMUM_BUN_VERSION[index]!) return;
  }
}

function requirePrivateDirectory(path: string): void {
  mkdirSync(path, { mode: 0o700, recursive: true });
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`Hutch cache path must be a real directory: ${path}`);
  }
  if (process.platform !== "win32"
      && (stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0)) {
    throw new Error(`Hutch cache directory must be owned by this user and mode 0700: ${path}`);
  }
}

// Hutch can execute a cached Bun before checking its hash. Pass a complete,
// sanitized child environment so explicit binary overrides cannot bypass the
// private cache. Windows uses its per-user application-data directory.
export function privateHutchEnvironment(root: string, inherited = process.env,
  bunVersion = process.versions.bun): NodeJS.ProcessEnv {
  requirePatchedBun(bunVersion);
  let parent: string;
  if (process.platform === "win32") {
    const localAppData = inherited.LOCALAPPDATA;
    if (!localAppData || !isAbsolute(localAppData)) {
      throw new Error("An absolute per-user LOCALAPPDATA path is required for the desktop Hutch cache.");
    }
    requirePrivateDirectory(localAppData);
    parent = join(localAppData, "NoctweaveRelayServer");
  } else {
    parent = join(root, ".local");
  }
  requirePrivateDirectory(parent);
  const home = join(parent, "hutch-store");
  requirePrivateDirectory(home);
  const environment: NodeJS.ProcessEnv = { ...inherited, HUTCH_HOME: home };
  delete environment.ELECTROBUN_HUTCH_BINARY;
  delete environment.HUTCH_ENGINE_BINARY;
  delete environment.HUTCH_ELECTROBUN_DEVKIT_ROOT;
  return environment;
}
