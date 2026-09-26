import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

if (process.platform !== "darwin") throw new Error("This smoke check requires macOS Keychain.");

const service = `org.noctweave.relay-desktop.fixture.${randomUUID()}`;
const account = "disposable-key";
const output = join(".runtime", "desktop-build", "launcher-key-smoke");
mkdirSync(join(".runtime", "desktop-build"), { recursive: true, mode: 0o700 });
const compiled = Bun.spawnSync([
  "xcrun", "--sdk", "macosx", "clang",
  "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
  `-DLAUNCHER_KEY_SERVICE="${service}"`,
  `-DLAUNCHER_KEY_ACCOUNT="${account}"`,
  "-DLAUNCHER_KEY_TEST_ALLOW_DELETE",
  "-framework", "Security", "-framework", "CoreFoundation",
  "desktop/native/launcher-key.c", "-o", output
], { stdout: "pipe", stderr: "pipe" });
if (compiled.exitCode !== 0) {
  throw new Error(`Disposable Keychain helper failed to compile: ${new TextDecoder().decode(compiled.stderr)}`);
}

function run(args: string[] = []): Uint8Array {
  const result = Bun.spawnSync([output, ...args], {
    stdin: "ignore", stdout: "pipe", stderr: "pipe",
    env: { HOME: process.env.HOME ?? "", PATH: "/usr/bin:/bin" }
  });
  if (result.exitCode !== 0) {
    throw new Error(`Disposable Keychain helper failed (${result.exitCode}): ${new TextDecoder().decode(result.stderr)}`);
  }
  return result.stdout;
}

let first: Uint8Array | undefined;
let second: Uint8Array | undefined;
try {
  first = run();
  second = run();
  if (first.byteLength !== 32 || second.byteLength !== 32
      || !Buffer.from(first).equals(Buffer.from(second))) {
    throw new Error("Disposable Keychain key did not round-trip.");
  }
  console.log("Disposable Keychain helper round-trip passed.");
} finally {
  first?.fill(0);
  second?.fill(0);
  run(["--delete"]);
}
