import { spawnSync } from "bun";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

if ((process.env.ELECTROBUN_OS ?? process.platform) === "macos"
    || (process.env.ELECTROBUN_OS ?? process.platform) === "darwin") {
  const architecture = process.env.ELECTROBUN_ARCH ?? process.arch;
  const clangArchitecture = architecture === "arm64" ? "arm64" : architecture === "x64" ? "x86_64" : "";
  if (!clangArchitecture) throw new Error(`Unsupported launcher-key architecture: ${architecture}`);

  const output = join(".runtime", "desktop-build", "launcher-key");
  mkdirSync(join(".runtime", "desktop-build"), { recursive: true, mode: 0o700 });
  const result = spawnSync([
    "xcrun", "--sdk", "macosx", "clang",
    "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fstack-protector-strong",
    "-arch", clangArchitecture,
    "-framework", "Security", "-framework", "CoreFoundation",
    "desktop/native/launcher-key.c", "-o", output
  ], { stdout: "pipe", stderr: "pipe" });
  if (result.exitCode !== 0) {
    throw new Error(`Cannot build the macOS launcher Keychain helper: ${new TextDecoder().decode(result.stderr)}`);
  }
}
