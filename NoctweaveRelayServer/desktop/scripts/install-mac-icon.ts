import { copyFileSync, cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const wrapperBundle = process.env.ELECTROBUN_WRAPPER_BUNDLE_PATH;
if (!wrapperBundle || !existsSync(wrapperBundle)) {
  throw new Error("Electrobun did not provide a valid relay wrapper path.");
}

const resources = process.env.ELECTROBUN_OS === "macos"
  ? join(wrapperBundle, "Contents", "Resources")
  : join(wrapperBundle, "Resources");
const projectRoot = fileURLToPath(new URL("../../", import.meta.url));
const relaySource = join(resources, "relay-source");
rmSync(relaySource, { recursive: true, force: true });
mkdirSync(relaySource, { recursive: true });
for (const item of ["Dockerfile", "Package.swift", "Package.resolved", "Sources", "Tests"]) {
  cpSync(join(projectRoot, item), join(relaySource, item), { recursive: true });
}

if (process.env.ELECTROBUN_OS === "macos") {
  const source = new URL("../assets/relay-icon.icns", import.meta.url);
  copyFileSync(source, join(resources, "AppIcon.icns"));
}
