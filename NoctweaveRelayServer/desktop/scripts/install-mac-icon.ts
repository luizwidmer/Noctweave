import { copyFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const wrapperBundle = process.env.ELECTROBUN_WRAPPER_BUNDLE_PATH;
if (!wrapperBundle || !existsSync(wrapperBundle)) {
  throw new Error("Electrobun did not provide a valid relay wrapper path.");
}

const resources = process.env.ELECTROBUN_OS === "macos"
  ? join(wrapperBundle, "Contents", "Resources")
  : join(wrapperBundle, "Resources");
if (process.env.ELECTROBUN_OS === "macos") {
  const source = new URL("../assets/relay-icon.icns", import.meta.url);
  copyFileSync(source, join(resources, "AppIcon.icns"));
}
