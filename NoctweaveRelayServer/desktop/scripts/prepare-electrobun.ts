import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runCachedTool } from "./checked-build";
import { privateHutchEnvironment } from "./private-hutch-home";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
if (process.argv.length > 2) throw new Error("desktop:prepare takes no arguments.");
runCachedTool([process.execPath, join(root, "node_modules", "electrobun", "bin", "electrobun.cjs"),
  "prepare", "--env=stable"], root, privateHutchEnvironment(root));
