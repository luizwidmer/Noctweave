import { readFileSync, writeFileSync } from "node:fs";
import { Resvg } from "@resvg/resvg-js";
import * as png2icons from "png2icons";

const svg = readFileSync(new URL("../assets/relay-icon.svg", import.meta.url), "utf8");
const source = new Resvg(svg, {
  background: "rgba(0,0,0,0)",
  fitTo: { mode: "width", value: 1024 }
}).render().asPng();

writeFileSync(new URL("../assets/relay-icon.png", import.meta.url), source);

const icns = png2icons.createICNS(Buffer.from(source), png2icons.BICUBIC2, 0);
const ico = png2icons.createICO(Buffer.from(source), png2icons.BICUBIC2, 0, false, true);

if (!icns || !ico) {
  throw new Error("Failed to generate Noctweave Relay desktop icon formats.");
}

writeFileSync(new URL("../assets/relay-icon.icns", import.meta.url), Uint8Array.from(icns));
writeFileSync(new URL("../assets/relay-icon.ico", import.meta.url), Uint8Array.from(ico));
