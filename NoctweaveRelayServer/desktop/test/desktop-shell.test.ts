import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";

test("relay desktop packages source and keeps Docker and admin boundaries explicit", async () => {
  const [config, backend, wrapper, html] = await Promise.all([
    readFile(new URL("../../electrobun.config.ts", import.meta.url), "utf8"),
    readFile(new URL("../bun/index.ts", import.meta.url), "utf8"),
    readFile(new URL("../scripts/install-mac-icon.ts", import.meta.url), "utf8"),
    readFile(new URL("../view/index.html", import.meta.url), "utf8")
  ]);
  expect(config).toMatch(/identifier:\s*"org\.noctweave\.relay-desktop"/);
  expect((config.match(/bundleCEF:\s*false/g) ?? []).length).toBe(3);
  expect((config.match(/desktop\/scripts\/install-mac-icon\.ts/g) ?? []).length).toBe(1);
  expect(backend).toMatch(/DockerRelayManager/);
  expect(backend).toMatch(/PATHS\.RESOURCES_FOLDER, "relay-source"/);
  expect(wrapper).toMatch(/"Sources", "Tests"/);
  expect(backend).toMatch(/clipboardWriteText/);
  expect(html).toContain("Build from source");
  expect(html).toContain("Docker access is powerful");
  expect(html).toContain("operator port publicly");
});
