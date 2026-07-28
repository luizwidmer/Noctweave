import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";

test("relay desktop packages source and keeps Docker and admin boundaries explicit", async () => {
  const [config, backend, wrapper, html, styles, view] = await Promise.all([
    readFile(new URL("../../electrobun.config.ts", import.meta.url), "utf8"),
    readFile(new URL("../bun/index.ts", import.meta.url), "utf8"),
    readFile(new URL("../scripts/install-mac-icon.ts", import.meta.url), "utf8"),
    readFile(new URL("../view/index.html", import.meta.url), "utf8"),
    readFile(new URL("../view/styles.css", import.meta.url), "utf8"),
    readFile(new URL("../view/index.ts", import.meta.url), "utf8")
  ]);
  expect(config).toMatch(/identifier:\s*"org\.noctweave\.relay-desktop"/);
  expect(config).toMatch(/icon:\s*"desktop\/assets\/relay-icon\.png"/);
  expect(config).toMatch(/icon:\s*"desktop\/assets\/relay-icon\.ico"/);
  expect((config.match(/bundleCEF:\s*false/g) ?? []).length).toBe(3);
  expect((config.match(/desktop\/scripts\/install-mac-icon\.ts/g) ?? []).length).toBe(1);
  expect(backend).toMatch(/DockerRelayManager/);
  expect(backend).toMatch(/PATHS\.RESOURCES_FOLDER, "relay-source"/);
  expect(wrapper).toMatch(/"Sources", "Tests"/);
  expect(wrapper).toMatch(/relay-icon\.icns/);
  expect(backend).toMatch(/clipboardWriteText/);
  expect(backend).toContain("publisherPassword");
  expect(html).toContain("Build from source");
  expect(html).toContain("Enable Noctweb hosting and Publisher / Lab");
  expect(html).toContain("Open Publisher / Lab");
  expect(html).toContain("Copy publisher password");
  expect(html).toContain("Docker access is powerful");
  expect(html).toContain("operator port publicly");
  expect(html).not.toContain('name="color-scheme" content="dark"');
  expect(html).toContain('id="appearanceSelect"');
  expect(html).toContain('value="system"');
  expect(html).toContain('value="light"');
  expect(html).toContain('value="dark"');
  expect(styles).toContain("--shell-surface-raised: #f6eee8");
  expect(styles).toContain("--shell-accent: #c96a61");
  expect(styles).toContain("--shell-accent-strong: #922d35");
  expect(styles).toContain(':root[data-theme="dark"]');
  expect(styles).toContain("prefers-color-scheme: dark");
  expect(styles).toContain("safe-area-inset-bottom");
  expect(view).toContain("noctweave.desktop.appearance");
  expect(view).toContain("noctwebHostingEnabled");
  expect(view).toContain("openPublisher");
  expect(view).toContain("localStorage");
});
