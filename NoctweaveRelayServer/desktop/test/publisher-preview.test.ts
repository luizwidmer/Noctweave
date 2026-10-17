import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

async function publisherHarness() {
  const source = await readFile(new URL(
    "../../Sources/NoctweaveRelayServer/NoctwebPublisherWebUI.swift", import.meta.url
  ), "utf8");
  // This raw Swift literal is the served JavaScript asset. Remove only Swift's
  // multiline-string indentation; execute the actual event handlers/renderer.
  const raw = source.split('private static let javascript = #"""\n')[1]?.split('\n    """#')[0];
  if (!raw) throw new Error("Publisher JavaScript asset was not found");
  const script = raw.replace(/^    /gm, "");
  const elements = new Map<string, any>();
  const blobs: Blob[] = [];
  const context = vm.createContext({
    console, TextEncoder, TextDecoder, Blob,
    crypto: globalThis.crypto, btoa, atob, URLSearchParams,
    location: { search: "" },
    URL: {
      createObjectURL(blob: Blob) { blobs.push(blob); return `blob:preview-${blobs.length}`; },
      revokeObjectURL() {}
    },
    DOMParser: class {
      parseFromString(html: string) { return { body: { innerHTML: html } }; }
    },
    document: {
      documentElement: { dataset: {} },
      getElementById(id: string) {
        if (!elements.has(id)) elements.set(id, {
          value: "", textContent: "", dataset: {}, hidden: false,
          setAttribute() {}, showModal() {},
          classList: { toggle() {}, add() {}, remove() {} },
          listeners: new Map(),
          addEventListener(name: string, callback: Function) { this.listeners.set(name, callback); }
        });
        return elements.get(id);
      },
      querySelectorAll: () => []
    }
  });
  vm.runInContext(script.replace(/^\s*start\(\);$/mu, `
      globalThis.harness = {
        bindEvents, updatePreview,
        setProject(value) { project = value; },
        async restore(saved) {
          fetchConfig = async () => ({ relaySuffix: "fixture" });
          openDatabase = async () => ({});
          unlockPublisherVault = async () => { vaultState = { project: saved }; };
          loadOrCreateIdentity = async () => ({});
          updateIdentityUI = () => {};
          updateHostingUI = () => {};
          await start();
          return project;
        }
      };`), context);
  return { app: context.harness, elements, blobs };
}

test("Refresh Preview renders the current files rather than the click event", async () => {
  const { app, elements, blobs } = await publisherHarness();
  app.setProject({ html: "<h1>My draft</h1>", css: "h1 { color: red; }", js: "" });
  app.bindEvents();
  app.updatePreview();
  expect(await blobs.at(-1)!.text()).toContain("<h1>My draft</h1>");
  elements.get("refreshPreviewButton").listeners.get("click")({ type: "click" });
  expect(await blobs.at(-1)!.text()).toContain("<h1>My draft</h1>");
  expect(elements.get("verificationState").textContent).toBe("Local draft · sandboxed");
});

for (const emptyFile of ["css", "js"] as const) {
  test(`restoring custom source preserves an intentionally empty ${emptyFile} file`, async () => {
    const { app, elements, blobs } = await publisherHarness();
    const saved = {
      publicationID: "fixture-publication", siteLabel: "fixture", title: "Template title",
      subtitle: "", body: "", accent: "#123456", ctaEnabled: false,
      buttonText: "", buttonURL: "", customCode: true, revision: 0,
      html: "<h1>Handwritten website</h1>", css: "h1 { color: blue; }", js: "/* optional */",
      [emptyFile]: ""
    };
    const restored = await app.restore(structuredClone(saved));
    expect(restored).toEqual(saved);
    expect(elements.get("codeEditor").value).toBe(saved.html);
    expect(await blobs.at(-1)!.text()).toContain(saved.html);
  });
}
