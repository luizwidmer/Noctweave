import { join } from "node:path";

import Electrobun, { BrowserView, BrowserWindow, PATHS } from "electrobun/bun";
import type { RelayDesktopRPC, RelayLauncherSettings } from "../rpc.js";
import { DockerRelayManager, validateSettings } from "./docker-relay.js";
import { LauncherStore } from "./launcher-store.js";

const sourceDirectory = join(PATHS.RESOURCES_FOLDER, "app", "relay-source");
const store = new LauncherStore();
let state = await store.load();
let manager = new DockerRelayManager(sourceDirectory, state.adminToken);

async function updateSettings(settings: RelayLauncherSettings): Promise<void> {
  state = { ...state, settings: validateSettings(settings) };
  await store.save(state);
}

const desktopRPC = BrowserView.defineRPC<RelayDesktopRPC>({
  maxRequestTime: 31 * 60 * 1000,
  handlers: {
    requests: {
      getStatus: () => manager.status(state.settings),
      buildImage: async () => {
        await manager.buildImage();
        return manager.status(state.settings);
      },
      startRelay: async (settings) => {
        await updateSettings(settings);
        await manager.start(state.settings);
        for (let attempt = 0; attempt < 20; attempt++) {
          const status = await manager.status(state.settings);
          if (status.relayHealthy) return status;
          await Bun.sleep(250);
        }
        return manager.status(state.settings);
      },
      stopRelay: async () => {
        await manager.stop();
        return manager.status(state.settings);
      },
      openConsole: () => Electrobun.Utils.openExternal(`http://127.0.0.1:${state.settings.adminPort}/admin/`),
      copyAdminToken: () => {
        Electrobun.Utils.clipboardWriteText(state.adminToken);
        return true;
      },
      getLogs: () => manager.logs()
    },
    messages: {}
  }
});

new BrowserWindow({
  title: "Noctweave Relay",
  url: "views://mainview/index.html",
  rpc: desktopRPC,
  renderer: "native",
  sandbox: false,
  transparent: false,
  titleBarStyle: "default",
  frame: {
    width: 1180,
    height: 780,
    x: 120,
    y: 90
  }
});
