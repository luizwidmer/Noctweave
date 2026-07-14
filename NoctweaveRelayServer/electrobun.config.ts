import type { ElectrobunConfig } from "electrobun";

export default {
  app: {
    name: "Noctweave Relay",
    identifier: "org.noctweave.relay-desktop",
    version: "0.1.0",
    description: "Source-built Noctweave relay operator launcher."
  },
  build: {
    bun: {
      entrypoint: "desktop/bun/index.ts"
    },
    views: {
      mainview: {
        entrypoint: "desktop/view/index.ts"
      }
    },
    copy: {
      "desktop/view/index.html": "views/mainview/index.html",
      "desktop/view/styles.css": "views/mainview/styles.css"
    },
    targets: "current",
    useAsar: false,
    watch: ["desktop"],
    mac: {
      bundleCEF: false,
      codesign: false,
      notarize: false
    },
    linux: {
      bundleCEF: false,
      icon: "../NoctweaveJS/desktop/assets/app-icon.png"
    },
    win: {
      bundleCEF: false,
      icon: "../NoctweaveJS/desktop/assets/app-icon.ico"
    }
  },
  scripts: {
    postWrap: "desktop/scripts/install-mac-icon.ts"
  }
} satisfies ElectrobunConfig;
