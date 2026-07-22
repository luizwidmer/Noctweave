import type { RPCSchema } from "electrobun/bun";

export type RelayExposure = "local" | "network";

export type RelayLauncherSettings = {
  relayName: string;
  exposure: RelayExposure;
  tcpPort: number;
  httpPort: number;
  adminPort: number;
  rendezvousTransportEnabled: boolean;
  trustedReverseProxyTLS: boolean;
};

export type RelayLauncherStatus = {
  dockerAvailable: boolean;
  imageReady: boolean;
  containerState: "missing" | "stopped" | "running";
  relayHealthy: boolean;
  settings: RelayLauncherSettings;
  relayEndpoint: string;
  adminURL: string;
  detail: string;
};

export type RelayDesktopRPC = {
  bun: RPCSchema<{
    requests: {
      getStatus: { params: Record<never, never>; response: RelayLauncherStatus };
      buildImage: { params: Record<never, never>; response: RelayLauncherStatus };
      startRelay: { params: RelayLauncherSettings; response: RelayLauncherStatus };
      stopRelay: { params: Record<never, never>; response: RelayLauncherStatus };
      openConsole: { params: Record<never, never>; response: boolean };
      copyAdminToken: { params: Record<never, never>; response: boolean };
      getLogs: { params: Record<never, never>; response: string };
    };
    messages: Record<never, never>;
  }>;
  webview: RPCSchema<{
    requests: Record<never, never>;
    messages: Record<never, never>;
  }>;
};
