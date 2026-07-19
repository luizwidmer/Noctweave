import { access } from "node:fs/promises";

import type {
  RelayLauncherSettings,
  RelayLauncherStatus
} from "../rpc.js";

export const relayImage = "noctweave-relay:local";
export const relayContainer = "noctweave-relay-desktop";
export const relayVolume = "noctweave-relay-data";

export type CommandResult = {
  exitCode: number;
  stdout: string;
  stderr: string;
};

export type CommandRunner = (
  command: string[],
  options?: { cwd?: string; timeoutMilliseconds?: number }
) => Promise<CommandResult>;

export type HealthProbe = (url: string) => Promise<boolean>;

export const defaultSettings: RelayLauncherSettings = {
  relayName: "My Noctweave Relay",
  exposure: "local",
  tcpPort: 9339,
  httpPort: 9340,
  adminPort: 9090
};

export function validateSettings(input: RelayLauncherSettings): RelayLauncherSettings {
  const relayName = input.relayName.trim();
  if (relayName.length < 1 || relayName.length > 80 || /[\u0000-\u001f\u007f]/u.test(relayName)) {
    throw new Error("Relay name must contain 1–80 printable characters.");
  }
  if (input.exposure !== "local" && input.exposure !== "network") {
    throw new Error("Relay exposure must be local or network.");
  }
  const ports = [input.tcpPort, input.httpPort, input.adminPort];
  if (ports.some((port) => !Number.isInteger(port) || port < 1024 || port > 65_535)) {
    throw new Error("Relay ports must be unique integers from 1024 through 65535.");
  }
  if (new Set(ports).size !== ports.length) {
    throw new Error("TCP, HTTP/WebSocket, and operator ports must be different.");
  }
  return { ...input, relayName };
}

export function dockerRunArguments(
  settingsInput: RelayLauncherSettings,
  adminToken: string,
  imageReference = relayImage
): string[] {
  const settings = validateSettings(settingsInput);
  if (!/^[a-f0-9]{64}$/u.test(adminToken)) {
    throw new Error("The generated operator token is invalid.");
  }
  if (imageReference !== relayImage && !/^[a-f0-9]{12,64}$/u.test(imageReference)) {
    throw new Error("The local relay image reference is invalid.");
  }
  const relayHost = settings.exposure === "network" ? "0.0.0.0" : "127.0.0.1";
  return [
    "run", "-d",
    "--name", relayContainer,
    "--restart", "unless-stopped",
    "-p", `${relayHost}:${settings.tcpPort}:9339`,
    "-p", `${relayHost}:${settings.httpPort}:9340`,
    "-p", `127.0.0.1:${settings.adminPort}:9090`,
    "-e", `NOCTWEAVE_ADMIN_TOKEN=${adminToken}`,
    "-e", "NOCTWEAVE_ADMIN_HOST=0.0.0.0",
    "-v", `${relayVolume}:/data`,
    imageReference,
    "--host", "0.0.0.0",
    "--port", "9339",
    "--http-port", "9340",
    "--admin-port", "9090",
    "--data-dir", "/data",
    "--rendezvous-transport", "true",
    "--relay-name", settings.relayName
  ];
}

export class DockerRelayManager {
  constructor(
    private readonly sourceDirectory: string,
    private readonly adminToken: string,
    private readonly runner: CommandRunner = runCommand,
    private readonly healthProbe: HealthProbe = probeHealth
  ) {}

  async buildImage(): Promise<void> {
    await access(`${this.sourceDirectory}/Dockerfile`);
    const result = await this.runner(
      ["docker", "build", "--progress=plain", "-t", relayImage, this.sourceDirectory],
      { timeoutMilliseconds: 30 * 60 * 1000 }
    );
    ensureSuccess(result, "Docker could not build the relay image");
  }

  async start(settings: RelayLauncherSettings): Promise<void> {
    const imageReference = await this.localImageReference();
    if (!imageReference) {
      throw new Error("Build the relay image from source before starting it.");
    }
    const removed = await this.runner(["docker", "rm", "-f", relayContainer]);
    if (removed.exitCode !== 0 && !/No such container/iu.test(removed.stderr)) {
      ensureSuccess(removed, "Docker could not replace the previous managed relay");
    }
    const result = await this.runner([
      "docker",
      ...dockerRunArguments(settings, this.adminToken, imageReference)
    ]);
    ensureSuccess(result, "Docker could not start the relay");
    for (let attempt = 0; attempt < 20; attempt++) {
      const status = await this.status(settings);
      if (status.relayHealthy) return;
      if (status.containerState === "stopped") {
        const logs = await this.logs();
        const detail = logs.trim().split("\n").slice(-4).join(" ").slice(0, 700);
        throw new Error(detail
          ? `Relay stopped during startup: ${detail}`
          : "Relay stopped during startup. Check whether its ports are already in use.");
      }
      await Bun.sleep(250);
    }
    throw new Error("Relay container did not become healthy within five seconds. Review its logs and port assignments.");
  }

  async stop(): Promise<void> {
    const result = await this.runner(["docker", "stop", "-t", "10", relayContainer]);
    if (result.exitCode !== 0 && !/No such container/iu.test(result.stderr)) {
      ensureSuccess(result, "Docker could not stop the relay");
    }
  }

  async logs(): Promise<string> {
    const result = await this.runner(["docker", "logs", "--tail", "120", relayContainer]);
    if (result.exitCode !== 0) {
      return "The managed relay has not produced logs yet.";
    }
    return `${result.stdout}\n${result.stderr}`.trim().slice(-32_000);
  }

  async status(settingsInput: RelayLauncherSettings): Promise<RelayLauncherStatus> {
    const settings = validateSettings(settingsInput);
    const docker = await this.runner(
      ["docker", "version", "--format", "{{.Server.Version}}"],
      { timeoutMilliseconds: 5_000 }
    );
    if (docker.exitCode !== 0) {
      return makeStatus(settings, false, false, "missing", false, "Docker Desktop or Docker Engine is not available.");
    }
    const imageReference = await this.localImageReference();
    const inspected = await this.runner([
      "docker", "inspect", "--format", "{{.State.Running}}", relayContainer
    ]);
    const containerState = inspected.exitCode !== 0
      ? "missing"
      : inspected.stdout.trim() === "true" ? "running" : "stopped";
    const healthy = containerState === "running"
      ? await this.healthProbe(`http://127.0.0.1:${settings.httpPort}/relay`)
      : false;
    const detail = healthy
      ? "Relay is accepting local health checks."
      : containerState === "running"
        ? "Container is running; the relay is still starting or unhealthy."
        : imageReference
          ? "Local relay image is ready to start."
          : "Build the relay image from the bundled source snapshot.";
    return makeStatus(settings, true, imageReference !== undefined, containerState, healthy, detail);
  }

  private async localImageReference(): Promise<string | undefined> {
    const result = await this.runner([
      "docker", "image", "ls",
      "--filter", `reference=${relayImage}`,
      "--format", "{{.ID}}"
    ]);
    if (result.exitCode !== 0) return undefined;
    const imageID = result.stdout.trim().split("\n")[0] ?? "";
    return /^[a-f0-9]{12,64}$/u.test(imageID) ? imageID : undefined;
  }
}

function makeStatus(
  settings: RelayLauncherSettings,
  dockerAvailable: boolean,
  imageReady: boolean,
  containerState: RelayLauncherStatus["containerState"],
  relayHealthy: boolean,
  detail: string
): RelayLauncherStatus {
  const clientHost = settings.exposure === "network" ? "<host-address>" : "127.0.0.1";
  return {
    dockerAvailable,
    imageReady,
    containerState,
    relayHealthy,
    settings,
    relayEndpoint: `http://${clientHost}:${settings.httpPort}`,
    adminURL: `http://127.0.0.1:${settings.adminPort}/admin/`,
    detail
  };
}

function ensureSuccess(result: CommandResult, message: string): void {
  if (result.exitCode === 0) return;
  const detail = result.stderr.trim().split("\n").slice(-3).join(" ").slice(0, 500);
  throw new Error(detail ? `${message}: ${detail}` : message);
}

async function probeHealth(url: string): Promise<boolean> {
  try {
    const requestID = crypto.randomUUID();
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        requestID,
        module: "nw.core",
        version: 2,
        method: "health",
        body: {},
        authToken: null
      }),
      redirect: "error",
      signal: AbortSignal.timeout(2_500)
    });
    if (!response.ok) return false;
    const payload = await response.json() as Record<string, unknown>;
    return payload.requestID === requestID
      && payload.module === "nw.core"
      && payload.version === 2
      && payload.method === "health"
      && payload.status === "success"
      && payload.error === null;
  } catch {
    return false;
  }
}

export async function runCommand(
  command: string[],
  options: { cwd?: string; timeoutMilliseconds?: number } = {}
): Promise<CommandResult> {
  const subprocess = Bun.spawn(command, {
    cwd: options.cwd,
    env: process.env,
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe"
  });
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    subprocess.kill();
  }, options.timeoutMilliseconds ?? 120_000);
  const [stdout, stderr, exitCode] = await Promise.all([
    readTail(subprocess.stdout),
    readTail(subprocess.stderr),
    subprocess.exited
  ]).finally(() => clearTimeout(timer));
  return {
    exitCode: timedOut ? 124 : exitCode,
    stdout,
    stderr: timedOut ? `${stderr}\nCommand timed out.`.trim() : stderr
  };
}

async function readTail(stream: ReadableStream<Uint8Array>, limit = 128 * 1024): Promise<string> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let output = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    output += decoder.decode(value, { stream: true });
    if (output.length > limit) output = output.slice(-limit);
  }
  output += decoder.decode();
  return output;
}
