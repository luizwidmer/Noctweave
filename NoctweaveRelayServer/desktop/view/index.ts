import Electrobun, { Electroview } from "electrobun/view";
import type {
  RelayDesktopRPC,
  RelayLauncherSettings,
  RelayLauncherStatus
} from "../rpc.js";

const rpc = Electroview.defineRPC<RelayDesktopRPC>({
  maxRequestTime: 31 * 60 * 1000,
  handlers: { requests: {}, messages: {} }
});
const desktop = new Electrobun.Electroview({ rpc });

const $ = <T extends Element>(selector: string): T => {
  const element = document.querySelector<T>(selector);
  if (!element) throw new Error(`Missing desktop element: ${selector}`);
  return element;
};

const form = $("#relayForm") as HTMLFormElement;
const buildButton = $("#buildImage") as HTMLButtonElement;
const startButton = $("#startRelay") as HTMLButtonElement;
const stopButton = $("#stopRelay") as HTMLButtonElement;
const consoleButton = $("#openConsole") as HTMLButtonElement;
const tokenButton = $("#copyToken") as HTMLButtonElement;
const logsButton = $("#refreshLogs") as HTMLButtonElement;
let currentStatus: RelayLauncherStatus | undefined;
let busy = false;
let activityMessage: { text: string; isError: boolean } | undefined;

function settingsFromForm(): RelayLauncherSettings {
  const data = new FormData(form);
  return {
    relayName: String(data.get("relayName") ?? ""),
    exposure: data.get("exposure") === "network" ? "network" : "local",
    tcpPort: Number(data.get("tcpPort")),
    httpPort: Number(data.get("httpPort")),
    adminPort: Number(data.get("adminPort")),
    rendezvousTransportEnabled: data.get("rendezvousTransportEnabled") === "on",
    trustedReverseProxyTLS: data.get("trustedReverseProxyTLS") === "on"
  };
}

function fillSettings(settings: RelayLauncherSettings): void {
  (form.elements.namedItem("relayName") as HTMLInputElement).value = settings.relayName;
  (form.elements.namedItem("exposure") as HTMLSelectElement).value = settings.exposure;
  (form.elements.namedItem("tcpPort") as HTMLInputElement).value = String(settings.tcpPort);
  (form.elements.namedItem("httpPort") as HTMLInputElement).value = String(settings.httpPort);
  (form.elements.namedItem("adminPort") as HTMLInputElement).value = String(settings.adminPort);
  (form.elements.namedItem("rendezvousTransportEnabled") as HTMLInputElement).checked = settings.rendezvousTransportEnabled;
  (form.elements.namedItem("trustedReverseProxyTLS") as HTMLInputElement).checked = settings.trustedReverseProxyTLS;
}

function render(status: RelayLauncherStatus, preserveForm = false): void {
  currentStatus = status;
  if (!preserveForm) fillSettings(status.settings);
  const running = status.containerState === "running";
  $("#dockerState").textContent = status.dockerAvailable ? "Ready" : "Unavailable";
  $("#imageState").textContent = status.imageReady ? "Built locally" : "Not built";
  $("#relayState").textContent = status.relayHealthy ? "Online" : running ? "Starting" : "Stopped";
  $("#relayEndpoint").textContent = status.relayEndpoint;
  $("#statusDetail").textContent = activityMessage?.text ?? status.detail;
  $("#statusDetail").classList.toggle("errorText", activityMessage?.isError === true);
  $("#statusDot").className = `statusDot ${status.relayHealthy ? "online" : running ? "waiting" : ""}`;
  $("#statusLabel").textContent = status.relayHealthy ? "Relay online" : running ? "Starting relay" : "Relay stopped";
  startButton.disabled = busy || !status.dockerAvailable || !status.imageReady || running;
  stopButton.disabled = busy || !running;
  buildButton.disabled = busy || !status.dockerAvailable || running;
  consoleButton.disabled = busy || !status.relayHealthy;
  tokenButton.disabled = busy || !status.relayHealthy;
}

function setBusy(value: boolean, label?: string): void {
  busy = value;
  if (label) activityMessage = { text: label, isError: false };
  document.body.classList.toggle("busy", value);
  if (currentStatus) render(currentStatus, true);
}

function showToast(message: string, isError = false): void {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.classList.add("visible");
  window.setTimeout(() => toast.classList.remove("visible"), 4200);
}

async function perform(label: string, operation: () => Promise<RelayLauncherStatus>): Promise<void> {
  setBusy(true, label);
  try {
    activityMessage = undefined;
    render(await operation());
  } catch (error) {
    const message = error instanceof Error ? error.message : "Operation failed.";
    activityMessage = { text: message, isError: true };
    showToast(message, true);
  } finally {
    setBusy(false);
  }
}

buildButton.addEventListener("click", () => perform(
  "Building the relay image from the bundled source. The first build may take several minutes…",
  () => desktop.rpc!.request.buildImage({})
));
startButton.addEventListener("click", () => perform(
  "Starting the managed relay container…",
  () => desktop.rpc!.request.startRelay(settingsFromForm())
));
stopButton.addEventListener("click", () => perform(
  "Stopping the relay without deleting its encrypted queues or configuration…",
  () => desktop.rpc!.request.stopRelay({})
));
consoleButton.addEventListener("click", async () => {
  await desktop.rpc!.request.openConsole({});
});
tokenButton.addEventListener("click", async () => {
  await desktop.rpc!.request.copyAdminToken({});
  showToast("Operator token copied. Paste it into the local console login.");
});
logsButton.addEventListener("click", async () => {
  try {
    $("#logs").textContent = await desktop.rpc!.request.getLogs({});
  } catch (error) {
    showToast(error instanceof Error ? error.message : "Could not read relay logs.", true);
  }
});

async function refresh(preserveForm = true): Promise<void> {
  if (busy) return;
  try {
    render(await desktop.rpc!.request.getStatus({}), preserveForm);
  } catch (error) {
    showToast(error instanceof Error ? error.message : "Could not inspect Docker.", true);
  }
}

render(await desktop.rpc!.request.getStatus({}));
window.setInterval(() => void refresh(), 5_000);
