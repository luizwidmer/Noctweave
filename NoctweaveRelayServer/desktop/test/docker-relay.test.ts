import { describe, expect, test } from "bun:test";

import {
  DockerRelayManager,
  dockerRunArguments,
  relayContainer,
  relayImage,
  validateSettings,
  type CommandResult
} from "../bun/docker-relay.js";

const token = "a".repeat(64);
const settings = {
  relayName: "Community Relay",
  exposure: "local" as const,
  tcpPort: 9339,
  httpPort: 9340,
  adminPort: 9090
};

describe("relay launcher validation", () => {
  test("builds a fixed local-only Docker command", () => {
    const args = dockerRunArguments(settings, token);
    expect(args).toContain("127.0.0.1:9339:9339");
    expect(args).toContain("127.0.0.1:9340:9340");
    expect(args).toContain("127.0.0.1:9090:9090");
    expect(args).toContain(relayImage);
    expect(args.slice(-2)).toEqual(["--relay-name", "Community Relay"]);
  });

  test("network exposure never publishes the operator console", () => {
    const args = dockerRunArguments({ ...settings, exposure: "network" }, token);
    expect(args).toContain("0.0.0.0:9339:9339");
    expect(args).toContain("0.0.0.0:9340:9340");
    expect(args).toContain("127.0.0.1:9090:9090");
  });

  test("rejects duplicate, privileged, and malformed settings", () => {
    expect(() => validateSettings({ ...settings, httpPort: 9339 })).toThrow("must be different");
    expect(() => validateSettings({ ...settings, tcpPort: 80 })).toThrow("1024 through 65535");
    expect(() => validateSettings({ ...settings, relayName: "bad\nname" })).toThrow("printable");
    expect(() => dockerRunArguments(settings, "secret")).toThrow("operator token");
  });
});

test("manager uses argument arrays for build, start, stop, and status", async () => {
  const commands: string[][] = [];
  const runner = async (command: string[]): Promise<CommandResult> => {
    commands.push(command);
    if (command[1] === "version") return { exitCode: 0, stdout: "27.0", stderr: "" };
    if (command[1] === "inspect") return { exitCode: 0, stdout: "true", stderr: "" };
    if (command[1] === "image") return { exitCode: 0, stdout: "[]", stderr: "" };
    return { exitCode: 0, stdout: relayContainer, stderr: "" };
  };
  const manager = new DockerRelayManager(
    new URL("../../", import.meta.url).pathname,
    token,
    runner,
    async () => true
  );
  await manager.start(settings);
  const status = await manager.status(settings);
  await manager.stop();
  expect(status.relayHealthy).toBe(true);
  expect(commands.some((command) => command[1] === "run")).toBe(true);
  expect(commands.some((command) => command.join(" ").includes("rm -f"))).toBe(true);
  expect(commands.at(-1)).toEqual(["docker", "stop", "-t", "10", relayContainer]);
});
