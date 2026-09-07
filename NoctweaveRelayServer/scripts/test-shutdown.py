#!/usr/bin/env python3
"""Exercise real relay termination, listener closure and identity persistence."""

import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid


def reserve_ports():
    sockets = [socket.socket() for _ in range(3)]
    try:
        for listener in sockets:
            listener.bind(("127.0.0.1", 0))
        return [listener.getsockname()[1] for listener in sockets]
    finally:
        for listener in sockets:
            listener.close()


def relay_info(port):
    body = json.dumps({
        "requestID": str(uuid.uuid4()), "module": "nw.core", "version": 2,
        "method": "info", "body": {}, "authToken": None,
    }).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/relay", data=body,
        headers={"Content-Type": "application/json"},
    )
    # Local process tests must not inherit an HTTP proxy or operator settings.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=1) as response:
        value = json.load(response)
    assert value["status"] == "success", "Relay info failed"
    return value["body"]["relayInfo"]["relayIdentity"]["claim"]["relayID"]


def run(binary):
    results = []
    expected_identity = None
    environment = {k: v for k, v in os.environ.items() if not k.startswith("NOCTWEAVE_")}
    environment["NOCTWEAVE_ADMIN_TOKEN"] = secrets.token_hex(32)
    with tempfile.TemporaryDirectory(prefix="noctweave-shutdown-") as directory:
        for termination_signal in (signal.SIGTERM, signal.SIGINT):
            tcp, http, admin = reserve_ports()
            with (Path(directory) / "process.log").open("wb") as log:
                process = subprocess.Popen([
                    str(binary), "--host", "127.0.0.1", "--port", str(tcp),
                    "--http-port", str(http), "--admin-host", "127.0.0.1",
                    "--admin-port", str(admin), "--data-dir", directory,
                    "--federation-mode", "solo",
                ], env=environment, stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 20
                    while True:
                        if process.poll() is not None:
                            raise AssertionError(f"Relay exited during startup: {process.returncode}")
                        try:
                            identity = relay_info(http)
                            break
                        except (OSError, urllib.error.URLError):
                            if time.monotonic() >= deadline:
                                raise AssertionError("Relay startup timed out")
                            time.sleep(0.05)
                    if expected_identity is not None:
                        assert identity == expected_identity, "Relay identity changed after restart"
                    expected_identity = identity

                    # Keep a child connection open: closing listening sockets
                    # alone must not leave the process hung on active clients.
                    with socket.create_connection(("127.0.0.1", tcp), timeout=2):
                        started = time.monotonic()
                        process.send_signal(termination_signal)
                        assert process.wait(timeout=5) == 0, "Termination must exit normally"
                        elapsed = time.monotonic() - started
                    for port in (tcp, http, admin):
                        with socket.socket() as probe:
                            probe.settimeout(1)
                            assert probe.connect_ex(("127.0.0.1", port)) != 0, "Listener remained open"
                    results.append({
                        "signal": termination_signal.name, "exitCode": process.returncode,
                        "seconds": round(elapsed, 3), "allListenersClosed": True,
                    })
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
    print(json.dumps({"passed": True, "identityRetainedAcrossRestart": True, "runs": results}, indent=2))


if __name__ == "__main__":
    executable = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else (
        Path(__file__).resolve().parents[1] / ".build/debug/NoctweaveRelayServer"
    )
    run(executable)
