#!/usr/bin/env python3
"""Bounded Reticulum transport bridge for the Noctweave relay protocol.

The bridge does not interpret, decrypt, transform, retry, or persist Noctweave
requests. Server mode exposes one Reticulum destination and forwards exact
relay request bytes to a fixed HTTP(S) ``POST /relay`` endpoint. Client mode
exposes the same endpoint on loopback and carries each exact request over a
Reticulum Link request.
"""

from __future__ import annotations

import argparse
import collections
import http.server
import ipaddress
import json
import os
import pathlib
import signal
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterable, Optional


APP_NAME = "noctweave"
DESTINATION_ASPECT = "relay"
REQUEST_PATH = "/noctweave/relay/v1"
BRIDGE_VERSION = 1
BRIDGE_ERROR_PREFIX = b"NWRB1-ERROR:"

DEFAULT_MAX_REQUEST_BYTES = 512 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 1_000_000
ABSOLUTE_MAX_REQUEST_BYTES = 8 * 1024 * 1024
ABSOLUTE_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
DEFAULT_REQUEST_TIMEOUT = 120.0
ABSOLUTE_MAX_TIMEOUT = 300.0


class BridgeError(Exception):
    """A safe, expected transport bridge failure."""


class BridgeConfigurationError(BridgeError):
    """Invalid operator-controlled bridge configuration."""


class BridgeRemoteError(BridgeError):
    """The remote bridge rejected or failed a request."""


def _bounded_integer(name: str, value: int, minimum: int, maximum: int) -> int:
    if not minimum <= value <= maximum:
        raise BridgeConfigurationError(
            f"{name} must be between {minimum} and {maximum}."
        )
    return value


def _bounded_timeout(value: float) -> float:
    if not 0.1 <= value <= ABSOLUTE_MAX_TIMEOUT:
        raise BridgeConfigurationError(
            f"request timeout must be between 0.1 and {ABSOLUTE_MAX_TIMEOUT} seconds."
        )
    return value


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_relay_url(url: str, allowed_upstream_hosts: Iterable[str] = ()) -> str:
    """Validate a fixed relay URL and reject implicit outbound authority."""

    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise BridgeConfigurationError("relay URL must use http or https.")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise BridgeConfigurationError("relay URL must contain a host and no user info.")
    if parsed.query or parsed.fragment:
        raise BridgeConfigurationError("relay URL must not contain a query or fragment.")
    if parsed.path not in {"", "/relay"}:
        raise BridgeConfigurationError("relay URL path must be exactly /relay.")
    try:
        parsed.port
    except ValueError as error:
        raise BridgeConfigurationError("relay URL contains an invalid port.") from error

    allowed = {item.lower().rstrip(".") for item in allowed_upstream_hosts}
    host = parsed.hostname.lower().rstrip(".")
    if not _is_loopback_host(host) and host not in allowed:
        raise BridgeConfigurationError(
            "non-loopback relay hosts require an exact --allow-upstream-host entry."
        )

    normalized_path = parsed.path or "/relay"
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, normalized_path, "", "")
    )


def validate_json_object(payload: bytes, maximum_bytes: int, label: str) -> None:
    if not payload or len(payload) > maximum_bytes:
        raise BridgeError(f"{label} is empty or exceeds its configured byte limit.")
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BridgeError(f"{label} is not valid UTF-8 JSON.") from error
    if not isinstance(decoded, dict):
        raise BridgeError(f"{label} must be a JSON object.")


def encode_bridge_error(code: str) -> bytes:
    safe = "".join(character for character in code.lower() if character.isalnum() or character in "_-")
    return BRIDGE_ERROR_PREFIX + (safe[:64] or "bridge_failure").encode("ascii")


def decode_bridge_error(payload: bytes) -> Optional[str]:
    if not payload.startswith(BRIDGE_ERROR_PREFIX):
        return None
    try:
        return payload[len(BRIDGE_ERROR_PREFIX) :].decode("ascii") or "bridge_failure"
    except UnicodeDecodeError:
        return "bridge_failure"


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class RelayHTTPForwarder:
    """Forwards exact relay JSON bytes to one prevalidated endpoint."""

    def __init__(
        self,
        relay_url: str,
        *,
        allowed_upstream_hosts: Iterable[str] = (),
        maximum_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
        maximum_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        timeout: float = DEFAULT_REQUEST_TIMEOUT,
    ) -> None:
        self.relay_url = normalize_relay_url(relay_url, allowed_upstream_hosts)
        self.maximum_request_bytes = _bounded_integer(
            "maximum request bytes", maximum_request_bytes, 1024, ABSOLUTE_MAX_REQUEST_BYTES
        )
        self.maximum_response_bytes = _bounded_integer(
            "maximum response bytes", maximum_response_bytes, 1024, ABSOLUTE_MAX_RESPONSE_BYTES
        )
        self.timeout = _bounded_timeout(timeout)
        self._opener = urllib.request.build_opener(
            NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def forward(self, payload: bytes) -> bytes:
        validate_json_object(payload, self.maximum_request_bytes, "relay request")
        request = urllib.request.Request(
            self.relay_url,
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "Noctweave-Reticulum-Bridge/1",
            },
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                if not 200 <= response.status < 300:
                    raise BridgeError(f"relay returned HTTP {response.status}.")
                declared = response.headers.get("Content-Length")
                if declared is not None:
                    try:
                        declared_size = int(declared)
                    except ValueError as error:
                        raise BridgeError("relay returned an invalid Content-Length.") from error
                    if declared_size < 0 or declared_size > self.maximum_response_bytes:
                        raise BridgeError("relay response exceeds its configured byte limit.")
                body = response.read(self.maximum_response_bytes + 1)
        except urllib.error.HTTPError as error:
            raise BridgeError(f"relay returned HTTP {error.code}.") from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise BridgeError("relay endpoint is unavailable.") from error

        validate_json_object(body, self.maximum_response_bytes, "relay response")
        return body


@dataclass
class _RateWindow:
    started_at: float
    count: int
    last_seen: float


class FixedWindowRateLimiter:
    """Bounded per-Link limiter used before the loopback relay hop."""

    def __init__(self, requests_per_minute: int, maximum_keys: int = 4096) -> None:
        self.requests_per_minute = _bounded_integer(
            "requests per minute", requests_per_minute, 1, 60_000
        )
        self.maximum_keys = _bounded_integer("rate-limit key count", maximum_keys, 16, 65_536)
        self._windows: "collections.OrderedDict[str, _RateWindow]" = collections.OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key: str, now: Optional[float] = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._lock:
            window = self._windows.pop(key, None)
            if window is None or current - window.started_at >= 60.0:
                window = _RateWindow(current, 0, current)
            window.last_seen = current
            if window.count >= self.requests_per_minute:
                self._windows[key] = window
                return False
            window.count += 1
            self._windows[key] = window
            while len(self._windows) > self.maximum_keys:
                self._windows.popitem(last=False)
            return True


def load_or_create_identity(rns: Any, path: pathlib.Path) -> Any:
    """Load or atomically persist one transport-only Reticulum identity."""

    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass

    if path.exists():
        identity = rns.Identity.from_file(str(path))
        if identity is None:
            raise BridgeConfigurationError("Reticulum identity file is invalid.")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return identity

    identity = rns.Identity()
    private_key = identity.get_private_key()
    if not isinstance(private_key, bytes) or not private_key:
        raise BridgeConfigurationError("Reticulum did not produce an identity key.")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(private_key)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
    return identity


class ReticulumRelayServer:
    def __init__(
        self,
        rns: Any,
        forwarder: RelayHTTPForwarder,
        identity_path: pathlib.Path,
        *,
        rns_config: Optional[str],
        maximum_concurrent_requests: int,
        requests_per_minute: int,
        global_requests_per_minute: int,
        announce_interval: float,
    ) -> None:
        self.rns = rns
        self.forwarder = forwarder
        self.identity_path = identity_path
        self.rns_config = rns_config
        self.maximum_concurrent_requests = _bounded_integer(
            "maximum concurrent requests", maximum_concurrent_requests, 1, 256
        )
        self.announce_interval = max(0.0, announce_interval)
        if 0 < self.announce_interval < 60:
            raise BridgeConfigurationError("announce interval must be zero or at least 60 seconds.")
        self.rate_limiter = FixedWindowRateLimiter(requests_per_minute)
        self.global_rate_limiter = FixedWindowRateLimiter(
            global_requests_per_minute, maximum_keys=16
        )
        self._slots = threading.BoundedSemaphore(self.maximum_concurrent_requests)
        self._stop = threading.Event()
        self.reticulum: Any = None
        self.destination: Any = None

    def _handle_request(
        self,
        path: str,
        data: Any,
        request_id: Any,
        link_id: Any,
        remote_identity: Any,
        requested_at: Any,
    ) -> bytes:
        del request_id, remote_identity, requested_at
        if path != REQUEST_PATH or not isinstance(data, (bytes, bytearray)):
            return encode_bridge_error("invalid_request")
        payload = bytes(data)
        if len(payload) > self.forwarder.maximum_request_bytes:
            return encode_bridge_error("request_too_large")
        link_key = bytes(link_id).hex() if isinstance(link_id, (bytes, bytearray)) else "unknown"
        if not self.global_rate_limiter.allow("all") or not self.rate_limiter.allow(link_key):
            return encode_bridge_error("rate_limited")
        if not self._slots.acquire(blocking=False):
            return encode_bridge_error("busy")
        try:
            return self.forwarder.forward(payload)
        except BridgeError:
            return encode_bridge_error("relay_unavailable")
        except Exception:
            return encode_bridge_error("bridge_failure")
        finally:
            self._slots.release()

    def start(self) -> str:
        self.reticulum = self.rns.Reticulum(self.rns_config)
        identity = load_or_create_identity(self.rns, self.identity_path)
        self.destination = self.rns.Destination(
            identity,
            self.rns.Destination.IN,
            self.rns.Destination.SINGLE,
            APP_NAME,
            DESTINATION_ASPECT,
        )
        self.destination.set_max_request_size(self.forwarder.maximum_request_bytes)
        self.destination.register_request_handler(
            REQUEST_PATH,
            response_generator=self._handle_request,
            allow=self.rns.Destination.ALLOW_ALL,
            auto_compress=False,
        )
        self.destination.announce(app_data=b"noctweave-reticulum-bridge-v1")
        if self.announce_interval > 0:
            thread = threading.Thread(target=self._announce_loop, daemon=True)
            thread.start()
        return bytes(self.destination.hash).hex()

    def _announce_loop(self) -> None:
        while not self._stop.wait(self.announce_interval):
            try:
                self.destination.announce(app_data=b"noctweave-reticulum-bridge-v1")
            except Exception:
                print("[reticulum-bridge] announce failed", file=sys.stderr, flush=True)

    def run(self) -> None:
        destination = self.start()
        print(f"[reticulum-bridge] destination {destination}", flush=True)
        print("[reticulum-bridge] server ready", flush=True)
        self._stop.wait()

    def stop(self) -> None:
        self._stop.set()


class ReticulumRelayClient:
    def __init__(
        self,
        rns: Any,
        destination_hex: str,
        *,
        rns_config: Optional[str],
        maximum_request_bytes: int,
        maximum_response_bytes: int,
        request_timeout: float,
        path_timeout: float,
        maximum_concurrent_requests: int,
    ) -> None:
        self.rns = rns
        self.rns_config = rns_config
        self.maximum_request_bytes = _bounded_integer(
            "maximum request bytes", maximum_request_bytes, 1024, ABSOLUTE_MAX_REQUEST_BYTES
        )
        self.maximum_response_bytes = _bounded_integer(
            "maximum response bytes", maximum_response_bytes, 1024, ABSOLUTE_MAX_RESPONSE_BYTES
        )
        self.request_timeout = _bounded_timeout(request_timeout)
        self.path_timeout = _bounded_timeout(path_timeout)
        self.maximum_concurrent_requests = _bounded_integer(
            "maximum concurrent requests", maximum_concurrent_requests, 1, 256
        )
        self.destination_hex = destination_hex.lower()
        self.destination_hash: Optional[bytes] = None
        self.reticulum: Any = None
        self._link: Any = None
        self._link_lock = threading.Lock()
        self._request_slots = threading.BoundedSemaphore(self.maximum_concurrent_requests)

    def start(self) -> None:
        self.reticulum = self.rns.Reticulum(self.rns_config)
        expected_bytes = self.rns.Reticulum.TRUNCATED_HASHLENGTH // 8
        if len(self.destination_hex) != expected_bytes * 2:
            raise BridgeConfigurationError(
                f"Reticulum destination must be {expected_bytes * 2} hexadecimal characters."
            )
        try:
            self.destination_hash = bytes.fromhex(self.destination_hex)
        except ValueError as error:
            raise BridgeConfigurationError("Reticulum destination is not hexadecimal.") from error

    def is_connected(self) -> bool:
        return self._link is not None and self._link.status == self.rns.Link.ACTIVE

    def _connect(self) -> Any:
        with self._link_lock:
            if self.is_connected():
                return self._link
            if self.destination_hash is None:
                raise BridgeError("Reticulum client has not been started.")

            if not self.rns.Transport.has_path(self.destination_hash):
                self.rns.Transport.request_path(self.destination_hash)
                deadline = time.monotonic() + self.path_timeout
                while not self.rns.Transport.has_path(self.destination_hash):
                    if time.monotonic() >= deadline:
                        raise BridgeError("Reticulum path resolution timed out.")
                    time.sleep(0.1)

            identity = self.rns.Identity.recall(self.destination_hash)
            if identity is None:
                raise BridgeError("Reticulum destination identity is unavailable.")
            destination = self.rns.Destination(
                identity,
                self.rns.Destination.OUT,
                self.rns.Destination.SINGLE,
                APP_NAME,
                DESTINATION_ASPECT,
            )
            established = threading.Event()

            def link_established(link: Any) -> None:
                self._link = link
                established.set()

            def link_closed(link: Any) -> None:
                if self._link is link:
                    self._link = None

            link = self.rns.Link(
                destination,
                established_callback=link_established,
                closed_callback=link_closed,
            )
            if not established.wait(self.path_timeout) or link.status != self.rns.Link.ACTIVE:
                try:
                    link.teardown()
                except Exception:
                    pass
                raise BridgeError("Reticulum link establishment timed out.")
            self._link = link
            return link

    def request(self, payload: bytes) -> bytes:
        validate_json_object(payload, self.maximum_request_bytes, "relay request")
        if not self._request_slots.acquire(timeout=self.request_timeout):
            raise BridgeError("Reticulum bridge is busy.")
        try:
            link = self._connect()
            complete = threading.Event()
            result: dict[str, Any] = {}

            def response_received(receipt: Any) -> None:
                result["response"] = receipt.response
                complete.set()

            def request_failed(receipt: Any) -> None:
                del receipt
                result["failed"] = True
                complete.set()

            receipt = link.request(
                REQUEST_PATH,
                data=payload,
                response_callback=response_received,
                failed_callback=request_failed,
                timeout=self.request_timeout,
                max_response_size=self.maximum_response_bytes,
            )
            if receipt is False:
                raise BridgeError("Reticulum rejected the outbound request.")
            if not complete.wait(self.request_timeout + 1.0):
                raise BridgeError("Reticulum request timed out.")
            if result.get("failed"):
                raise BridgeError("Reticulum request failed.")
            response = result.get("response")
            if not isinstance(response, (bytes, bytearray)):
                raise BridgeError("Reticulum returned an invalid response type.")
            response_bytes = bytes(response)
            remote_error = decode_bridge_error(response_bytes)
            if remote_error is not None:
                raise BridgeRemoteError(f"remote bridge error: {remote_error}")
            validate_json_object(response_bytes, self.maximum_response_bytes, "relay response")
            return response_bytes
        finally:
            self._request_slots.release()


class _ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_client_gateway_handler(client: ReticulumRelayClient) -> type[http.server.BaseHTTPRequestHandler]:
    class ClientGatewayHandler(http.server.BaseHTTPRequestHandler):
        server_version = "NoctweaveReticulumBridge"
        sys_version = ""

        def do_GET(self) -> None:
            if self.path != "/bridge/health":
                self._send(404, b'{"error":"not_found"}')
                return
            body = json.dumps(
                {
                    "status": "ready",
                    "transport": "reticulum",
                    "destination": client.destination_hex,
                    "link": "connected" if client.is_connected() else "idle",
                },
                separators=(",", ":"),
            ).encode("utf-8")
            self._send(200, body)

        def do_POST(self) -> None:
            if self.path != "/relay":
                self._send(404, b'{"error":"not_found"}')
                return
            if self.headers.get("Transfer-Encoding") is not None:
                self._send(400, b'{"error":"transfer_encoding_not_supported"}')
                return
            lengths = self.headers.get_all("Content-Length", failobj=[])
            if len(lengths) != 1:
                self._send(411, b'{"error":"content_length_required"}')
                return
            try:
                length = int(lengths[0])
            except ValueError:
                self._send(400, b'{"error":"invalid_content_length"}')
                return
            if length <= 0 or length > client.maximum_request_bytes:
                self._send(413, b'{"error":"payload_too_large"}')
                return
            payload = self.rfile.read(length)
            if len(payload) != length:
                self._send(400, b'{"error":"truncated_request"}')
                return
            try:
                response = client.request(payload)
            except BridgeRemoteError as error:
                code = str(error).rsplit(":", 1)[-1].strip()
                body = json.dumps({"error": code}, separators=(",", ":")).encode("utf-8")
                self._send(502, body)
                return
            except BridgeError:
                self._send(502, b'{"error":"reticulum_transport_unavailable"}')
                return
            self._send(200, response)

        def _send(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            del format, args

    return ClientGatewayHandler


def run_client_gateway(client: ReticulumRelayClient, host: str, port: int) -> None:
    if host != "127.0.0.1":
        raise BridgeConfigurationError("client gateway must bind to 127.0.0.1.")
    _bounded_integer("client gateway port", port, 1, 65_535)
    client.start()
    server = _ThreadingHTTPServer((host, port), make_client_gateway_handler(client))

    def stop_server(signum: int, frame: Any) -> None:
        del signum, frame
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop_server)
    signal.signal(signal.SIGTERM, stop_server)
    print(f"[reticulum-bridge] client gateway http://{host}:{port}", flush=True)
    print(f"[reticulum-bridge] remote destination {client.destination_hex}", flush=True)
    server.serve_forever(poll_interval=0.25)
    server.server_close()


def import_reticulum() -> Any:
    try:
        import RNS  # type: ignore
    except ModuleNotFoundError as error:
        raise BridgeConfigurationError(
            "Reticulum is not installed. Install the reviewed rns dependency first."
        ) from error
    return RNS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Carry exact Noctweave relay requests over Reticulum Links."
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    server = subparsers.add_parser("server", help="Expose a relay as a Reticulum destination.")
    server.add_argument("--relay-url", default="http://127.0.0.1:9340/relay")
    server.add_argument("--allow-upstream-host", action="append", default=[])
    server.add_argument("--identity", required=True)
    server.add_argument("--rns-config", default=None)
    server.add_argument("--max-request-bytes", type=int, default=DEFAULT_MAX_REQUEST_BYTES)
    server.add_argument("--max-response-bytes", type=int, default=DEFAULT_MAX_RESPONSE_BYTES)
    server.add_argument("--request-timeout", type=float, default=DEFAULT_REQUEST_TIMEOUT)
    server.add_argument("--max-concurrent-requests", type=int, default=8)
    server.add_argument("--requests-per-minute", type=int, default=120)
    server.add_argument("--global-requests-per-minute", type=int, default=2400)
    server.add_argument("--announce-interval", type=float, default=900.0)

    client = subparsers.add_parser("client", help="Expose a loopback relay endpoint for one Reticulum destination.")
    client.add_argument("--destination", required=True)
    client.add_argument("--listen-host", default="127.0.0.1")
    client.add_argument("--listen-port", type=int, default=9341)
    client.add_argument("--rns-config", default=None)
    client.add_argument("--max-request-bytes", type=int, default=DEFAULT_MAX_REQUEST_BYTES)
    client.add_argument("--max-response-bytes", type=int, default=DEFAULT_MAX_RESPONSE_BYTES)
    client.add_argument("--request-timeout", type=float, default=DEFAULT_REQUEST_TIMEOUT)
    client.add_argument("--path-timeout", type=float, default=60.0)
    client.add_argument("--max-concurrent-requests", type=int, default=4)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        rns = import_reticulum()
        if args.mode == "server":
            forwarder = RelayHTTPForwarder(
                args.relay_url,
                allowed_upstream_hosts=args.allow_upstream_host,
                maximum_request_bytes=args.max_request_bytes,
                maximum_response_bytes=args.max_response_bytes,
                timeout=args.request_timeout,
            )
            bridge = ReticulumRelayServer(
                rns,
                forwarder,
                pathlib.Path(args.identity),
                rns_config=args.rns_config,
                maximum_concurrent_requests=args.max_concurrent_requests,
                requests_per_minute=args.requests_per_minute,
                global_requests_per_minute=args.global_requests_per_minute,
                announce_interval=args.announce_interval,
            )

            def stop_bridge(signum: int, frame: Any) -> None:
                del signum, frame
                bridge.stop()

            signal.signal(signal.SIGINT, stop_bridge)
            signal.signal(signal.SIGTERM, stop_bridge)
            bridge.run()
            return 0

        client = ReticulumRelayClient(
            rns,
            args.destination,
            rns_config=args.rns_config,
            maximum_request_bytes=args.max_request_bytes,
            maximum_response_bytes=args.max_response_bytes,
            request_timeout=args.request_timeout,
            path_timeout=args.path_timeout,
            maximum_concurrent_requests=args.max_concurrent_requests,
        )
        run_client_gateway(client, args.listen_host, args.listen_port)
        return 0
    except BridgeConfigurationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except BridgeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
