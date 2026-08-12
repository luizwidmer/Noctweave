import http.client
import importlib.util
import json
import os
import pathlib
import stat
import sys
import tempfile
import threading
import unittest


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "noctweave_reticulum_bridge.py"
SPEC = importlib.util.spec_from_file_location("noctweave_reticulum_bridge", MODULE_PATH)
bridge = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)


class _RelayHandler(bridge.http.server.BaseHTTPRequestHandler):
    response_body = b'{"requestID":"1","module":"nw.core","version":2,"method":"health","body":{"kind":"health","value":{"status":"ok"}},"error":null}'
    status = 200

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        self.server.last_body = self.rfile.read(length)
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.response_body)))
        self.end_headers()
        self.wfile.write(self.response_body)

    def log_message(self, format, *args):
        pass


class _FakeClient:
    destination_hex = "00" * 16
    maximum_request_bytes = 4096

    def __init__(self, response=None, error=None):
        self.response = response or b'{"ok":true}'
        self.error = error
        self.requests = []

    def is_connected(self):
        return False

    def request(self, payload):
        self.requests.append(payload)
        if self.error:
            raise self.error
        return self.response


class _FakeIdentity:
    key = b"k" * 64

    def get_private_key(self):
        return self.key


class _FakeIdentityAPI:
    loaded = None

    def __new__(cls):
        return _FakeIdentity()

    @classmethod
    def from_file(cls, path):
        data = pathlib.Path(path).read_bytes()
        return _FakeIdentity() if data == _FakeIdentity.key else None


class _FakeRNS:
    Identity = _FakeIdentityAPI


class _FakeForwarder:
    maximum_request_bytes = 4096

    def __init__(self):
        self.requests = []

    def forward(self, payload):
        self.requests.append(payload)
        return b'{"ok":true}'


class ValidationTests(unittest.TestCase):
    def test_relay_url_defaults_to_exact_relay_path(self):
        self.assertEqual(
            bridge.normalize_relay_url("http://127.0.0.1:9340"),
            "http://127.0.0.1:9340/relay",
        )

    def test_relay_url_rejects_unapproved_remote_host(self):
        with self.assertRaises(bridge.BridgeConfigurationError):
            bridge.normalize_relay_url("https://relay.example/relay")

    def test_relay_url_accepts_exact_operator_allow_entry(self):
        self.assertEqual(
            bridge.normalize_relay_url(
                "https://relay.example/relay", ["relay.example"]
            ),
            "https://relay.example/relay",
        )

    def test_relay_url_rejects_redirectable_path_and_credentials(self):
        for url in (
            "http://127.0.0.1:9340/other",
            "http://user:secret@127.0.0.1:9340/relay",
            "http://127.0.0.1:9340/relay?next=x",
        ):
            with self.subTest(url=url):
                with self.assertRaises(bridge.BridgeConfigurationError):
                    bridge.normalize_relay_url(url)

    def test_bridge_error_is_bounded_and_machine_readable(self):
        payload = bridge.encode_bridge_error("Too Many Requests!" * 20)
        self.assertLessEqual(len(payload), len(bridge.BRIDGE_ERROR_PREFIX) + 64)
        self.assertEqual(bridge.decode_bridge_error(payload), "toomanyrequeststoomanyrequeststoomanyrequeststoomanyrequeststoom")


class RateLimiterTests(unittest.TestCase):
    def test_limiter_is_per_link_and_resets(self):
        limiter = bridge.FixedWindowRateLimiter(2, maximum_keys=16)
        self.assertTrue(limiter.allow("a", now=0))
        self.assertTrue(limiter.allow("a", now=1))
        self.assertFalse(limiter.allow("a", now=2))
        self.assertTrue(limiter.allow("b", now=2))
        self.assertTrue(limiter.allow("a", now=61))

    def test_limiter_caps_key_memory(self):
        limiter = bridge.FixedWindowRateLimiter(1, maximum_keys=16)
        for index in range(50):
            limiter.allow(str(index), now=float(index))
        self.assertEqual(len(limiter._windows), 16)


class ServerBridgeTests(unittest.TestCase):
    def make_server(self, requests_per_minute=2, global_requests_per_minute=3):
        forwarder = _FakeForwarder()
        server = bridge.ReticulumRelayServer(
            object(),
            forwarder,
            pathlib.Path("unused"),
            rns_config=None,
            maximum_concurrent_requests=2,
            requests_per_minute=requests_per_minute,
            global_requests_per_minute=global_requests_per_minute,
            announce_interval=0,
        )
        return server, forwarder

    def test_server_forwards_exact_bytes(self):
        server, forwarder = self.make_server()
        payload = b'{"requestID":"1"}'
        response = server._handle_request(
            bridge.REQUEST_PATH, payload, b"request", b"link-a", None, 0
        )
        self.assertEqual(response, b'{"ok":true}')
        self.assertEqual(forwarder.requests, [payload])

    def test_server_enforces_per_link_rate_limit(self):
        server, _ = self.make_server(requests_per_minute=1, global_requests_per_minute=10)
        payload = b'{"requestID":"1"}'
        first = server._handle_request(
            bridge.REQUEST_PATH, payload, b"one", b"link-a", None, 0
        )
        second = server._handle_request(
            bridge.REQUEST_PATH, payload, b"two", b"link-a", None, 0
        )
        self.assertIsNone(bridge.decode_bridge_error(first))
        self.assertEqual(bridge.decode_bridge_error(second), "rate_limited")

    def test_server_enforces_global_rate_limit_across_links(self):
        server, _ = self.make_server(requests_per_minute=10, global_requests_per_minute=1)
        payload = b'{"requestID":"1"}'
        server._handle_request(bridge.REQUEST_PATH, payload, b"one", b"a", None, 0)
        second = server._handle_request(
            bridge.REQUEST_PATH, payload, b"two", b"b", None, 0
        )
        self.assertEqual(bridge.decode_bridge_error(second), "rate_limited")


class ForwarderTests(unittest.TestCase):
    def setUp(self):
        self.server = bridge._ThreadingHTTPServer(("127.0.0.1", 0), _RelayHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_forwards_exact_request_and_returns_exact_response(self):
        payload = b'{"requestID":"1","module":"nw.core","version":2,"method":"health","body":{},"authToken":null}'
        forwarder = bridge.RelayHTTPForwarder(
            f"http://127.0.0.1:{self.server.server_port}/relay",
            maximum_request_bytes=4096,
            maximum_response_bytes=4096,
            timeout=2,
        )
        response = forwarder.forward(payload)
        self.assertEqual(self.server.last_body, payload)
        self.assertEqual(response, _RelayHandler.response_body)

    def test_rejects_non_object_json_before_forwarding(self):
        forwarder = bridge.RelayHTTPForwarder(
            f"http://127.0.0.1:{self.server.server_port}/relay",
            maximum_request_bytes=4096,
            maximum_response_bytes=4096,
            timeout=2,
        )
        with self.assertRaises(bridge.BridgeError):
            forwarder.forward(b"[]")


class LocalGatewayTests(unittest.TestCase):
    def setUp(self):
        self.client = _FakeClient()
        handler = bridge.make_client_gateway_handler(self.client)
        self.server = bridge._ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        connection.close()
        return response.status, payload

    def test_gateway_preserves_exact_relay_bytes(self):
        payload = b'{"requestID":"1"}'
        status, response = self._request(
            "POST", "/relay", payload, {"Content-Type": "application/json"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.client.requests, [payload])
        self.assertEqual(response, self.client.response)

    def test_gateway_rejects_wrong_path(self):
        status, _ = self._request("POST", "/other", b"{}")
        self.assertEqual(status, 404)

    def test_gateway_maps_remote_failure_without_leaking_details(self):
        self.client.error = bridge.BridgeRemoteError("remote bridge error: rate_limited")
        status, payload = self._request(
            "POST", "/relay", b"{}", {"Content-Type": "application/json"}
        )
        self.assertEqual(status, 502)
        self.assertEqual(json.loads(payload), {"error": "rate_limited"})

    def test_gateway_rejects_browser_origins_and_cross_site_metadata(self):
        status, _ = self._request(
            "POST",
            "/relay",
            b"{}",
            {
                "Content-Type": "application/json",
                "Origin": "https://attacker.example",
            },
        )
        self.assertEqual(status, 403)
        status, _ = self._request(
            "POST",
            "/relay",
            b"{}",
            {
                "Content-Type": "application/json",
                "Sec-Fetch-Site": "cross-site",
            },
        )
        self.assertEqual(status, 403)
        self.assertEqual(self.client.requests, [])

    def test_gateway_requires_json_content_type(self):
        status, _ = self._request("POST", "/relay", b"{}")
        self.assertEqual(status, 415)
        status, _ = self._request(
            "POST", "/relay", b"{}", {"Content-Type": "text/plain"}
        )
        self.assertEqual(status, 415)
        self.assertEqual(self.client.requests, [])

    def test_health_is_local_bridge_state_not_relay_health(self):
        status, payload = self._request("GET", "/bridge/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["link"], "idle")


class IdentityTests(unittest.TestCase):
    def test_identity_is_created_and_reloaded_with_owner_only_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "identity"
            first = bridge.load_or_create_identity(_FakeRNS, path)
            second = bridge.load_or_create_identity(_FakeRNS, path)
            self.assertEqual(first.get_private_key(), second.get_private_key())
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
