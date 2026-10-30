#!/usr/bin/env python3
"""Regression fixtures for the exact Caddy release route gate."""

import copy
import json
import pathlib
import runpy
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
CHECK = runpy.run_path(str(ROOT / "check-caddy-routes.py"))["check_config"]
BASELINE = json.loads((ROOT / "fixtures" / "caddy-adapted.json").read_text(encoding="utf-8"))


def https_route(config):
    return config["apps"]["http"]["servers"]["srv0"]["routes"][0]


def http_route(config):
    return config["apps"]["http"]["servers"]["srv1"]["routes"][0]


class CaddyRouteGateTests(unittest.TestCase):
    def test_deployed_adapted_config(self):
        CHECK(BASELINE)

    def test_rejects_nested_proxy_matcher(self):
        config = copy.deepcopy(BASELINE)
        nested = https_route(config)["handle"][0]["routes"][0]["handle"][0]["routes"][0]
        nested["match"] = [{"path": ["/other"]}]
        with self.assertRaisesRegex(ValueError, "HTTPS /relay proxy"):
            CHECK(config)

    def test_rejects_plaintext_response_on_port_80(self):
        config = copy.deepcopy(BASELINE)
        http_route(config)["handle"][0]["routes"][0]["handle"][0] = {
            "handler": "static_response", "body": "plaintext", "status_code": 200
        }
        with self.assertRaisesRegex(ValueError, "HTTP server must only redirect"):
            CHECK(config)

    def test_rejects_second_http_route(self):
        config = copy.deepcopy(BASELINE)
        config["apps"]["http"]["servers"]["srv1"]["routes"].append({
            "handle": [{"handler": "static_response", "body": "open", "status_code": 200}]
        })
        with self.assertRaisesRegex(ValueError, "HTTP server must only redirect"):
            CHECK(config)

    def test_rejects_additional_https_route(self):
        config = copy.deepcopy(BASELINE)
        config["apps"]["http"]["servers"]["srv0"]["routes"].append({
            "handle": [{"handler": "static_response", "body": "shadow", "status_code": 200}]
        })
        with self.assertRaisesRegex(ValueError, "HTTPS /relay proxy"):
            CHECK(config)

    def test_rejects_extra_listener(self):
        config = copy.deepcopy(BASELINE)
        config["apps"]["http"]["servers"]["srv2"] = {"listen": [":8080"], "routes": []}
        with self.assertRaisesRegex(ValueError, "exactly one HTTPS"):
            CHECK(config)


if __name__ == "__main__":
    unittest.main()
