#!/usr/bin/env python3
"""Verify the deployed Caddyfile's exact HTTPS routing and HTTP redirect."""

import json
import sys


HOST = "relay.example.com"
UPSTREAM = "127.0.0.1:9340"
FALLBACK = "Noctweave Relay is online. Use HTTPS or WSS on /relay."


def check_config(config):
    try:
        servers = config["apps"]["http"]["servers"]
        if not isinstance(servers, dict) or len(servers) != 2:
            raise ValueError("expected exactly one HTTPS and one HTTP server")
        by_listener = {tuple(server["listen"]): server for server in servers.values()}
        if set(by_listener) != {(':443',), (':80',)}:
            raise ValueError("unexpected Caddy HTTP listeners")
        https, http = by_listener[(':443',)], by_listener[(':80',)]
        if set(https) != {"listen", "routes"} or set(http) != {"listen", "routes"}:
            raise ValueError("unexpected Caddy server behavior")

        group = https["routes"][0]["handle"][0]["routes"][0]["group"]
        if not isinstance(group, str) or not group:
            raise ValueError("HTTPS handle group is missing")

        expected_https = [{
            "match": [{"host": [HOST]}],
            "handle": [{"handler": "subroute", "routes": [
                {
                    "group": group,
                    "match": [{"path": ["/relay"]}],
                    "handle": [{"handler": "subroute", "routes": [
                        {"handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": UPSTREAM}]}]}
                    ]}],
                },
                {
                    "group": group,
                    "handle": [{"handler": "subroute", "routes": [
                        {"handle": [{"handler": "static_response", "body": FALLBACK, "status_code": 200}]}
                    ]}],
                },
            ]}],
            "terminal": True,
        }]
        if https["routes"] != expected_https:
            raise ValueError("HTTPS /relay proxy or fallback differs from the approved route")

        expected_http = [{
            "match": [{"host": [HOST]}],
            "handle": [{"handler": "subroute", "routes": [
                {"handle": [{
                    "handler": "static_response",
                    "headers": {"Location": ["https://relay.example.com{http.request.uri}"]},
                    "status_code": 308,
                }]}
            ]}],
            "terminal": True,
        }]
        if http["routes"] != expected_http:
            raise ValueError("HTTP server must only redirect to HTTPS")
    except (KeyError, IndexError, TypeError) as error:
        raise ValueError("malformed Caddy routing structure") from error


def main() -> int:
    try:
        check_config(json.load(sys.stdin))
    except (ValueError, json.JSONDecodeError) as error:
        print(f"Caddy relay route check failed: {error}", file=sys.stderr)
        return 1
    print("Caddy /relay proxies exactly and port 80 only redirects to HTTPS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
