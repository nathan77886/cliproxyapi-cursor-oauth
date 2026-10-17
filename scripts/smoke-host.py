#!/usr/bin/env python3
"""Load the built plugin in an isolated CLIProxyAPI Docker container.

No user credentials are mounted. --poll-upstream makes one pending-auth request
to Cursor; it cannot create a key without someone authorizing the browser link.
"""
import argparse
import http.client
import json
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="eceasy/cli-proxy-api:v8.0.4")
    parser.add_argument("--poll-upstream", action="store_true")
    parser.add_argument("--proxy-url", default="")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if not (root / "dist/auth-cursor-oauth.so").exists():
        parser.error("build dist/auth-cursor-oauth.so first")
    name = "cursor-oauth-smoke-" + secrets.token_hex(4)
    management_key = secrets.token_urlsafe(24)
    with tempfile.TemporaryDirectory(prefix="cursor-oauth-smoke-") as tmp:
        config = Path(tmp) / "config.yaml"
        # JSON is valid YAML; this avoids a PyYAML dependency for smoke tests.
        config.write_text(json.dumps({
            "config-version": 8,
            "server": {"host": "", "port": 8317},
            "access": {"api-keys": [secrets.token_urlsafe(24)]},
            "management": {"allow-remote": True, "secret-key": management_key},
            "oauth": {"auth-dir": "/root/.cli-proxy-api"},
            "plugins": {"enabled": True, "dir": "/CLIProxyAPI/plugins", "configs": {
                "auth-cursor-oauth": {"enabled": True, "proxy-url": args.proxy_url},
            }},
        }))
        config.chmod(0o600)
        subprocess.run([
            "docker", "run", "--detach", "--rm", "--name", name,
            "--add-host", "host.docker.internal:host-gateway",
            "--publish", "127.0.0.1::8317",
            "--volume", f"{config}:/CLIProxyAPI/config.yaml",
            "--volume", f"{root / 'dist'}:/CLIProxyAPI/plugins/linux/amd64:ro",
            args.image,
        ], check=True, stdout=subprocess.DEVNULL)
        try:
            port = subprocess.check_output(["docker", "port", name, "8317"], text=True).strip()
            base = "http://" + port + "/v8/management"

            def request(path, method="GET"):
                req = urllib.request.Request(base + path, method=method, headers={
                    "Authorization": "Bearer " + management_key,
                })
                with urllib.request.urlopen(req, timeout=30) as response:
                    return json.load(response)

            for attempt in range(50):
                try:
                    plugins = request("/plugins").get("plugins", [])
                    break
                except (OSError, http.client.HTTPException):
                    if attempt == 49:
                        raise
                    time.sleep(0.2)
            plugin = next(p for p in plugins if p.get("id") == "auth-cursor-oauth")
            assert plugin.get("registered") and plugin.get("effective_enabled"), plugin
            assert plugin.get("supports_oauth") and plugin.get("oauth_provider") == "cursor", plugin
            login = request("/oauth/auth-url?provider=cursor")
            url = urllib.parse.urlparse(login["url"])
            query = urllib.parse.parse_qs(url.query)
            assert url.hostname == "cursor.com" and url.path == "/loginDeepControl", url.hostname
            assert "challenge" in query and "verifier" not in query
            result = {"registered": True, "supports_oauth": True, "browser_host": url.hostname}
            if args.poll_upstream:
                state = urllib.parse.quote(login["state"], safe="")
                status = request("/oauth/status?state=" + state)
                assert status.get("status") == "wait", status
                result["upstream_poll"] = "pending"
            print(json.dumps(result))
        except Exception:
            logs = subprocess.check_output(["docker", "logs", "--tail", "35", name], text=True, stderr=subprocess.STDOUT)
            print(logs)
            raise
        finally:
            subprocess.run(["docker", "rm", "--force", name], check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
