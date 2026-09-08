#!/usr/bin/env python3
"""Verify the image launcher's real HTTPS proxy and private-CA translation."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import tempfile
import threading
import time


class Origin(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<!doctype html><title>Private CA browser fixture</title><h1>Proxy and CA verified</h1>")


class Proxy(BaseHTTPRequestHandler):
    destinations = []
    allowed_destination = ""

    def log_message(self, *args):
        pass

    def do_CONNECT(self):
        if self.path != self.allowed_destination:
            self.send_error(403)
            return
        self.destinations.append(self.path)
        host, port = self.path.rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=5) as target:
            self.send_response(200, "Connection Established")
            self.end_headers()
            sockets = [self.connection, target]
            while True:
                ready, _, _ = select.select(sockets, [], [], 5)
                if not ready:
                    return
                for readable in ready:
                    data = readable.recv(65536)
                    if not data:
                        return
                    (target if readable is self.connection else self.connection).sendall(data)


def main():
    assert os.geteuid() != 0
    with tempfile.TemporaryDirectory(prefix="ambit-browser-proxy-") as temporary:
        root = Path(temporary)
        certificate, key = root / "ca.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "1", "-keyout", str(key), "-out", str(certificate)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(certificate, key)
        origin.socket = tls.wrap_socket(origin.socket, server_side=True)
        Proxy.allowed_destination = f"localhost:{origin.server_port}"
        proxy = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
        for server in (origin, proxy):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        observed = []
        try:
            for trusted in (False, True):
                session = f"proxy-{os.getpid()}-{'trusted' if trusted else 'untrusted'}"
                env = dict(os.environ)
                for name in ("AGENT_BROWSER_CA_CERT", "AGENT_BROWSER_PROXY", "SSL_CERT_FILE", "HTTP_PROXY", "http_proxy", "https_proxy"):
                    env.pop(name, None)
                env["HTTPS_PROXY"] = f"http://127.0.0.1:{proxy.server_port}"
                # Deliberately exercise the CONNECT proxy for this loopback fixture.
                env["AGENT_BROWSER_PROXY_BYPASS"] = "<-loopback>"
                if trusted:
                    env["SSL_CERT_FILE"] = str(certificate)
                base = ["agent-browser", "--session", session, "--json"]
                with (root / f"{session}.log").open("w") as log:
                    daemon = subprocess.Popen([*base, "daemon"], env=env, stdout=log, stderr=log)
                    try:
                        socket_path = Path(f"/workspace/.ambit/browser/sockets/{session}.sock")
                        deadline = time.monotonic() + 10
                        while not socket_path.exists() and daemon.poll() is None and time.monotonic() < deadline:
                            time.sleep(0.05)
                        assert socket_path.exists(), "Proxy fixture daemon failed to start"
                        result = subprocess.run([*base, "open", f"https://localhost:{origin.server_port}"], env=env, text=True, capture_output=True, timeout=45)
                        payload = json.loads(result.stdout)
                        if trusted:
                            assert result.returncode == 0 and payload["success"], payload
                            title = subprocess.run([*base, "get", "title"], env=env, text=True, capture_output=True, check=True, timeout=15)
                            assert json.loads(title.stdout)["data"]["title"] == "Private CA browser fixture"
                        else:
                            assert result.returncode != 0 and not payload["success"], payload
                            assert "CERT" in payload["error"], payload
                        observed.append({"customCa": trusted, "navigationSucceeded": payload["success"]})
                        subprocess.run([*base, "close"], env=env, capture_output=True, check=True, timeout=15)
                        daemon.wait(timeout=15)
                    finally:
                        if daemon.poll() is None:
                            daemon.terminate()
                            daemon.wait(timeout=15)
            assert len(Proxy.destinations) >= 2
            print(json.dumps({"schema": "ambit.browser-proxy-conformance/v1", "status": "passed", "observations": observed, "connectRequests": len(Proxy.destinations)}))
        finally:
            for server in (origin, proxy):
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    main()
