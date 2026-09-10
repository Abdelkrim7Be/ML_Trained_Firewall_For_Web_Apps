"""End to end fixtures: a real server process, a real origin, real sockets.

The unit and integration suites use Starlette's TestClient, which drives the app
in process. That is fast and it catches most things, but it does not exercise
uvicorn, the event loop under concurrency, server sent events over a live socket,
or what survives a restart. This suite does.
"""

from __future__ import annotations

import os
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import httpx
import pytest

REPO = Path(__file__).resolve().parents[2]
PYTHON = str(REPO / ".venv" / "bin" / "python")
BOOT_TIMEOUT = 120.0


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Origin(BaseHTTPRequestHandler):
    """The application being protected. Records everything it is asked for."""

    received: ClassVar[list[dict]] = []

    def _respond(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        _Origin.received.append({
            "path": self.path, "method": self.command, "body": body,
            "headers": dict(self.headers),
        })
        if self.path.startswith("/slow"):
            time.sleep(0.4)
        payload = b'{"origin":"reached"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _respond

    def log_message(self, *_args):
        pass


class Origin:
    def __init__(self):
        self.port = free_port()
        self._server = HTTPServer(("127.0.0.1", self.port), _Origin)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._server.shutdown()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def received(self) -> list[dict]:
        return _Origin.received

    def clear(self):
        _Origin.received.clear()


class Waf:
    """The firewall, as an actual subprocess."""

    def __init__(self, origin_url: str, db_path: Path, **env):
        self.port = free_port()
        self.db_path = db_path
        self.env = {
            **os.environ,
            "WAF_UPSTREAM": origin_url,
            "WAF_HOST": "127.0.0.1",
            "WAF_PORT": str(self.port),
            "WAF_DB_PATH": str(db_path),
            "WAF_FEEDBACK_PATH": str(db_path.parent / "feedback.jsonl"),
            "WAF_MODE": "block",
            "WAF_SCORING_BUDGET_MS": "60000",
            "PYTHONPATH": str(REPO / "src"),
            **{k: str(v) for k, v in env.items()},
        }
        self.proc: subprocess.Popen | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        self.proc = subprocess.Popen(
            [PYTHON, "-m", "mlwaf.waf.app"],
            cwd=REPO, env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        deadline = time.time() + BOOT_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"waf died on boot:\n{self.proc.stdout.read()}")
            try:
                r = httpx.get(f"{self.url}/_waf/readyz", timeout=2.0)
                if r.status_code == 200:
                    return self
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
        raise TimeoutError("waf never became ready")

    def stop(self, graceful: bool = True):
        if self.proc is None:
            return
        if graceful:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=25)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        else:
            self.proc.kill()
        self.proc = None


@pytest.fixture(scope="session")
def model_present():
    if not (REPO / "models" / "model.joblib").exists():
        pytest.skip("models/model.joblib missing, run `make train` first")


@pytest.fixture(scope="session")
def origin(model_present):
    o = Origin().start()
    yield o
    o.stop()


@pytest.fixture(scope="module")
def waf(origin, tmp_path_factory):
    db = tmp_path_factory.mktemp("waf") / "waf.db"
    w = Waf(origin.url, db).start()
    yield w
    w.stop()


@pytest.fixture
def client(waf, origin):
    origin.clear()
    with httpx.Client(base_url=waf.url, timeout=30.0) as c:
        yield c
