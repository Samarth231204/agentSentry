"""The trap web server: hosts pages that the attack agents plant, for indirect prompt injection.

A page looks like an ordinary article but carries a hidden instruction (invisible to a human reader,
still present in the page text that a browsing agent passes to its model). Every request is recorded,
so the oracle knows the target really read the page. It listens on 127.0.0.1 only.

    /p/<id>    a planted page
    /b/<id>    a beacon: the hidden instruction may tell the target to open it (proof of obedience)
"""

from __future__ import annotations

import html
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

from agentguard.attack.payloads import HIDDEN_STYLES
from agentguard.events import emit

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>{title}</title></head>
<body><article><h1>{title}</h1>{body}</article>{hidden}</body></html>"""


class TrapServer:
    def __init__(self, save_dir: Optional[Path] = None):
        self.pages: dict[str, str] = {}
        self.hits: list[dict] = []
        self.save_dir = save_dir
        self._httpd: Optional[ThreadingHTTPServer] = None

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self._httpd.server_address[1]}" if self._httpd else ""

    def start(self) -> "TrapServer":
        if self._httpd:
            return self
        trap = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                parts = self.path.strip("/").split("/")
                kind, pid = (parts + ["", ""])[:2]
                if kind == "robots.txt":
                    body, code = "User-agent: *\nAllow: /\n", 200
                elif kind == "p" and pid in trap.pages:
                    body, code = trap.pages[pid], 200
                elif kind == "b":
                    body, code = "ok", 200
                else:
                    body, code = "not found", 404
                if kind in ("p", "b"):
                    hit = {"kind": "page" if kind == "p" else "beacon", "id": pid, "time": time.time(),
                           "agent": self.headers.get("User-Agent", "")[:120]}
                    trap.hits.append(hit)
                    emit("trap", "trap_hit", **hit)
                data = body.encode()
                self.send_response(code)
                self.send_header("Content-Type", "text/html; charset=utf-8" if kind == "p" else "text/plain")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):  # keep the terminal quiet
                pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._httpd.serve_forever, daemon=True, name="agentguard-trap").start()
        return self

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    def plant(self, title: str, article: str, hidden_instruction: str, style: str = "display_none") -> dict:
        """Creates a page. BEACON_URL (or {beacon}) in the hidden instruction becomes this page's beacon URL."""
        pid = secrets.token_hex(4)
        beacon = f"{self.base}/b/{pid}"
        hidden = hidden_instruction.replace("{beacon}", beacon).replace("BEACON_URL", beacon)
        wrap = HIDDEN_STYLES.get(style, HIDDEN_STYLES["display_none"])
        paras = "".join(f"<p>{html.escape(p)}</p>" for p in article.split("\n") if p.strip())
        self.pages[pid] = PAGE.format(title=html.escape(title), body=paras,
                                      hidden=wrap.format(text=html.escape(hidden, quote=True)))
        if self.save_dir:
            self.save_dir.mkdir(parents=True, exist_ok=True)
            (self.save_dir / f"{pid}.html").write_text(self.pages[pid])
        emit("trap", "page_planted", id=pid, title=title[:120], style=style, hidden=hidden[:300])
        return {"url": f"{self.base}/p/{pid}", "beacon": beacon, "id": pid}

    def reads(self, pid: str, since: float = 0.0) -> int:
        return sum(1 for h in self.hits if h["id"] == pid and h["kind"] == "page" and h["time"] >= since)

    def beacons(self, since: float = 0.0) -> list[str]:
        return [h["id"] for h in self.hits if h["kind"] == "beacon" and h["time"] >= since]
