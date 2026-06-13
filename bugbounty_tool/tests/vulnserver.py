"""Intentionally vulnerable HTTP server for self-test of bug-bounty-toolkit.

USE ONLY ON LOCALHOST. This file ships several vulnerabilities on purpose:
* Reflected XSS in /search?q=
* Error-based SQLi in /user?id= (sqlite3 with raw concat)
* Time-based command injection in /ping?host= (calls os.system "sleep")
* Path traversal in /read?file=
* Open redirect in /go?url=
* Insecure cookies (no HttpOnly/Secure/SameSite)
* Permissive CORS reflecting Origin with credentials
* Directory listing at /files/
* Backup file /index.php.bak
* No anti-CSRF token on /transfer POST
* xmlrpc.php endpoint simulating WordPress
* Default admin/admin login at /login
"""
from __future__ import annotations

import os
import re
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

DB_PATH = "/tmp/_bbt_vulndb.sqlite"


def _init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    con = sqlite3.connect(DB_PATH)
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    con.executemany("INSERT INTO users (name, email) VALUES (?, ?)",
                    [("alice", "a@x"), ("bob", "b@x"), ("carol", "c@x")])
    con.commit()
    con.close()


_init_db()

HOME_HTML = """<!doctype html><html><head><title>VulnApp</title></head><body>
<h1>Vulnerable test app</h1>
<ul>
  <li><a href="/search?q=test">Search</a></li>
  <li><a href="/user?id=1">User profile</a></li>
  <li><a href="/ping?host=127.0.0.1">Ping</a></li>
  <li><a href="/read?file=app.py">Reader</a></li>
  <li><a href="/go?url=https://example.com">Redirect</a></li>
  <li><a href="/login">Login</a></li>
  <li><a href="/files/">Files</a></li>
  <li><a href="/transfer">Transfer</a></li>
</ul>
<form action="/transfer" method="post">
  <input name="amount" value="10"/>
  <input name="to" value="alice"/>
  <button>Send</button>
</form>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs):  # silence
        return

    def _send(self, code: int, body: bytes, ctype: str = "text/html",
              extra_headers=None, cookies=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # Intentionally weak cookies on root
        if cookies:
            for c in cookies:
                self.send_header("Set-Cookie", c)
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, TRACE, OPTIONS")
        self.end_headers()

    def _cors_headers(self):
        origin = self.headers.get("Origin")
        if origin:
            return {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
        return {}

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query, keep_blank_values=True)

        if u.path == "/" or u.path == "/index.php":
            return self._send(200, HOME_HTML.encode(),
                              cookies=["SESSIONID=abc123; Path=/"])
        if u.path == "/index.php.bak":
            return self._send(200, b"<?php // SECRET_KEY = 'sekret-bbt'\n?>")
        if u.path == "/.git/HEAD":
            return self._send(200, b"ref: refs/heads/main\n", ctype="text/plain")
        if u.path == "/xmlrpc.php":
            return self._send(200, b"XML-RPC server accepts POST requests only.")
        if u.path == "/wp-json/wp/v2/users":
            return self._send(
                200,
                b'[{"id":1,"slug":"admin"},{"id":2,"slug":"bob"}]',
                ctype="application/json")
        if u.path == "/files/":
            body = b"<html><head><title>Index of /files/</title></head><body><h1>Index of /files/</h1><ul><li>a.txt</li><li>b.txt</li></ul></body></html>"
            return self._send(200, body)
        if u.path == "/search":
            q = (qs.get("q") or [""])[0]
            # Reflected XSS - q is echoed without escaping
            body = f"<html><body>You searched for: {q}</body></html>".encode()
            return self._send(200, body, extra_headers=self._cors_headers())
        if u.path == "/user":
            uid = (qs.get("id") or [""])[0]
            # SQL injection (raw concat into query)
            con = sqlite3.connect(DB_PATH)
            try:
                rows = con.execute(f"SELECT name, email FROM users WHERE id = {uid}").fetchall()
                body = f"<html><body>User: {rows}</body></html>".encode()
                return self._send(200, body)
            except Exception as exc:
                body = f"<html><body>SQLite error: {exc}</body></html>".encode()
                return self._send(500, body)
            finally:
                con.close()
        if u.path == "/ping":
            host = (qs.get("host") or [""])[0]
            # Command injection
            cmd = f"echo pinging {host}"
            os.system(cmd)
            body = f"<html><body>ran: {cmd}</body></html>".encode()
            return self._send(200, body)
        if u.path == "/read":
            f = (qs.get("file") or [""])[0]
            # Path traversal
            try:
                with open(f, "rb") as fh:
                    data = fh.read(2048)
                return self._send(200, data, ctype="text/plain")
            except Exception as exc:
                return self._send(404, str(exc).encode())
        if u.path == "/go":
            target = (qs.get("url") or ["/"])[0]
            # Open redirect
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
            return
        if u.path == "/login":
            return self._send(200, (
                "<html><body><form method='post' action='/login'>"
                "<input name='username'/><input type='password' name='password'/>"
                "<button>Login</button></form></body></html>"
            ).encode())
        return self._send(404, b"not found")

    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        params = parse_qs(raw.decode("utf-8", "ignore"), keep_blank_values=True)
        if u.path == "/login":
            user = (params.get("username") or [""])[0]
            pwd = (params.get("password") or [""])[0]
            # Default admin/admin
            if user == "admin" and pwd == "admin":
                self.send_response(302)
                self.send_header("Location", "/dashboard")
                self.send_header("Set-Cookie", "auth=admin")
                self.end_headers()
                return
            return self._send(200, b"<html><body>Invalid credentials</body></html>")
        if u.path == "/transfer":
            # No CSRF token
            body = f"<html><body>transferred {params}</body></html>".encode()
            return self._send(200, body)
        return self._send(404, b"not found")


def run(port: int = 9999):
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"vulnserver listening on http://127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    run()
