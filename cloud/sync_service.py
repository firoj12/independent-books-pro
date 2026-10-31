"""
Independent Books Cloud Sync Foundation (prototype).

This service is a separate sync gateway, not yet wired into the existing UI.
Run behind HTTPS in production. Do not expose the built-in HTTP server directly
to the public internet.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

DB_PATH = Path(os.environ.get("IB_CLOUD_DB", "cloud-data/cloud.sqlite3"))
TOKEN_SECRET = os.environ.get("IB_TOKEN_SECRET", "")
BOOTSTRAP_KEY = os.environ.get("IB_BOOTSTRAP_KEY", "")
TOKEN_TTL = int(os.environ.get("IB_TOKEN_TTL_SECONDS", "28800"))
MAX_BODY = 2 * 1024 * 1024
ROLES = {"admin", "accountant", "viewer"}
WRITE_ROLES = {"admin", "accountant"}


def _db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("""
      CREATE TABLE IF NOT EXISTS users(
        id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
        password_salt TEXT NOT NULL, password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','accountant','viewer')),
        active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sync_ops(
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        op_id TEXT UNIQUE NOT NULL, company_id TEXT NOT NULL,
        actor TEXT NOT NULL, op_type TEXT NOT NULL, payload TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS sync_ops_company_seq
        ON sync_ops(company_id, seq);
      CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL,
        action TEXT NOT NULL, company_id TEXT, created_at INTEGER NOT NULL,
        detail TEXT NOT NULL DEFAULT '{}'
      );
    """)
    return conn


def _password_hash(password: str, salt: bytes | None = None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return salt.hex(), digest.hex()


def _verify_password(password, salt_hex, hash_hex):
    try:
        _, got = _password_hash(password, bytes.fromhex(salt_hex))
        return hmac.compare_digest(got, hash_hex)
    except (ValueError, TypeError):
        return False


def _token(username, role, user_id):
    if not TOKEN_SECRET:
        raise RuntimeError("IB_TOKEN_SECRET must be configured before starting")
    expiry = int(time.time()) + TOKEN_TTL
    body = json.dumps({"sub": username, "role": role, "uid": user_id, "exp": expiry},
                      separators=(",", ":"), sort_keys=True).encode()
    import base64
    part = base64.urlsafe_b64encode(body).rstrip(b"=").decode()
    sig = hmac.new(TOKEN_SECRET.encode(), part.encode(), hashlib.sha256).digest()
    return part + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


def _decode_token(token):
    import base64
    try:
        part, signature = token.split(".", 1)
        expected = base64.urlsafe_b64encode(
            hmac.new(TOKEN_SECRET.encode(), part.encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        if not hmac.compare_digest(signature, expected):
            return None
        padded = part + "=" * (-len(part) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded))
        if int(data["exp"]) < int(time.time()):
            return None
        return data
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


class SyncHandler(BaseHTTPRequestHandler):
    server_version = "IndependentBooksSync/0.1"

    def log_message(self, *_):
        # Do not log request bodies or credentials.
        pass

    def _send(self, status, obj):
        raw = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length < 1 or length > MAX_BODY:
            raise ValueError("Request body must be between 1 byte and 2 MiB")
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _user(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        claims = _decode_token(auth[7:])
        if not claims:
            return None
        with _db() as db:
            row = db.execute("SELECT active, role FROM users WHERE id=?",
                             (claims["uid"],)).fetchone()
        if not row or not row["active"] or row["role"] != claims["role"]:
            return None
        return claims

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            return self._send(200, {"status": "ok", "service": "Independent Books Sync"})
        user = self._user()
        if not user:
            return self._send(401, {"error": "Authentication required"})
        if path == "/api/me":
            return self._send(200, {"username": user["sub"], "role": user["role"]})
        if path == "/api/sync/pull":
            from urllib.parse import parse_qs
            query = parse_qs(urlparse(self.path).query)
            company = (query.get("company_id") or [""])[0].strip()
            try:
                cursor = max(0, int((query.get("after") or ["0"])[0]))
            except ValueError:
                return self._send(400, {"error": "after must be a non-negative integer"})
            if not company:
                return self._send(400, {"error": "company_id is required"})
            with _db() as db:
                rows = db.execute(
                    "SELECT seq,op_id,actor,op_type,payload,created_at FROM sync_ops "
                    "WHERE company_id=? AND seq>? ORDER BY seq LIMIT 500",
                    (company, cursor)).fetchall()
                db.execute("INSERT INTO audit_log(actor,action,company_id,created_at,detail) "
                           "VALUES(?,?,?,?,?)",
                           (user["sub"], "sync.pull", company, int(time.time()),
                            json.dumps({"after": cursor, "count": len(rows)})))
            ops = [{"seq": r["seq"], "op_id": r["op_id"], "actor": r["actor"],
                    "type": r["op_type"], "payload": json.loads(r["payload"]),
                    "created_at": r["created_at"]} for r in rows]
            return self._send(200, {"operations": ops,
                                    "next_cursor": ops[-1]["seq"] if ops else cursor})
        return self._send(404, {"error": "Not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self._body()
            if path == "/api/bootstrap":
                # One-time first-admin creation, protected by a secret set by the owner.
                if not BOOTSTRAP_KEY or not hmac.compare_digest(
                        str(body.get("bootstrap_key", "")), BOOTSTRAP_KEY):
                    return self._send(403, {"error": "Invalid bootstrap key"})
                username = str(body.get("username", "")).strip().lower()
                password = str(body.get("password", ""))
                if len(username) < 3 or len(password) < 12:
                    return self._send(400, {"error": "Username must be 3+ chars and password 12+ chars"})
                with _db() as db:
                    if db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                        return self._send(409, {"error": "Bootstrap is already completed"})
                    salt, digest = _password_hash(password)
                    uid = secrets.token_hex(16)
                    db.execute("INSERT INTO users(id,username,password_salt,password_hash,role,created_at) "
                               "VALUES(?,?,?,?,?,?)",
                               (uid, username, salt, digest, "admin", int(time.time())))
                return self._send(201, {"status": "admin_created"})
            if path == "/api/login":
                username = str(body.get("username", "")).strip().lower()
                password = str(body.get("password", ""))
                with _db() as db:
                    row = db.execute("SELECT * FROM users WHERE username=? AND active=1",
                                     (username,)).fetchone()
                if not row or not _verify_password(password, row["password_salt"], row["password_hash"]):
                    return self._send(401, {"error": "Invalid username or password"})
                token = _token(row["username"], row["role"], row["id"])
                with _db() as db:
                    db.execute("INSERT INTO audit_log(actor,action,created_at,detail) VALUES(?,?,?,?)",
                               (username, "auth.login", int(time.time()), "{}"))
                return self._send(200, {"access_token": token, "token_type": "Bearer",
                                        "expires_in": TOKEN_TTL, "role": row["role"]})
            user = self._user()
            if not user:
                return self._send(401, {"error": "Authentication required"})
            if path == "/api/users":
                if user["role"] != "admin":
                    return self._send(403, {"error": "Admin role required"})
                username = str(body.get("username", "")).strip().lower()
                password = str(body.get("password", ""))
                role = str(body.get("role", ""))
                if len(username) < 3 or len(password) < 12 or role not in ROLES:
                    return self._send(400, {"error": "Username 3+ chars, password 12+ chars and valid role required"})
                salt, digest = _password_hash(password)
                uid = secrets.token_hex(16)
                with _db() as db:
                    db.execute("INSERT INTO users(id,username,password_salt,password_hash,role,created_at) "
                               "VALUES(?,?,?,?,?,?)",
                               (uid, username, salt, digest, role, int(time.time())))
                    db.execute("INSERT INTO audit_log(actor,action,created_at,detail) VALUES(?,?,?,?)",
                               (user["sub"], "user.create", int(time.time()),
                                json.dumps({"username": username, "role": role})))
                return self._send(201, {"status": "user_created", "username": username, "role": role})
            if path == "/api/sync/push":
                if user["role"] not in WRITE_ROLES:
                    return self._send(403, {"error": "Viewer role is read-only"})
                company = str(body.get("company_id", "")).strip()
                ops = body.get("operations")
                if not company or not isinstance(ops, list) or not 1 <= len(ops) <= 100:
                    return self._send(400, {"error": "company_id and 1-100 operations are required"})
                accepted, duplicates = [], []
                with _db() as db:
                    for op in ops:
                        op_id = str(op.get("op_id", "")).strip()
                        op_type = str(op.get("type", "")).strip()
                        payload = op.get("payload")
                        if not op_id or len(op_id) > 100 or not op_type or len(op_type) > 80:
                            return self._send(400, {"error": "Each operation needs op_id and type"})
                        if not isinstance(payload, dict):
                            return self._send(400, {"error": "Operation payload must be an object"})
                        existing = db.execute("SELECT seq FROM sync_ops WHERE op_id=?", (op_id,)).fetchone()
                        if existing:
                            duplicates.append(op_id)
                            continue
                        cur = db.execute(
                            "INSERT INTO sync_ops(op_id,company_id,actor,op_type,payload,created_at) "
                            "VALUES(?,?,?,?,?,?)",
                            (op_id, company, user["sub"], op_type,
                             json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                             int(time.time())))
                        accepted.append({"op_id": op_id, "seq": cur.lastrowid})
                    db.execute("INSERT INTO audit_log(actor,action,company_id,created_at,detail) VALUES(?,?,?,?,?)",
                               (user["sub"], "sync.push", company, int(time.time()),
                                json.dumps({"accepted": len(accepted), "duplicates": len(duplicates)})))
                return self._send(200, {"accepted": accepted, "duplicates": duplicates})
            return self._send(404, {"error": "Not found"})
        except json.JSONDecodeError:
            return self._send(400, {"error": "Invalid JSON"})
        except sqlite3.IntegrityError:
            return self._send(409, {"error": "Username already exists or conflicting operation"})
        except Exception:
            # Never return internal exception details to an unauthenticated client.
            return self._send(500, {"error": "Request could not be completed"})

    def do_DELETE(self):
        user = self._user()
        if not user:
            return self._send(401, {"error": "Authentication required"})
        if user["role"] != "admin":
            return self._send(403, {"error": "Admin role required"})
        return self._send(405, {"error": "Use the admin user-management endpoint; direct deletes are disabled"})


def main():
    if not TOKEN_SECRET or len(TOKEN_SECRET) < 32:
        raise SystemExit("Set IB_TOKEN_SECRET to a random secret of at least 32 characters.")
    if not BOOTSTRAP_KEY or len(BOOTSTRAP_KEY) < 20:
        raise SystemExit("Set IB_BOOTSTRAP_KEY to a one-time bootstrap secret of at least 20 characters.")
    host = os.environ.get("IB_BIND_HOST", "127.0.0.1")
    port = int(os.environ.get("IB_BIND_PORT", "8765"))
    server = ThreadingHTTPServer((host, port), SyncHandler)
    print(f"Sync prototype listening on {host}:{port}. Use HTTPS reverse proxy before remote access.")
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
