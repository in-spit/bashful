#!/usr/bin/env python3
# Requires: Python 3.10+, cryptography (pip install -r requirements.txt)

import argparse
import asyncio
import datetime
import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import ssl
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NAME_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
MID_RE = re.compile(r"^[0-9a-f]{32}$")

MAX_LINE = 256 * 1024
MAX_ENV = 64 * 1024
MAX_BLOB = 4096
MAX_INVITE = 128
MAX_ROOM_MEMBERS = 50
MAX_ROOMS_PER_ADMIN = 20
MAX_MAILBOX = 5000
MAX_ACK = 500
PUSH_BATCH = 200

AUTH_TIMEOUT = 120
IDLE_TIMEOUT = 300
SEND_TIMEOUT = 15

FAIL_LIMIT = 8
FAIL_WINDOW = 600
REGISTER_LIMIT = 20
REGISTER_WINDOW = 3600

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    name TEXT PRIMARY KEY,
    verifier TEXT NOT NULL,
    enc_pub TEXT NOT NULL,
    sig_pub TEXT NOT NULL,
    blob TEXT NOT NULL,
    created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rooms (
    name TEXT PRIMARY KEY,
    admin TEXT NOT NULL,
    version INTEGER NOT NULL,
    created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS members (
    room TEXT NOT NULL,
    user TEXT NOT NULL,
    joined INTEGER NOT NULL,
    PRIMARY KEY (room, user)
);
CREATE TABLE IF NOT EXISTS mailbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    to_user TEXT NOT NULL,
    kind TEXT NOT NULL,
    sender TEXT NOT NULL,
    room TEXT NOT NULL,
    mid TEXT NOT NULL,
    ts INTEGER NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS mailbox_to ON mailbox (to_user, id);
"""


def log(message):
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}", flush=True)


def group(hex_text):
    return " ".join(hex_text[i:i + 4] for i in range(0, len(hex_text), 4))


class Reject(Exception):
    def __init__(self, code, message, **extra):
        super().__init__(message)
        self.code = code
        self.message = message
        self.extra = extra


def canon(value, what="name"):
    if not isinstance(value, str):
        raise Reject("bad_request", f"{what} must be text")
    value = value.lower()
    if not NAME_RE.match(value):
        raise Reject("bad_name", f"{what} must be 1-32 characters: letters, digits, _ or -")
    return value


def hex64(value, what):
    if not isinstance(value, str) or not HEX64_RE.match(value):
        raise Reject("bad_request", f"{what} must be 64 hex characters")
    return value


def text_field(req, key, limit):
    value = req.get(key)
    if not isinstance(value, str) or not value or len(value) > limit:
        raise Reject("bad_request", f"{key} is missing or too long")
    return value


def mid_field(req):
    value = req.get("mid")
    if not isinstance(value, str) or not MID_RE.match(value):
        raise Reject("bad_request", "mid must be 32 hex characters")
    return value


def ts_field(req):
    value = req.get("ts")
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 2 ** 41:
        raise Reject("bad_request", "ts must be an integer timestamp")
    return value


def int_field(req, key):
    value = req.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise Reject("bad_request", f"{key} must be an integer")
    return value


def verifier_for(auth_hex):
    return hashlib.sha256(b"e2echat1-verifier|" + bytes.fromhex(auth_hex)).hexdigest()


def reply(req, **data):
    frame = {"t": "ok", **data}
    if isinstance(req.get("id"), (int, str)):
        frame["id"] = req["id"]
    return frame


def ensure_certificate(data_dir):
    cert_path = data_dir / "cert.pem"
    key_path = data_dir / "key.pem"
    if not (cert_path.exists() and key_path.exists()):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "e2e-chat server")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256())
        )
        key_bytes = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(key_bytes)
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return cert_path, key_path, fingerprint


class Session:
    def __init__(self, reader, writer, ip):
        self.reader = reader
        self.writer = writer
        self.ip = ip
        self.user = None
        self.sent_upto = 0
        self.closed = False
        self.write_lock = asyncio.Lock()
        self.push_lock = asyncio.Lock()

    async def send(self, frame):
        if self.closed:
            return
        data = json.dumps(frame, separators=(",", ":")).encode() + b"\n"
        async with self.write_lock:
            try:
                self.writer.write(data)
                await asyncio.wait_for(self.writer.drain(), SEND_TIMEOUT)
            except (OSError, asyncio.TimeoutError):
                self.close()

    def close(self):
        self.closed = True
        self.writer.close()


class Server:
    def __init__(self, db, invite):
        self.db = db
        self.invite = invite
        self.online = {}
        self.fails = defaultdict(deque)
        self.registrations = defaultdict(deque)
        self.tasks = set()
        self.open_commands = {"register", "login", "ping"}
        self.handlers = {
            "register": self.register,
            "login": self.login,
            "ping": self.ping,
            "keys": self.keys,
            "send": self.send_dm,
            "ack": self.ack,
            "rooms": self.rooms,
            "room_create": self.room_create,
            "room_add": self.room_add,
            "room_kick": self.room_kick,
            "room_leave": self.room_leave,
            "room_info": self.room_info,
            "room_send": self.room_send,
        }

    @contextmanager
    def tx(self):
        self.db.execute("BEGIN")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def spawn(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    def prune(self):
        now = time.time()
        for table, window in ((self.fails, FAIL_WINDOW), (self.registrations, REGISTER_WINDOW)):
            for key in list(table):
                queue = table[key]
                while queue and queue[0] < now - window:
                    queue.popleft()
                if not queue:
                    del table[key]

    async def prune_forever(self):
        while True:
            await asyncio.sleep(300)
            self.prune()

    def check_login_throttle(self, ip, user):
        now = time.time()
        for key in (("ip", ip), ("user", user)):
            queue = self.fails[key]
            while queue and queue[0] < now - FAIL_WINDOW:
                queue.popleft()
            if len(queue) >= FAIL_LIMIT:
                raise Reject("throttled", "too many failed logins, try again later")

    def record_failure(self, ip, user):
        now = time.time()
        self.fails[("ip", ip)].append(now)
        self.fails[("user", user)].append(now)

    def check_register_throttle(self, ip):
        now = time.time()
        queue = self.registrations[ip]
        while queue and queue[0] < now - REGISTER_WINDOW:
            queue.popleft()
        if len(queue) >= REGISTER_LIMIT:
            raise Reject("throttled", "too many registrations from this address, try again later")
        queue.append(now)

    def user_exists(self, user):
        return self.db.execute("SELECT 1 FROM users WHERE name=?", (user,)).fetchone() is not None

    def require_user(self, user):
        if not self.user_exists(user):
            raise Reject("no_such_user", "no such user")

    def check_capacity(self, recipients):
        for user in set(recipients):
            count = self.db.execute("SELECT COUNT(*) FROM mailbox WHERE to_user=?", (user,)).fetchone()[0]
            if count >= MAX_MAILBOX:
                raise Reject("mailbox_full", f"the mailbox of {user} is full")

    def insert_mail(self, rows):
        with self.tx():
            for row in rows:
                self.db.execute(
                    "INSERT INTO mailbox (to_user, kind, sender, room, mid, ts, payload) VALUES (?,?,?,?,?,?,?)",
                    (row["to"], row["kind"], row["sender"], row["room"], row["mid"], row["ts"], row["payload"]),
                )

    def event_rows(self, recipients, room, by, payload):
        text = json.dumps(payload, separators=(",", ":"))
        now = int(time.time())
        return [
            {"to": user, "kind": "event", "sender": by, "room": room, "mid": "0" * 32, "ts": now, "payload": text}
            for user in recipients
        ]

    def notify(self, users):
        for user in set(users):
            session = self.online.get(user)
            if session:
                self.spawn(self.push_pending(session))

    async def push_pending(self, session):
        async with session.push_lock:
            while not session.closed and session.user:
                rows = self.db.execute(
                    "SELECT id, kind, sender, room, mid, ts, payload FROM mailbox "
                    "WHERE to_user=? AND id>? ORDER BY id LIMIT ?",
                    (session.user, session.sent_upto, PUSH_BATCH),
                ).fetchall()
                if not rows:
                    return
                for mbid, kind, sender, room, mid, ts, payload in rows:
                    if kind == "event":
                        frame = {"t": "event", "mbid": mbid, **json.loads(payload)}
                    else:
                        frame = {"t": "msg", "mbid": mbid, "kind": kind, "from": sender,
                                 "room": room, "mid": mid, "ts": ts, "env": payload}
                    await session.send(frame)
                    session.sent_upto = mbid

    async def attach(self, session, user):
        old = self.online.get(user)
        if old is not None and old is not session:
            await old.send({"t": "err", "code": "kicked", "msg": "you logged in from somewhere else"})
            old.close()
        session.user = user
        session.sent_upto = 0
        self.online[user] = session

    async def serve(self, reader, writer):
        peer = writer.get_extra_info("peername")
        session = Session(reader, writer, peer[0] if peer else "unknown")
        try:
            await session.send({"t": "hello", "v": 1, "invite": bool(self.invite)})
            while not session.closed:
                timeout = IDLE_TIMEOUT if session.user else AUTH_TIMEOUT
                line = await asyncio.wait_for(reader.readline(), timeout)
                if not line:
                    break
                await self.dispatch(session, line)
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            if session.user and self.online.get(session.user) is session:
                del self.online[session.user]
                log(f"{session.user} disconnected")
            session.close()

    async def dispatch(self, session, line):
        request_id = None
        try:
            req = json.loads(line)
            if not isinstance(req, dict):
                raise ValueError("not an object")
            if isinstance(req.get("id"), (int, str)):
                request_id = req["id"]
            kind = req.get("t")
            handler = self.handlers.get(kind) if isinstance(kind, str) else None
            if handler is None:
                raise Reject("bad_request", "unknown command")
            if session.user is None and kind not in self.open_commands:
                raise Reject("auth_required", "log in first")
            await handler(session, req)
        except Reject as rejection:
            frame = {"t": "err", "code": rejection.code, "msg": rejection.message, **rejection.extra}
            if request_id is not None:
                frame["id"] = request_id
            await session.send(frame)
        except ValueError:
            await session.send({"t": "err", "code": "bad_request", "msg": "malformed frame"})
        except Exception as error:
            log(f"internal error: {type(error).__name__}: {error}")
            frame = {"t": "err", "code": "internal", "msg": "server error"}
            if request_id is not None:
                frame["id"] = request_id
            await session.send(frame)

    async def ping(self, session, req):
        frame = {"t": "pong"}
        if isinstance(req.get("id"), (int, str)):
            frame["id"] = req["id"]
        await session.send(frame)

    async def register(self, session, req):
        if session.user:
            raise Reject("already_logged_in", "already logged in")
        self.check_register_throttle(session.ip)
        if self.invite:
            given = req.get("invite")
            if not isinstance(given, str) or len(given) > MAX_INVITE or not hmac.compare_digest(given, self.invite):
                raise Reject("invite_required", "a valid invite code is required")
        user = canon(req.get("user"), "username")
        auth = hex64(req.get("auth"), "auth")
        enc_pub = hex64(req.get("enc"), "enc")
        sig_pub = hex64(req.get("sig"), "sig")
        blob = text_field(req, "blob", MAX_BLOB)
        try:
            with self.tx():
                self.db.execute(
                    "INSERT INTO users (name, verifier, enc_pub, sig_pub, blob, created) VALUES (?,?,?,?,?,?)",
                    (user, verifier_for(auth), enc_pub, sig_pub, blob, int(time.time())),
                )
        except sqlite3.IntegrityError:
            raise Reject("exists", "that username is taken")
        await self.attach(session, user)
        log(f"{user} registered from {session.ip}")
        await session.send(reply(req, user=user))

    async def login(self, session, req):
        if session.user:
            raise Reject("already_logged_in", "already logged in")
        raw_user = req.get("user")
        user = raw_user.lower()[:64] if isinstance(raw_user, str) else ""
        self.check_login_throttle(session.ip, user)
        auth = req.get("auth")
        auth_ok = isinstance(auth, str) and HEX64_RE.match(auth) is not None
        row = None
        if auth_ok and NAME_RE.match(user):
            row = self.db.execute(
                "SELECT verifier, enc_pub, sig_pub, blob FROM users WHERE name=?", (user,)
            ).fetchone()
        expected = row[0] if row else "0" * 64
        offered = verifier_for(auth if auth_ok else "0" * 64)
        if row is None or not hmac.compare_digest(offered, expected):
            self.record_failure(session.ip, user)
            log(f"failed login for '{user[:32]}' from {session.ip}")
            raise Reject("bad_credentials", "wrong username or password")
        await self.attach(session, user)
        log(f"{user} logged in from {session.ip}")
        await session.send(reply(req, user=user, enc=row[1], sig=row[2], blob=row[3]))
        await self.push_pending(session)

    async def keys(self, session, req):
        user = canon(req.get("user"), "username")
        row = self.db.execute("SELECT enc_pub, sig_pub FROM users WHERE name=?", (user,)).fetchone()
        if row is None:
            raise Reject("no_such_user", "no such user")
        await session.send(reply(req, user=user, enc=row[0], sig=row[1]))

    async def send_dm(self, session, req):
        target = canon(req.get("to"), "recipient")
        mid = mid_field(req)
        ts = ts_field(req)
        env = text_field(req, "env", MAX_ENV)
        self.require_user(target)
        self.check_capacity([target])
        self.insert_mail([{"to": target, "kind": "dm", "sender": session.user, "room": "",
                           "mid": mid, "ts": ts, "payload": env}])
        await session.send(reply(req))
        self.notify([target])

    async def ack(self, session, req):
        ids = req.get("ids")
        valid = isinstance(ids, list) and len(ids) <= MAX_ACK and all(
            isinstance(i, int) and not isinstance(i, bool) for i in ids
        )
        if not valid:
            raise Reject("bad_request", "ids must be a short list of integers")
        if ids:
            marks = ",".join("?" * len(ids))
            self.db.execute(f"DELETE FROM mailbox WHERE to_user=? AND id IN ({marks})", [session.user, *ids])
        await session.send(reply(req))

    def room_state(self, room):
        row = self.db.execute("SELECT admin, version FROM rooms WHERE name=?", (room,)).fetchone()
        if row is None:
            raise Reject("no_such_room", "no such room")
        members = [r[0] for r in self.db.execute(
            "SELECT user FROM members WHERE room=? ORDER BY joined, rowid", (room,))]
        return row[0], row[1], members

    def member_state(self, session, room):
        admin, version, members = self.room_state(room)
        if session.user not in members:
            raise Reject("no_such_room", "no such room")
        return admin, version, members

    def drop_member(self, room, user):
        self.db.execute("DELETE FROM members WHERE room=? AND user=?", (room, user))
        admin, version = self.db.execute("SELECT admin, version FROM rooms WHERE name=?", (room,)).fetchone()
        remaining = [r[0] for r in self.db.execute(
            "SELECT user FROM members WHERE room=? ORDER BY joined, rowid", (room,))]
        if not remaining:
            self.db.execute("DELETE FROM rooms WHERE name=?", (room,))
            return remaining, admin, version + 1
        if admin == user:
            admin = remaining[0]
        version += 1
        self.db.execute("UPDATE rooms SET admin=?, version=? WHERE name=?", (admin, version, room))
        return remaining, admin, version

    async def room_create(self, session, req):
        room = canon(req.get("room"), "room")
        owned = self.db.execute("SELECT COUNT(*) FROM rooms WHERE admin=?", (session.user,)).fetchone()[0]
        if owned >= MAX_ROOMS_PER_ADMIN:
            raise Reject("limit", "you administer too many rooms")
        now = int(time.time())
        try:
            with self.tx():
                self.db.execute("INSERT INTO rooms (name, admin, version, created) VALUES (?,?,?,?)",
                                (room, session.user, 1, now))
                self.db.execute("INSERT INTO members (room, user, joined) VALUES (?,?,?)",
                                (room, session.user, now))
        except sqlite3.IntegrityError:
            raise Reject("exists", "that room name is taken")
        log(f"{session.user} created room #{room}")
        await session.send(reply(req, room=room, version=1))

    async def room_add(self, session, req):
        room = canon(req.get("room"), "room")
        target = canon(req.get("user"), "username")
        admin, version, members = self.member_state(session, room)
        if admin != session.user:
            raise Reject("not_admin", "only the room admin can add people")
        self.require_user(target)
        if target in members:
            raise Reject("already_member", f"{target} is already in the room")
        if len(members) >= MAX_ROOM_MEMBERS:
            raise Reject("room_full", "the room is full")
        with self.tx():
            self.db.execute("INSERT INTO members (room, user, joined) VALUES (?,?,?)",
                            (room, target, int(time.time())))
            self.db.execute("UPDATE rooms SET version=version+1 WHERE name=?", (room,))
        version += 1
        everyone = members + [target]
        payload = {"kind": "member_added", "room": room, "user": target, "by": session.user,
                   "version": version, "admin": admin}
        self.insert_mail(self.event_rows(everyone, room, session.user, payload))
        await session.send(reply(req, room=room, version=version))
        self.notify(everyone)

    async def room_kick(self, session, req):
        room = canon(req.get("room"), "room")
        target = canon(req.get("user"), "username")
        admin, version, members = self.member_state(session, room)
        if admin != session.user:
            raise Reject("not_admin", "only the room admin can remove people")
        if target == session.user:
            raise Reject("bad_request", "use leave to remove yourself")
        if target not in members:
            raise Reject("not_member", f"{target} is not in the room")
        with self.tx():
            remaining, admin, version = self.drop_member(room, target)
        payload = {"kind": "member_removed", "room": room, "user": target, "by": session.user,
                   "reason": "kicked", "version": version, "admin": admin}
        self.insert_mail(self.event_rows(remaining + [target], room, session.user, payload))
        await session.send(reply(req, room=room, version=version))
        self.notify(remaining + [target])

    async def room_leave(self, session, req):
        room = canon(req.get("room"), "room")
        self.member_state(session, room)
        with self.tx():
            remaining, admin, version = self.drop_member(room, session.user)
        payload = {"kind": "member_removed", "room": room, "user": session.user, "by": session.user,
                   "reason": "left", "version": version, "admin": admin}
        self.insert_mail(self.event_rows(remaining, room, session.user, payload))
        await session.send(reply(req, room=room))
        self.notify(remaining)

    async def room_info(self, session, req):
        room = canon(req.get("room"), "room")
        admin, version, _ = self.member_state(session, room)
        rows = self.db.execute(
            "SELECT u.name, u.enc_pub, u.sig_pub FROM members m JOIN users u ON u.name = m.user "
            "WHERE m.room=? ORDER BY m.joined, m.rowid", (room,)).fetchall()
        members = [{"user": r[0], "enc": r[1], "sig": r[2]} for r in rows]
        await session.send(reply(req, room=room, admin=admin, version=version, members=members))

    async def rooms(self, session, req):
        rows = self.db.execute(
            "SELECT r.name, r.admin, r.version FROM members m JOIN rooms r ON r.name = m.room "
            "WHERE m.user=? ORDER BY r.name", (session.user,)).fetchall()
        await session.send(reply(req, rooms=[{"room": r[0], "admin": r[1], "version": r[2]} for r in rows]))

    async def room_send(self, session, req):
        room = canon(req.get("room"), "room")
        mid = mid_field(req)
        ts = ts_field(req)
        offered_version = int_field(req, "version")
        envs = req.get("envs")
        if not isinstance(envs, dict):
            raise Reject("bad_request", "envs must be an object")
        admin, version, members = self.member_state(session, room)
        if offered_version != version:
            raise Reject("stale", "the member list changed, refresh it and try again", version=version)
        others = set(members) - {session.user}
        if set(envs) != others:
            raise Reject("bad_recipients", "a ciphertext is needed for exactly every other member")
        for env in envs.values():
            if not isinstance(env, str) or not env or len(env) > MAX_ENV:
                raise Reject("bad_request", "ciphertext missing or too long")
        self.check_capacity(others)
        rows = [{"to": user, "kind": "room", "sender": session.user, "room": room,
                 "mid": mid, "ts": ts, "payload": env} for user, env in envs.items()]
        self.insert_mail(rows)
        await session.send(reply(req))
        self.notify(others)


async def run(args):
    data_dir = Path(args.data)
    data_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(data_dir, 0o700)
    except OSError:
        pass
    cert_path, key_path, fingerprint = ensure_certificate(data_dir)

    db = sqlite3.connect(data_dir / "server.db", isolation_level=None)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.executescript(SCHEMA)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)

    server = Server(db, args.invite_code)
    listener = await asyncio.start_server(
        server.serve, args.host, args.port, ssl=context, limit=MAX_LINE, ssl_handshake_timeout=10
    )
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)
    server.spawn(server.prune_forever())

    log(f"listening on {args.host}:{args.port}")
    log(f"certificate fingerprint (SHA-256): {group(fingerprint)}")
    log("registration: " + ("invite code required" if args.invite_code else "open to anyone"))
    log(f"data directory: {data_dir.resolve()}")
    async with listener:
        await listener.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="End-to-end encrypted chat relay server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7443)
    parser.add_argument("--data", default="chat-data")
    parser.add_argument("--invite-code", default=None, help="require this code to register")
    args = parser.parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
