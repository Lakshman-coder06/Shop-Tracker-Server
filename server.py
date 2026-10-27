"""
server.py  -  Thalapathi Studio SHOP SERVER
=============================================
Run this on ONE computer (the shop PC, or a cloud host). Every copy of the
Thalapathi Studio app - Worker 1's PC, Worker 2's PC, the Admin's PC - then
connects to it, so everyone reads and writes the SAME data.

    python server.py

What it does
  * Holds the one real database (data/shop_tracker.db).
  * Logs people in (name + PIN) and hands out a signed, expiring token.
  * Checks EVERY request against policy.py (Workers only see their own
    data, only Admin can change rates/workers, nobody can record a sale
    under someone else's name).
  * Takes automatic backups of the database.

Settings (all optional - the defaults suit a shop PC). Set as environment
variables:
    PORT / SHOPTRACKER_PORT   port to listen on            (default 8000)
    SHOPTRACKER_HOST          address to listen on         (default 0.0.0.0)
    SHOPTRACKER_DB            full path of the database file
    SHOPTRACKER_SECRET        token-signing secret (else one is generated
                              and saved next to the database)
    SHOP_TIMEZONE             e.g. Asia/Kolkata            (default Asia/Kolkata)
    SHOPTRACKER_TOKEN_HOURS   how long a login lasts       (default 14)
    SHOPTRACKER_BACKUP_HOURS  hours between backups        (default 12)
    SHOPTRACKER_BACKUP_KEEP   how many backups to keep     (default 30)
    SHOPTRACKER_TRUST_PROXY   set to 1 ONLY behind a cloud proxy/load
                              balancer, so login throttling sees real IPs
"""

import base64
import hashlib
import hmac
import inspect
import json
import logging
import os
import secrets
import socket
import sqlite3
import sys
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

# ---- Timezone MUST be set before shop_db is imported or used ----------
# "Today's sales" is computed with the server's local clock, so the server
# has to run on Indian time even if it is hosted in another country.
SHOP_TIMEZONE = os.environ.get("SHOP_TIMEZONE", "Asia/Kolkata")
if hasattr(time, "tzset"):  # Linux / macOS / cloud containers
    os.environ["TZ"] = SHOP_TIMEZONE
    time.tzset()
# (On Windows the server uses the PC's own clock/timezone - make sure the
#  PC is set to India Standard Time.)

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

import shop_db
import policy

API_VERSION = 1
SERVER_VERSION = "1.0"
APP_NAME = "Thalapathi Studio"

DATA_DIR = os.path.dirname(os.path.abspath(shop_db.DB_FILE))
TOKEN_HOURS = float(os.environ.get("SHOPTRACKER_TOKEN_HOURS", "14"))
BACKUP_HOURS = float(os.environ.get("SHOPTRACKER_BACKUP_HOURS", "12"))
BACKUP_KEEP = int(os.environ.get("SHOPTRACKER_BACKUP_KEEP", "30"))
TRUST_PROXY = os.environ.get("SHOPTRACKER_TRUST_PROXY") == "1"
BACKUP_DIR = os.environ.get("SHOPTRACKER_BACKUP_DIR") or os.path.join(DATA_DIR, "backups")

# ---------------------------------------------------------------------
# logging (never logs PINs or request bodies)
# ---------------------------------------------------------------------
os.makedirs(os.path.join(DATA_DIR, "logs"), exist_ok=True)
log = logging.getLogger("shopserver")
log.setLevel(logging.INFO)
_fmt = logging.Formatter("%(asctime)s  %(levelname)s  %(message)s")
_sh = logging.StreamHandler(sys.stdout)
_sh.setFormatter(_fmt)
log.addHandler(_sh)
_fh = RotatingFileHandler(os.path.join(DATA_DIR, "logs", "server.log"), maxBytes=1_000_000, backupCount=3, encoding="utf-8")
_fh.setFormatter(_fmt)
log.addHandler(_fh)

# One lock around every database operation: a shop's traffic is tiny, and
# this guarantees two PCs saving a job at the same instant can never
# collide (e.g. get the same JOB-...-0001 code).
DB_LOCK = threading.RLock()


# ---------------------------------------------------------------------
# signing secret + tokens (stateless: survive a server restart)
# ---------------------------------------------------------------------

def _load_secret() -> bytes:
    env = os.environ.get("SHOPTRACKER_SECRET")
    if env:
        return env.encode("utf-8")
    path = os.path.join(DATA_DIR, "secret.key")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read().strip()
    key = secrets.token_hex(32).encode("ascii")
    with open(path, "wb") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return key


SECRET = _load_secret()


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(user_id: int) -> str:
    payload = {"uid": user_id, "exp": int(time.time() + TOKEN_HOURS * 3600)}
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = _b64e(hmac.new(SECRET, body.encode("ascii"), hashlib.sha256).digest())
    return f"{body}.{sig}"


def read_token(token: str):
    """Returns the user id inside a valid, unexpired token, else None."""
    try:
        body, sig = token.split(".", 1)
        expected = _b64e(hmac.new(SECRET, body.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_b64d(body))
        if payload["exp"] < time.time():
            return None
        return int(payload["uid"])
    except Exception:
        return None


# ---------------------------------------------------------------------
# login throttling (a 4-digit PIN has only 10,000 possibilities, so
# unlimited guessing over a network would be easy without this)
# ---------------------------------------------------------------------
_FAILS = {}          # key -> list of failure timestamps
_LOCKED_UNTIL = {}   # key -> unix time
MAX_FAILS_PER_IP_NAME = 5
MAX_FAILS_PER_NAME = 30
FAIL_WINDOW = 15 * 60
LOCK_SECONDS = 5 * 60
_THROTTLE_LOCK = threading.Lock()


def _client_ip(request: Request) -> str:
    if TRUST_PROXY:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "?"


def _throttle_keys(ip, name):
    n = name.strip().lower()
    return (f"{ip}|{n}", f"name|{n}")


def _locked_seconds(keys):
    now = time.time()
    with _THROTTLE_LOCK:
        left = [max(0, _LOCKED_UNTIL.get(k, 0) - now) for k in keys]
    return int(max(left))


def _register_failure(keys):
    now = time.time()
    limits = (MAX_FAILS_PER_IP_NAME, MAX_FAILS_PER_NAME)
    with _THROTTLE_LOCK:
        for k, limit in zip(keys, limits):
            lst = [t for t in _FAILS.get(k, []) if now - t < FAIL_WINDOW]
            lst.append(now)
            _FAILS[k] = lst
            if len(lst) >= limit:
                _LOCKED_UNTIL[k] = now + LOCK_SECONDS
                _FAILS[k] = []


def _clear_failures(key):
    with _THROTTLE_LOCK:
        _FAILS.pop(key, None)
        _LOCKED_UNTIL.pop(key, None)


# ---------------------------------------------------------------------
# JSON conversion (database rows -> JSON, and datetimes in arguments)
# ---------------------------------------------------------------------
_NEVER_SEND = {"pin_hash"}  # PIN hashes never leave the server


def to_jsonable(obj):
    if isinstance(obj, sqlite3.Row):
        return {k: to_jsonable(obj[k]) for k in obj.keys() if k not in _NEVER_SEND}
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items() if k not in _NEVER_SEND}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, datetime):
        return {"__datetime__": obj.isoformat()}
    return obj


def from_jsonable(obj):
    if isinstance(obj, dict):
        if set(obj.keys()) == {"__datetime__"}:
            return datetime.fromisoformat(obj["__datetime__"])
        return {k: from_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [from_jsonable(v) for v in obj]
    return obj


# ---------------------------------------------------------------------
# backups
# ---------------------------------------------------------------------

def backup_database(reason="scheduled"):
    """Safe online copy of the live database (SQLite's own backup API)."""
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        dest = os.path.join(BACKUP_DIR, f"shop_tracker_{stamp}.db")
        with DB_LOCK:
            src = sqlite3.connect(shop_db.DB_FILE, timeout=30)
            try:
                dst = sqlite3.connect(dest)
                try:
                    src.backup(dst)
                finally:
                    dst.close()
            finally:
                src.close()
        files = sorted(f for f in os.listdir(BACKUP_DIR) if f.startswith("shop_tracker_") and f.endswith(".db"))
        for old in files[:-BACKUP_KEEP] if BACKUP_KEEP > 0 else []:
            try:
                os.remove(os.path.join(BACKUP_DIR, old))
            except OSError:
                pass
        log.info("Backup saved (%s): %s", reason, dest)
        return dest
    except Exception:
        log.exception("Backup FAILED")
        return None


def _backup_loop():
    while True:
        time.sleep(BACKUP_HOURS * 3600)
        backup_database("scheduled")


def _local_addresses():
    """Best-effort list of this machine's LAN addresses, for the startup banner."""
    addrs = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))  # no packet is actually sent
        addrs.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if ip not in addrs and not ip.startswith("127."):
                addrs.append(ip)
    except Exception:
        pass
    return addrs


# ---------------------------------------------------------------------
# the app
# ---------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app):
    with DB_LOCK:
        shop_db.init_db()
    backup_database("startup")
    threading.Thread(target=_backup_loop, daemon=True).start()
    port = int(os.environ.get("PORT") or os.environ.get("SHOPTRACKER_PORT") or 8000)
    log.info("=" * 62)
    log.info("%s server %s is running.  Timezone: %s", APP_NAME, SERVER_VERSION, SHOP_TIMEZONE)
    log.info("Database: %s", shop_db.DB_FILE)
    log.info("In the app on each PC, enter the server address as ONE of:")
    for ip in _local_addresses():
        log.info("      http://%s:%d", ip, port)
    log.info("=" * 62)
    yield


app = FastAPI(title=f"{APP_NAME} server", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


@app.get("/", response_class=PlainTextResponse)
def root():
    return f"{APP_NAME} server is running. Open the {APP_NAME} app and enter this address to connect."


@app.get("/api/health")
def health():
    """No login needed; reveals nothing about the business. The app uses it
    for 'Test connection' and for the green/red connection light."""
    return {"app": APP_NAME, "server_version": SERVER_VERSION, "api_version": API_VERSION,
            "time": datetime.now().isoformat(timespec="seconds")}


class LoginBody(BaseModel):
    name: str = Field(max_length=100)
    pin: str = Field(max_length=64)


@app.post("/api/login")
def login(body: LoginBody, request: Request):
    keys = _throttle_keys(_client_ip(request), body.name)
    wait = _locked_seconds(keys)
    if wait > 0:
        mins = max(1, (wait + 59) // 60)
        log.warning("Login blocked (too many attempts) for '%s'", body.name.strip()[:40])
        raise HTTPException(429, f"Too many wrong attempts. Please wait {mins} minute(s) and try again.")

    with DB_LOCK:
        user = shop_db.authenticate(body.name, body.pin)
    if user is None:
        _register_failure(keys)
        log.info("Failed login for '%s'", body.name.strip()[:40])
        # Same answer whether the name or the PIN was wrong - never reveal which.
        raise HTTPException(401, "Invalid username or PIN.")

    _clear_failures(keys[0])
    log.info("Login OK: %s (%s)", user["name"], user["role"])
    return {"token": make_token(user["id"]), "user": to_jsonable(user),
            "token_hours": TOKEN_HOURS}


class RpcBody(BaseModel):
    fn: str = Field(max_length=100)
    args: list = Field(default_factory=list)
    kwargs: dict = Field(default_factory=dict)


# errors the app should receive as proper, named exceptions
_PASS_THROUGH = {
    "DuplicateNameError": shop_db.DuplicateNameError,
    "LastAdminError": shop_db.LastAdminError,
}


def _current_user(authorization: str):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Please log in again.")
    uid = read_token(authorization[7:].strip())
    if uid is None:
        raise HTTPException(401, "Your login has expired. Please log in again.")
    conn = shop_db.get_connection()
    try:
        row = conn.execute("SELECT id, name, role, active FROM users WHERE id = ?", (uid,)).fetchone()
    finally:
        conn.close()
    if row is None or not row["active"]:
        raise HTTPException(401, "This account is no longer active.")
    return {"id": row["id"], "name": row["name"], "role": row["role"]}


@app.post("/api/rpc")
def rpc(body: RpcBody, authorization: str = Header(default="")):
    with DB_LOCK:
        # 1) Who is asking? (Checked first, so strangers learn nothing.)
        user = _current_user(authorization)

        # 2) Is this a known operation, and are the arguments well-formed?
        if body.fn not in policy.POLICY or not hasattr(shop_db, body.fn):
            raise HTTPException(404, f"Unknown operation: {body.fn}")
        func = getattr(shop_db, body.fn)
        try:
            args = from_jsonable(body.args)
            kwargs = from_jsonable(body.kwargs)
            bound = inspect.signature(func).bind(*args, **kwargs)
            bound.apply_defaults()
        except (TypeError, ValueError) as e:
            raise HTTPException(400, f"Bad arguments for {body.fn}: {e}")

        # 3) Is this person allowed? (identity forcing, worker scoping, ownership, validation)
        try:
            params = policy.apply_rule(body.fn, user, dict(bound.arguments))
        except policy.PolicyError as e:
            log.warning("DENIED %s -> %s (%s)", user["name"], body.fn, e)
            raise HTTPException(403, str(e))
        except policy.BadRequestError as e:
            raise HTTPException(400, str(e))

        # 4) Do it.
        try:
            result = func(**params)
        except tuple(_PASS_THROUGH.values()) as e:
            return {"ok": False, "error": {"type": type(e).__name__, "message": str(e)}}
        except ValueError as e:
            return {"ok": False, "error": {"type": "ValueError", "message": str(e)}}
        except sqlite3.IntegrityError:
            return {"ok": False, "error": {"type": "IntegrityError",
                                           "message": "That conflicts with an existing record (for example, the name is already taken)."}}
        except Exception:
            log.exception("Error while running %s for %s", body.fn, user["name"])
            raise HTTPException(500, "The server hit an unexpected error. Nothing was changed. Please try again.")

    return {"ok": True, "result": to_jsonable(result)}


if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("SHOPTRACKER_HOST", "0.0.0.0")
    port = int(os.environ.get("PORT") or os.environ.get("SHOPTRACKER_PORT") or 8000)
    # ONE worker process on purpose: all database access is serialized by
    # DB_LOCK above, which only works inside a single process.
    uvicorn.run(app, host=host, port=port, workers=1, log_level="warning",
                proxy_headers=TRUST_PROXY, forwarded_allow_ips="*" if TRUST_PROXY else None)
