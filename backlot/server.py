from __future__ import annotations

import asyncio
import base64
import contextvars
import hashlib
import json
import os
import re
import secrets
import shlex
import sqlite3
import threading
import time
import traceback
import urllib.parse
import uuid
from contextlib import asynccontextmanager, closing
from datetime import datetime, timezone
from pathlib import PurePosixPath
from collections.abc import Callable, Iterable
from typing import Any, Literal, NamedTuple

import httpx
import modal
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from backlot.agent import Bash, Click, Drag, Exec, Key, Process, Scroll, TypeText, Wait

APP_NAME = "backlot"
DB_DEFAULT = "/data/backlot.db"
RESOLUTION_RE = re.compile(r"^(\d{3,4})x(\d{3,4})x(16|24|32)$")
TEMPLATE_REF_RE = re.compile(
    r"[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9_-]*@\d+\.\d+\.\d+"
)
RAM_CHOICES = {4, 8, 16, 32, 64}
CPU_CHOICES = {1, 2, 4, 8, 16}
ACTION_MODELS = {
    "click": Click,
    "drag": Drag,
    "type": TypeText,
    "key": Key,
    "scroll": Scroll,
    "wait": Wait,
    "bash": Bash,
    "exec": Exec,
    "process": Process,
}
CURATED_TEMPLATE_REF = "backlot/linux-desktop@1.0.0"
CURATED_TEMPLATE_IMAGE_ID = "__backlot_desktop__"
CURATED_TEMPLATE_SPEC = {
    "name": "Linux desktop",
    "purpose": "XFCE desktop with Chromium, Terminal, Files, and Text Editor ready.",
    "hardware": {
        "cpu": 1,
        "ram": 4,
        "disk_size_gb": None,
        "resolution": "1280x720x24",
        "idle_timeout_minutes": 30,
    },
}

# --- Bounded execution, and why an implicit boot is a defect (implementation note B5.0) ---
#
# Four consumer paths auto-start a stopped machine through runtime_for_consumer:
# agent_request, vnc_payload, app_payload and run_chat. For a caller that rents a
# machine that is the right behavior and stays the default. For a caller running
# a BOUNDED, externally-funded action it is a money leak: a single bounded call against a
# stopped machine boots a VM nobody reserved, which then bills to the idle reaper
# or the 23h rollover. That is $0.66 at the observed 4c/8g shape and $0.12 at the
# 1c/4g shape, against a reservation sized for one bounded call. It is invisible
# to any spend ceiling the caller declared, because the caller never asked for a
# machine.
#
# So the rule is: machine EXISTENCE comes from the provisioning path, never from
# a bounded action. A bounded caller that finds the machine stopped is refused
# with machine_not_running and starts it deliberately, or not at all.
#
# The flag is request-scoped and defaults to False, which is exactly today's
# behavior for every caller that exists right now. A caller opts in per request.
# When the budget-lease seam lands, presenting a lease sets this too, and the
# refusal is already in place rather than being retrofitted onto four call sites.
#
# It is a ContextVar rather than a parameter threaded through four signatures
# because the supervisor and the explicit start endpoints call start_runtime
# outside any request, where the default correctly applies and no caller has to
# remember to pass anything.
BOUNDED_EXECUTION_HEADER = "x-backlot-bounded-execution"
BOUNDED_EXECUTION: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "backlot_bounded_execution", default=False
)

app = modal.App(APP_NAME)
registry_volume = modal.Volume.from_name("backlot-data", create_if_missing=True)
backlot_secret = modal.Secret.from_name("backlot-secrets")

control_image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install(
        # Pinned, and it is the only dependency here that is load-bearing for a
        # signature somebody else verifies.
        "cryptography==50.0.0",
        "fastapi==0.141.1",
        "httpx==0.28.1",
        "pydantic==2.13.4",
    )
    .add_local_dir("backlot", "/root/backlot", copy=True)
)

desktop_image = (
    modal.Image.debian_slim(python_version="3.12")
    .apt_install(
        "ca-certificates",
        "chromium",
        "curl",
        "dbus-x11",
        "desktop-file-utils",
        "fonts-dejavu-core",
        # Staff installers clone their own source. Without git the agency install probe
        # exits 90 at its last step and installs nothing, having already done the work.
        "git",
        "hicolor-icon-theme",
        "imagemagick",
        "libglib2.0-bin",
        "mousepad",
        "novnc",
        "python3-yaml",
        "scrot",
        "thunar",
        "websockify",
        "xfce4-terminal",
        "xfdesktop4",
        "xfwm4",
        "x11vnc",
        "xdotool",
        "xvfb",
    )
    .run_commands(
        "curl -fsSL -o /tmp/gitleaks.tar.gz "
        "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz "
        "&& echo '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb  /tmp/gitleaks.tar.gz' | sha256sum -c - "
        "&& tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks "
        "&& rm /tmp/gitleaks.tar.gz"
    )
    .run_commands(
        "curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/openclaw-install.sh "
        "https://openclaw.ai/install.sh "
        "&& echo '0034898bce1ff687b25812e9807d89d34080d5569bbdacfae8816d115ccb9b89  /tmp/openclaw-install.sh' | sha256sum -c - "
        "&& bash /tmp/openclaw-install.sh --no-prompt --no-onboard "
        "--version 2026.7.1-2 --verify "
        "&& openclaw --version | grep -F '2026.7.1-2' "
        "&& rm /tmp/openclaw-install.sh"
    )
    .pip_install("fastapi==0.141.1", "pydantic==2.13.4", "uvicorn==0.52.0")
    .add_local_dir("backlot", "/root/backlot", copy=True)
)

# Two locks, deliberately, because one lock did two unrelated jobs and the slow job
# starved the fast one. registry_lock is held for the milliseconds a sqlite statement
# takes. lifecycle_lock_for() is held across a Modal snapshot, which measures ~30s, but
# only against the ONE computer being changed. Sharing a single lock meant a stop on
# machine B blocked a read on machine A for the whole snapshot, so an `echo x` was
# observed taking 46 seconds behind an unrelated stop.
runtime_lock = threading.RLock()
_lifecycle_locks: dict[str, threading.RLock] = {}
_lifecycle_locks_guard = threading.Lock()


def lifecycle_lock_for(computer_id: str) -> threading.RLock:
    """One lock per computer, so slow lifecycle work never blocks another machine."""
    with _lifecycle_locks_guard:
        lock = _lifecycle_locks.get(computer_id)
        if lock is None:
            lock = threading.RLock()
            _lifecycle_locks[computer_id] = lock
        return lock


# --- The runtime signing key (implementation note section 8A.0, gaps L1 and L2) ---------
#
# The prerequisite neither the Backlot contract nor OpSpot's P8L4 had named:
# Backlot holds no asymmetric key material at all. `backlot-secrets` carries
# four keys and not one of them is a signing key. P8L4's `cnf` proof of
# possession, the signed refusal acknowledgement, and the meter checkpoint all
# rest on one, so until it exists every guarantee on that seam is "Backlot said
# so" over a bearer channel.
#
# ONE keypair per runtime, serving all three obligations. Splitting them would
# mean three rotation schedules and three ways for OpSpot to hold a stale
# verification key, to buy a separation that does not correspond to a real trust
# boundary: the same process holds all three.
#
# Rotation is OVERLAP based and cannot be instant. A lease minted against
# thumbprint A is verified against A until it is provably dead, which is
# `exp + clock_skew_bound`, not `exp`. So the previous public key stays
# published through the overlap and the previous PRIVATE key stays loaded, and
# the operator retires it only after the last bound lease is dead. Publishing
# only the active key would silently invalidate every lease in flight at the
# moment of rotation.
RUNTIME_KEY_ENV = "BACKLOT_RUNTIME_SIGNING_KEY"
RUNTIME_KEY_PREVIOUS_ENV = "BACKLOT_RUNTIME_SIGNING_KEY_PREVIOUS"


def _load_signing_key(env_name: str):
    """Load an Ed25519 private key from a base64 raw 32 byte seed.

    Raw seed rather than PEM on purpose: PEM in an environment variable invites
    newline mangling, and the failure mode of a subtly corrupted PEM is a key
    that loads and produces signatures nobody can verify.
    """
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        return None
    try:
        seed = base64.b64decode(raw, validate=True)
        return ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    except Exception:
        # Never echo any part of the value, not even a length, in the message
        # that reaches a caller. The variable NAME is the whole diagnosis.
        print(f"BACKLOT_SIGNING_KEY_UNREADABLE env={env_name}")
        return None


def _public_jwk(private_key) -> dict[str, str]:
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(public_bytes).decode().rstrip("="),
    }


def jwk_thumbprint(jwk: dict[str, str]) -> str:
    """RFC 7638 thumbprint.

    The member set and their order are fixed by the RFC, not by us, which is the
    entire point: two implementations that both follow it derive the same
    identifier for the same key without having agreed on anything else.
    """
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).decode().rstrip("=")


def runtime_keys() -> dict[str, Any]:
    """Active and overlapping-previous key material, public parts only."""
    keys = {}
    for label, env_name in (
        ("active", RUNTIME_KEY_ENV),
        ("previous", RUNTIME_KEY_PREVIOUS_ENV),
    ):
        private_key = _load_signing_key(env_name)
        if private_key is None:
            continue
        jwk = _public_jwk(private_key)
        keys[label] = {
            "private": private_key,
            "jwk": jwk,
            "thumbprint": jwk_thumbprint(jwk),
        }
    return keys


def signing_state() -> dict[str, Any]:
    """Whether this runtime can sign anything, safe to expose.

    Reports unavailable rather than raising at import, so the code can deploy
    before the key is provisioned and the absence is visible on a health read
    instead of as a crash loop.
    """
    keys = runtime_keys()
    active = keys.get("active")
    previous = keys.get("previous")
    return {
        "available": active is not None,
        "algorithm": "Ed25519",
        "active_thumbprint": active["thumbprint"] if active else None,
        "previous_thumbprint": previous["thumbprint"] if previous else None,
        "rotation_overlap_active": previous is not None,
    }


def sign_runtime_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Detached signature over the canonical JSON of `payload`.

    Detached rather than a JWS envelope because every consumer of this already
    has the payload: it is the acknowledgement or checkpoint body they asked
    for. Canonical JSON with sorted keys and no spaces, so the bytes signed are
    reproducible from the object rather than from a particular serializer's
    whitespace habits. Byte-identical regeneration after a crash is a stated
    requirement of section 8A.1 and it depends entirely on this being canonical.
    """
    keys = runtime_keys()
    active = keys.get("active")
    if active is None:
        raise HTTPException(
            503,
            detail={
                "code": "signing_key_unavailable",
                "message": (
                    "This runtime holds no Ed25519 signing key, so it cannot "
                    "produce a verifiable acknowledgement. Provision "
                    f"{RUNTIME_KEY_ENV} in the runtime secret. Refusing rather "
                    "than returning an unsigned acknowledgement, which the "
                    "consumer would have no way to tell apart from a real one."
                ),
            },
        )
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    signature = active["private"].sign(body)
    return {
        "payload": payload,
        "signature": base64.urlsafe_b64encode(signature).decode().rstrip("="),
        "alg": "EdDSA",
        "kid": active["thumbprint"],
    }


# --- Trusted clock (implementation note B5.0, gap L14, threat T13) ----------------------
#
# now() is wall clock. Wall clock can move backwards: NTP correction, a host
# migration, a hypervisor resume. Every lease decision Backlot is about to make
# rests on comparing now() to an `exp` it did not choose, and a clock that has
# silently jumped backwards makes an expired lease look live. That is the unsafe
# direction, and before this there was nothing in the process that could even
# notice it.
#
# The detector is a second clock that cannot be adjusted. time.monotonic() only
# ever counts forward and is immune to NTP, so anchoring both at import and
# comparing their elapsed deltas turns an unobservable skew into an arithmetic
# one. Wall elapsed should track monotonic elapsed; the gap between them is
# drift, and drift past the published bound means the wall clock moved when it
# should not have.
#
# Deliberately NOT wired into now() itself. now() is called 20 times for
# ordinary bookkeeping like last_active_at, and making routine housekeeping
# raise on a clock problem would turn a measurement fault into an outage. The
# guard is consulted where a wrong answer costs money or safety: before starting
# a machine, and later before honoring a lease expiry.
CLOCK_SKEW_BOUND_SECONDS_DEFAULT = 60
_CLOCK_ANCHOR_WALL = time.time()
_CLOCK_ANCHOR_MONOTONIC = time.monotonic()


def clock_skew_bound() -> int:
    """How far wall clock may drift from monotonic before the clock is untrusted.

    A floor of 5s exists because a bound of zero would make every ordinary
    scheduler hiccup an outage, and the value is meant to be measured out of the
    B5.1 proofs rather than guessed. P8L4 declines to publish it; this is the
    local enforcement side of that number, not a claim about what it should be.
    """
    raw = os.environ.get(
        "BACKLOT_CLOCK_SKEW_BOUND_SECONDS", str(CLOCK_SKEW_BOUND_SECONDS_DEFAULT)
    )
    try:
        return max(5, int(raw))
    except ValueError:
        return CLOCK_SKEW_BOUND_SECONDS_DEFAULT


def clock_drift_seconds() -> float:
    """Signed wall-minus-monotonic drift since import.

    Negative means the wall clock moved BACKWARDS relative to a clock that
    cannot. That is the direction that makes an expired lease look live, so it
    is reported with its sign rather than as a magnitude.
    """
    wall_elapsed = time.time() - _CLOCK_ANCHOR_WALL
    monotonic_elapsed = time.monotonic() - _CLOCK_ANCHOR_MONOTONIC
    return wall_elapsed - monotonic_elapsed


# An operator override that can only ever move the runtime toward DISTRUST.
#
# Two jobs, and it is worth being explicit that they are the same mechanism. An
# operator who knows NTP is broken on the host, or who is mid-incident, needs a
# way to fail Backlot closed without a redeploy. And the B5.0 gate needs the
# untrusted-clock refusal to be provable against the DEPLOYED control plane
# rather than only in a unit test, and wall-clock skew cannot be induced inside
# a Modal container from outside it.
#
# It is safe because it is one-directional by construction: it can declare the
# clock untrusted, never trusted. Nothing here can mask real drift, so the worst
# an attacker with the admin key could do is refuse bounded work, which that key
# can already do by revoking itself. It expires on its own so a forgotten
# override cannot become permanent.
CLOCK_DISTRUST_MAX_SECONDS = 3600
_clock_distrust_until: float = 0.0


def declare_clock_untrusted(seconds: int) -> dict[str, Any]:
    global _clock_distrust_until
    seconds = max(0, min(CLOCK_DISTRUST_MAX_SECONDS, seconds))
    _clock_distrust_until = time.monotonic() + seconds if seconds else 0.0
    return clock_state()


def clock_state() -> dict[str, Any]:
    drift = clock_drift_seconds()
    bound = clock_skew_bound()
    # Measured against monotonic, so an operator override cannot be outlived by
    # a wall-clock jump, which would be a way to escape it.
    overridden = time.monotonic() < _clock_distrust_until
    return {
        "trusted": (abs(drift) <= bound) and not overridden,
        "drift_seconds": round(drift, 3),
        "skew_bound_seconds": bound,
        # Named separately because backwards is the unsafe direction and a
        # magnitude alone hides which way the clock went.
        "direction": "backward" if drift < 0 else "forward",
        # Distinguishes "the clock is bad" from "an operator said so", because
        # an incident responder reading /health needs to know which.
        "operator_declared_untrusted": overridden,
    }


def require_trusted_clock(what: str) -> None:
    """Refuse a money-or-safety decision taken against a clock we cannot trust.

    Fails CLOSED, unlike the bounded-execution header. The header's failure mode
    is refusing a caller who never opted in; this one's failure mode is honoring
    an expired lease or billing against a fabricated timestamp, so the safe
    default flips.
    """
    state = clock_state()
    if not state["trusted"]:
        raise HTTPException(
            503,
            detail={
                "code": "untrusted_clock",
                "operation": what,
                **state,
                "message": (
                    "The wall clock has drifted past the published bound "
                    "relative to a monotonic reference, so any decision that "
                    "depends on time is refused until it is back in bound. A "
                    "backward drift is the unsafe direction: it makes an "
                    "expired authorization look live."
                ),
            },
        )


def now() -> int:
    return int(time.time())


def db_path() -> str:
    return os.environ.get("BACKLOT_DB_PATH", DB_DEFAULT)


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(db_path(), timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def persist() -> None:
    if db_path().startswith("/data/"):
        registry_volume.commit()


def reload_registry() -> None:
    if db_path().startswith("/data/"):
        with runtime_lock:
            registry_volume.reload()


def init_db() -> None:
    path = db_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with closing(connect()) as connection, connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS templates (
                ref TEXT PRIMARY KEY,
                image_id TEXT NOT NULL,
                spec_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS computers (
                id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL REFERENCES workspaces(id),
                name TEXT NOT NULL,
                ram INTEGER NOT NULL,
                cpu INTEGER NOT NULL,
                disk_size_gb INTEGER,
                resolution TEXT NOT NULL,
                template_ref TEXT REFERENCES templates(ref),
                idle_timeout_minutes INTEGER NOT NULL,
                status TEXT NOT NULL,
                sandbox_id TEXT,
                snapshot_image_id TEXT,
                agent_url TEXT,
                agent_token TEXT,
                vnc_url TEXT,
                vnc_token TEXT,
                vnc_password TEXT,
                created_at INTEGER NOT NULL,
                started_at INTEGER,
                last_active_at INTEGER,
                expires_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS threads (
                id TEXT PRIMARY KEY,
                computer_id TEXT NOT NULL REFERENCES computers(id) ON DELETE CASCADE,
                messages_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            """
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO templates(ref, image_id, spec_json, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                CURATED_TEMPLATE_REF,
                CURATED_TEMPLATE_IMAGE_ID,
                json.dumps(CURATED_TEMPLATE_SPEC),
                now(),
            ),
        )
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(computers)")
        }
        for column in (
            "error_reason TEXT",
            "status_changed_at INTEGER",
            "stranded_since INTEGER",
            "env_json TEXT",
        ):
            if column.split()[0] not in columns:
                connection.execute(f"ALTER TABLE computers ADD COLUMN {column}")
        # Registries deployed before stranded_since already have error rows holding a
        # sandbox. Their true onset is unknowable because status_changed_at was rewound
        # on every failed tick; the latest recorded failure is the conservative safe
        # lower bound. Preserve it from this boot forward instead of granting every
        # later failure a new fifteen-minute window.
        connection.execute(
            """
            UPDATE computers SET stranded_since = status_changed_at
            WHERE status = 'error' AND sandbox_id IS NOT NULL
                AND stranded_since IS NULL AND status_changed_at IS NOT NULL
            """
        )
        # Who made this row. Without it, a consumer reconciling against a shared account
        # can only guess ownership from the name, and "delete anything I do not
        # recognise" has another tenant's machines in its blast radius.
        workspace_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(workspaces)")
        }
        for column in ("created_by TEXT", "created_by_key TEXT"):
            if column.split()[0] not in workspace_columns:
                connection.execute(f"ALTER TABLE workspaces ADD COLUMN {column}")
        # Secret stores and copy-paste add trailing newlines. Hashing one in would make a
        # correct key fail forever with no way to see why, since nobody can read the
        # stored value back to spot the whitespace.
        bootstrap_key = (os.environ.get("BACKLOT_BOOTSTRAP_KEY") or "").strip()
        if bootstrap_key:
            bootstrap_hash = hash_key(bootstrap_key)
            # The configured secret is the only admin credential. Drop bootstrap rows
            # seeded by a previous secret, otherwise a rotated-out key keeps
            # authenticating forever and DELETE /api-keys/{id} refuses to revoke it.
            connection.execute(
                """
                DELETE FROM api_keys
                WHERE name = 'bootstrap' AND workspace_id IS NULL AND key_hash != ?
                """,
                (bootstrap_hash,),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO api_keys(id, name, key_hash, workspace_id, created_at)
                VALUES (?, 'bootstrap', ?, NULL, ?)
                """,
                (f"key_{uuid.uuid4().hex}", bootstrap_hash, now()),
            )
    persist()


def hash_key(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def one(sql: str, params: tuple = ()) -> sqlite3.Row | None:
    with runtime_lock:
        with closing(connect()) as connection, connection:
            return connection.execute(sql, params).fetchone()


def many(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    with runtime_lock:
        with closing(connect()) as connection, connection:
            return connection.execute(sql, params).fetchall()


def execute(sql: str, params: tuple = ()) -> None:
    with runtime_lock:
        with closing(connect()) as connection, connection:
            connection.execute(sql, params)
        persist()


def row_dict(row: sqlite3.Row) -> dict[str, Any]:
    return dict(row)


ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ENV_MAX_KEYS = 64
ENV_MAX_VALUE = 4096


def validate_env(env: dict[str, str] | None) -> str | None:
    """Per-machine environment. Values are treated as secret and never returned."""
    if not env:
        return None
    if len(env) > ENV_MAX_KEYS:
        raise HTTPException(422, f"env accepts at most {ENV_MAX_KEYS} keys")
    for key, value in env.items():
        if not ENV_KEY_RE.fullmatch(key):
            raise HTTPException(422, f"env key is not a valid variable name: {key}")
        if key.startswith("BACKLOT_"):
            # Reserved: these carry the VNC password and display geometry, so a caller
            # setting them could weaken the desktop's own auth.
            raise HTTPException(422, f"env key {key} is reserved")
        if len(value) > ENV_MAX_VALUE:
            raise HTTPException(422, f"env value for {key} exceeds {ENV_MAX_VALUE} bytes")
    return json.dumps(env)


def computer_public(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    data = dict(row)
    # env_json holds per-customer secrets, so it leaves through no response.
    for field in ("agent_token", "vnc_token", "vnc_password", "env_json"):
        data.pop(field, None)
    data["computer_id"] = data["id"]
    return data


STALE_GRACE_SECONDS = 300


def runtime_health(row: sqlite3.Row | dict[str, Any], current_time: int) -> dict[str, Any]:
    computer = dict(row)
    status = computer["status"]
    expires_at = computer["expires_at"]
    last_active = computer["last_active_at"] or computer["created_at"]
    idle_seconds = max(0, current_time - last_active)
    idle_limit = computer["idle_timeout_minutes"] * 60
    changed_at = computer.get("status_changed_at")
    stale = False
    reason = None
    if status == "error":
        reason = computer.get("error_reason") or ERROR_SUPERVISION_FAILED
        # A provider-missing row is terminal and its runtime claims have already been
        # cleared, but `stale` records why it became terminal: the registry said
        # running after Modal no longer had a task. Consumers need to distinguish that
        # reconciliation from an ordinary start or supervision failure.
        stale = reason == ERROR_PROVIDER_TASK_MISSING
    elif status == "running" and expires_at and expires_at <= current_time:
        # Modal terminates a sandbox at its timeout, so a row still claiming to run
        # past that point is describing a machine that no longer exists.
        stale = True
        reason = "runtime_expired"
    elif status == "running" and idle_seconds > idle_limit + STALE_GRACE_SECONDS:
        # Idle reaping has stopped happening, so this is billing unattended.
        stale = True
        reason = "idle_reaper_stalled"
    return {
        "computer_id": computer["id"],
        "name": computer["name"],
        "status": status,
        "healthy": reason is None,
        "reason": reason,
        "stale": stale,
        "idle_seconds": idle_seconds,
        "expires_at": expires_at,
        "status_changed_at": changed_at,
        "disk_retained_until": (
            changed_at + snapshot_ttl()
            if computer.get("snapshot_image_id") and changed_at
            else None
        ),
    }


class Principal(BaseModel):
    key_id: str
    workspace_id: str | None
    # The key's name, set by an admin when the key was minted. This is the stable
    # consumer label: a scoped key reissued under the same name still identifies the
    # same consumer, whereas key_id changes on every rotation.
    key_name: str


def principal(authorization: str | None = Header(default=None)) -> Principal:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer key")
    reload_registry()
    key = authorization[7:].strip()
    row = one(
        "SELECT id, name, workspace_id FROM api_keys WHERE key_hash = ?",
        (hash_key(key),),
    )
    if not row:
        raise HTTPException(401, "Invalid bearer key")
    return Principal(
        key_id=row["id"], workspace_id=row["workspace_id"], key_name=row["name"]
    )


def require_admin(current: Principal) -> None:
    if current.workspace_id:
        raise HTTPException(403, detail={"code": "workspace_scope_mismatch"})


def require_workspace(current: Principal, workspace_id: str) -> None:
    if current.workspace_id and current.workspace_id != workspace_id:
        raise HTTPException(403, detail={"code": "workspace_scope_mismatch"})


def get_workspace(workspace_id: str, current: Principal) -> sqlite3.Row:
    require_workspace(current, workspace_id)
    row = one("SELECT * FROM workspaces WHERE id = ?", (workspace_id,))
    if not row:
        raise HTTPException(404, "Workspace not found")
    return row


def get_computer(computer_id: str, current: Principal | None = None) -> sqlite3.Row:
    row = one("SELECT * FROM computers WHERE id = ?", (computer_id,))
    if not row:
        raise HTTPException(404, "Computer not found")
    if current:
        require_workspace(current, row["workspace_id"])
    return row


def resolution_parts(value: str) -> tuple[int, int, int]:
    match = RESOLUTION_RE.fullmatch(value)
    if not match:
        raise HTTPException(422, "resolution must look like 1280x720x24")
    width, height, depth = map(int, match.groups())
    if width > 2560 or height > 1600:
        raise HTTPException(422, "resolution exceeds 2560x1600")
    return width, height, depth


class WorkspaceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)


class ApiKeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    workspace_id: str = Field(min_length=1)


class ComputerCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace_id: str
    name: str = Field(min_length=1, max_length=100)
    ram: Literal[4, 8, 16, 32, 64] = 4
    cpu: Literal[1, 2, 4, 8, 16] = 1
    disk_size_gb: int | None = Field(default=None, ge=1)
    resolution: str = "1280x720x24"
    template_ref: str | None = None
    idle_timeout_minutes: int = Field(default=30, ge=1, le=1440)
    env: dict[str, str] | None = None


class ClockTrust(BaseModel):
    model_config = ConfigDict(extra="forbid")
    untrusted_for_seconds: int = Field(ge=0, le=CLOCK_DISTRUST_MAX_SECONDS)


class ComputerResize(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ram: Literal[4, 8, 16, 32, 64] | None = None
    cpu: Literal[1, 2, 4, 8, 16] | None = None


class ComputerMove(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace_id: str


class CloneComputer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    computer_id: str
    name: str | None = Field(default=None, min_length=1, max_length=100)


class RegisteredTemplateHardware(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cpu: Literal[1, 2, 4, 8, 16]
    ram: Literal[4, 8, 16, 32, 64]
    resolution: str
    idle_timeout_minutes: int = Field(ge=1, le=1440)


class TemplateRegister(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ref: str
    image_id: str = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=100)
    purpose: str = Field(min_length=1, max_length=500)
    hardware: RegisteredTemplateHardware


class TemplateBinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    template_ref: str | None
    expected_workspace_id: str = Field(min_length=1)
    expected_template_ref: str | None
    expected_snapshot_image_id: str | None


class TemplateBuild(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ref: str
    name: str | None = Field(default=None, min_length=1, max_length=100)
    purpose: str | None = Field(default=None, min_length=1, max_length=500)
    hardware: dict[str, Any] = Field(default_factory=dict)
    env: dict[str, str] = Field(default_factory=dict)
    # Reaches the build sandbox as env and is then forgotten. exclude=True keeps it out
    # of model_dump_json(), which is what lands in templates.spec_json, and spec_json is
    # permanent: there is no image delete in Modal 1.5.2 and a template cannot be
    # deleted while a computer references it. A credential in `env` is written into a
    # row nobody can remove; the same credential in `secrets` is never written at all.
    # Values here are also redacted out of every command string and build log.
    secrets: dict[str, str] = Field(default_factory=dict, exclude=True)
    build: dict[str, Any] = Field(default_factory=dict)
    files: dict[str, str] = Field(default_factory=dict)


class ChatCompletion(BaseModel):
    model_config = ConfigDict(extra="allow")
    model: str = "claude-sonnet-5"
    messages: list[dict[str, Any]]
    computer_id: str
    max_steps: int = Field(default=20, ge=1, le=100)
    max_tokens: int = Field(default=4096, ge=1, le=16384)
    stream: bool = False
    thread_id: str | None = None


def sandbox_timeout() -> int:
    return min(86_400, max(120, int(os.environ.get("BACKLOT_SANDBOX_TIMEOUT_SECONDS", "82800"))))


def snapshot_ttl() -> int:
    # Modal exposes no image delete in 1.5.2, so the creation-time ttl is the only
    # reclamation lever. An abandoned workspace stops costing storage this long after
    # its last stop; every stop re-snapshots and restarts the clock for live ones.
    return max(3_600, int(os.environ.get("BACKLOT_SNAPSHOT_TTL_SECONDS", "2592000")))


def workspace_computer_ceiling() -> int:
    # An infrastructure safety valve against a runaway loop or a bad actor, NOT a plan
    # limit. Plan limits are product policy. The default
    # is set high enough that no honest agency reaches it.
    return max(1, int(os.environ.get("BACKLOT_WORKSPACE_COMPUTER_CEILING", "50")))


def sandbox_resources(computer: sqlite3.Row | dict[str, Any]) -> tuple[float, int]:
    cpu = float(os.environ.get("BACKLOT_TEST_CPU", computer["cpu"]))
    memory = int(os.environ.get("BACKLOT_TEST_MEMORY_MIB", int(computer["ram"]) * 1024))
    return cpu, memory


def image_for(computer: sqlite3.Row | dict[str, Any]) -> modal.Image:
    if computer.get("snapshot_image_id"):
        return modal.Image.from_id(computer["snapshot_image_id"])
    if computer.get("template_ref"):
        template = one("SELECT image_id FROM templates WHERE ref = ?", (computer["template_ref"],))
        if not template:
            raise HTTPException(422, "Unknown template_ref")
        if template["image_id"] == CURATED_TEMPLATE_IMAGE_ID:
            return desktop_image
        return modal.Image.from_id(template["image_id"])
    return desktop_image


def template_public(row: sqlite3.Row) -> dict[str, Any]:
    spec = json.loads(row["spec_json"])
    hardware = spec.get("hardware", {})
    return {
        "ref": row["ref"],
        "image_id": None if row["image_id"] == CURATED_TEMPLATE_IMAGE_ID else row["image_id"],
        "name": spec.get("name") or row["ref"].split("/", 1)[-1].split("@", 1)[0],
        "purpose": spec.get("purpose") or "Operator-built Linux desktop template.",
        "defaults": {
            "cpu": int(hardware.get("cpu", 1)),
            "ram": int(hardware.get("ram", max(4, int(hardware.get("memory_mib", 4096)) // 1024))),
            "disk_size_gb": hardware.get("disk_size_gb"),
            "resolution": hardware.get("resolution", "1280x720x24"),
            "idle_timeout_minutes": int(hardware.get("idle_timeout_minutes", 30)),
        },
        "created_at": row["created_at"],
    }


ERROR_SNAPSHOT_EXPIRED = "snapshot_expired"
ERROR_START_FAILED = "runtime_start_failed"
ERROR_SUPERVISION_FAILED = "runtime_supervision_failed"
ERROR_SNAPSHOT_UNRECOVERABLE = "snapshot_failed_disk_lost"
ERROR_PROVIDER_TASK_MISSING = "provider_task_missing"

# How long to keep retrying a failed snapshot before giving up and terminating. At the
# 60 second tick that is roughly fifteen attempts, which covers a transient backend
# blip. Past it the failure is not transient, and holding the sandbox open until
# Modal's 24 hour cap loses the disk anyway. The only thing the extra hours buy is bill.
STRANDED_TERMINATE_SECONDS = 900

SNAPSHOT_GONE_RE = re.compile(r"not found|expired|no such image|does not exist", re.I)


def failure_reason(
    exc: BaseException,
    snapshot_image_id: str | None,
    default: str = ERROR_START_FAILED,
) -> str:
    if snapshot_image_id and SNAPSHOT_GONE_RE.search(str(exc)):
        return ERROR_SNAPSHOT_EXPIRED
    return default


def mark_error(computer_id: str, reason: str) -> None:
    try:
        failure_time = now()
        execute(
            """
            UPDATE computers SET status = 'error', error_reason = ?, status_changed_at = ?,
                stranded_since = CASE
                    WHEN sandbox_id IS NULL THEN NULL
                    ELSE COALESCE(stranded_since, ?)
                END
            WHERE id = ?
            """,
            (reason, failure_time, failure_time, computer_id),
        )
    except Exception:
        # Recording why must never replace the failure being reported.
        pass


def start_runtime(computer_id: str, *, implicit: bool = True) -> sqlite3.Row:
    """Boot a machine.

    `implicit` defaults to True on purpose. Every call site is treated as a
    convenience boot unless it says otherwise, so a fifth one added later
    inherits the bounded-execution refusal instead of quietly reopening the
    leak. The explicit lifecycle routes (create, start, restart, resize restore)
    and the supervisor's rollover pass implicit=False, because a caller asking
    for a machine in so many words is the provisioning path, not a bounded
    action that stumbled into one.
    """
    if BOUNDED_EXECUTION.get():
        # Scoped to bounded callers on purpose, and this is a deliberate narrowing
        # of the B5.0 gate's wording ("refuses starts"), recorded in DECISIONS.md
        # rather than made quietly. The harm an untrusted clock does is honoring a
        # stale `exp`, which only exists on the lease surface. Refusing EVERY start
        # on a 60s NTP correction would take the live customer path down to protect
        # against a risk that surface does not carry. When leases land, lease
        # validation calls this too, which is where the rest of the gate's intent
        # lives.
        require_trusted_clock("start_runtime")
    if implicit and BOUNDED_EXECUTION.get():
        raise HTTPException(
            409,
            detail={
                "code": "machine_not_running",
                "computer_id": computer_id,
                "message": (
                    "This machine is not running, and a bounded execution will "
                    "not start one. Starting a machine is a provisioning "
                    "decision with its own cost, not a side effect of an "
                    "action. Call POST /computers/{id}/start explicitly if a "
                    "boot is what you meant."
                ),
            },
        )
    with lifecycle_lock_for(computer_id):
        computer = get_computer(computer_id)
        if computer["status"] == "running":
            return computer
        width, height, depth = resolution_parts(computer["resolution"])
        timeout = sandbox_timeout()
        cpu, memory = sandbox_resources(computer)
        vnc_password = secrets.token_urlsafe(6)[:8]
        sandbox = None
        try:
            sandbox = modal.Sandbox.create(
                "bash",
                "/root/backlot/desktop.sh",
                app=app,
                image=image_for(row_dict(computer)),
                timeout=timeout,
                cpu=cpu,
                memory=memory,
                env={
                    # Caller env first so the reserved BACKLOT_ vars always win, even if
                    # validation is ever loosened.
                    **json.loads(computer["env_json"] or "{}"),
                    "BACKLOT_WIDTH": str(width),
                    "BACKLOT_HEIGHT": str(height),
                    "BACKLOT_DEPTH": str(depth),
                    "BACKLOT_VNC_PASSWORD": vnc_password,
                },
                readiness_probe=modal.Probe.with_exec(
                    "curl", "-fsS", "http://127.0.0.1:8080/health"
                ),
                experimental_options={"vm_runtime": True},
            )
            sandbox.wait_until_ready(timeout=120)
            agent = sandbox.create_connect_token(
                {"computer_id": computer_id, "purpose": "agent"}, port=8080
            )
            vnc = sandbox.create_connect_token(
                {"computer_id": computer_id, "purpose": "vnc"}, port=6080
            )
            started = now()
            execute(
                """
                UPDATE computers SET
                    status = 'running', sandbox_id = ?, agent_url = ?, agent_token = ?,
                    vnc_url = ?, vnc_token = ?, vnc_password = ?, started_at = ?,
                    last_active_at = ?, expires_at = ?,
                    error_reason = NULL, status_changed_at = ?, stranded_since = NULL
                WHERE id = ?
                """,
                (
                    sandbox.object_id,
                    agent.url,
                    agent.token,
                    vnc.url,
                    vnc.token,
                    vnc_password,
                    started,
                    started,
                    started + timeout,
                    started,
                    computer_id,
                ),
            )
            sandbox.detach()
            return get_computer(computer_id)
        except Exception as exc:
            if sandbox:
                sandbox.terminate(wait=True)
            mark_error(computer_id, failure_reason(exc, computer["snapshot_image_id"]))
            raise


def clear_unrecoverable_runtime(
    computer: sqlite3.Row,
    *,
    event: str,
    exc: BaseException | None = None,
    captured_snapshot_id: str | None = None,
    reason: str = ERROR_SNAPSHOT_UNRECOVERABLE,
) -> sqlite3.Row:
    """Atomically detach a runtime that cannot exist and preserve its intact disk."""
    with runtime_lock:
        with closing(connect()) as connection, connection:
            cursor = connection.execute(
                """
                UPDATE computers SET
                    status = 'error', sandbox_id = NULL,
                    snapshot_image_id = COALESCE(?, snapshot_image_id),
                    agent_url = NULL, agent_token = NULL, vnc_url = NULL, vnc_token = NULL,
                    vnc_password = NULL, started_at = NULL, expires_at = NULL,
                    error_reason = ?, status_changed_at = ?, stranded_since = NULL
                WHERE id = ? AND sandbox_id = ?
                """,
                (
                    captured_snapshot_id,
                    reason,
                    now(),
                    computer["id"],
                    computer["sandbox_id"],
                ),
            )
            cleanup_landed = cursor.rowcount == 1
        persist()
    cleared = get_computer(computer["id"])
    if not cleanup_landed:
        print(
            "BACKLOT_DEAD_SANDBOX_CLEANUP_SKIPPED "
            f"computer_id={computer['id']} workspace_id={computer['workspace_id']} "
            f"expected_sandbox={computer['sandbox_id']} "
            f"current_sandbox={cleared['sandbox_id']} current_status={cleared['status']} "
            "reason=runtime_changed",
            flush=True,
        )
        return cleared
    redact = supervision_redactor(computer)
    message = redact(str(exc)) if exc is not None else "none"
    exception_type = type(exc).__name__ if exc is not None else "none"
    print(
        f"{event} computer_id={computer['id']} workspace_id={computer['workspace_id']} "
        f"sandbox={computer['sandbox_id']} exception_type={exception_type} "
        f"message={json.dumps(message)} reason={reason}",
        flush=True,
    )
    return cleared


class ProviderTaskTerminal(RuntimeError):
    """Stable local type for a provider handle whose task has already finished."""

    def __init__(self, returncode: int):
        self.returncode = returncode
        super().__init__(f"provider task is terminal with returncode {returncode}")


class RuntimeLiveness(NamedTuple):
    """One bounded provider lookup, including the provider-did-not-answer state."""

    computer: sqlite3.Row
    sandbox: Any | None
    state: Literal["unclaimed", "live", "terminal", "unknown"]
    error: Exception | None


class ProviderTaskUnavailable(HTTPException):
    """Stable request result for a runtime whose provider liveness is unknown."""

    def __init__(self, computer: sqlite3.Row, cause: Exception):
        self.cause = cause
        super().__init__(
            503,
            detail={
                "code": "provider_unreachable",
                "computer_id": computer["id"],
                "retryable": True,
                "retry_after": "retry_request",
                "message": (
                    "The provider did not answer the liveness lookup. No runtime "
                    "claims were changed; retry the request."
                ),
            },
        )


def reconcile_runtime_liveness(
    computer: sqlite3.Row,
) -> RuntimeLiveness:
    """Resolve one provider task and heal a registry row that outlived it.

    `Sandbox.from_id` is the narrow authority: Modal 1.5.2 performs a zero-timeout
    SandboxWait RPC there and populates the public `returncode` when the task is
    terminal. A typed NotFound means no handle remains; a non-None returncode means the
    retained handle is terminal. Neither result depends on vendor message text.

    A provider failure is not evidence that the task is gone. It returns `unknown`
    without mutating the row so each caller can apply its own safe fallback. Rows with
    no runtime claim require no provider RPC.
    """
    if not computer["sandbox_id"]:
        return RuntimeLiveness(computer, None, "unclaimed", None)
    try:
        sandbox = modal.Sandbox.from_id(computer["sandbox_id"])
    except modal.exception.NotFoundError as exc:
        return RuntimeLiveness(
            clear_unrecoverable_runtime(
                computer,
                event="BACKLOT_DEAD_SANDBOX_DETACHED",
                exc=exc,
                reason=ERROR_PROVIDER_TASK_MISSING,
            ),
            None,
            "terminal",
            exc,
        )
    except Exception as exc:
        # The lookup itself is the narrow provider boundary. Anything other than the
        # typed terminal answer above means the provider did not answer this pass; it
        # says nothing about whether the task still exists.
        return RuntimeLiveness(computer, None, "unknown", exc)
    returncode = getattr(sandbox, "returncode", None)
    if returncode is not None:
        terminal = ProviderTaskTerminal(returncode)
        return RuntimeLiveness(
            clear_unrecoverable_runtime(
                computer,
                event="BACKLOT_DEAD_SANDBOX_DETACHED",
                exc=terminal,
                reason=ERROR_PROVIDER_TASK_MISSING,
            ),
            None,
            "terminal",
            terminal,
        )
    return RuntimeLiveness(computer, sandbox, "live", None)


def provider_task_missing(computer: sqlite3.Row) -> None:
    """Return the stable consumer contract after in-request terminal cleanup."""
    raise HTTPException(
        409,
        detail={
            "code": ERROR_PROVIDER_TASK_MISSING,
            "computer_id": computer["id"],
            "retryable": True,
            "retry_after": "explicit_start",
            "message": (
                "The provider task disappeared and its dead runtime claims were "
                "cleared. Start the computer explicitly, then retry the request."
            ),
        },
    )


def runtime_for_consumer(
    computer: sqlite3.Row,
    *,
    unknown_event: str,
    require_sandbox: bool = False,
) -> tuple[sqlite3.Row, Any | None]:
    """Return a live runtime without letting reconciliation become an implicit boot."""
    sandbox = None
    if (
        computer["status"] == "error"
        and computer["error_reason"] == ERROR_PROVIDER_TASK_MISSING
    ):
        provider_task_missing(computer)
    if computer["status"] == "running":
        liveness = reconcile_runtime_liveness(computer)
        computer, sandbox = liveness.computer, liveness.sandbox
        if liveness.state == "terminal":
            provider_task_missing(computer)
        if liveness.state == "unknown":
            raise_provider_unreachable(liveness, event=unknown_event)
    else:
        # Preserve the existing on-demand behavior for ordinary stopped/error rows.
        # A row reconciled from provider-missing is refused above and can only boot via
        # the explicit lifecycle endpoint.
        computer = start_runtime(computer["id"])
    if require_sandbox and sandbox is None:
        liveness = reconcile_runtime_liveness(computer)
        computer, sandbox = liveness.computer, liveness.sandbox
        if liveness.state == "terminal":
            provider_task_missing(computer)
        if liveness.state == "unknown":
            raise_provider_unreachable(liveness, event=unknown_event)
    return computer, sandbox


def snapshot_running(computer: sqlite3.Row) -> str | None:
    liveness = reconcile_runtime_liveness(computer)
    computer, sandbox = liveness.computer, liveness.sandbox
    if liveness.state == "terminal":
        return None
    if liveness.state == "unknown":
        raise_provider_unreachable(liveness, event="BACKLOT_SNAPSHOT_LIVENESS_UNKNOWN")
    if sandbox is None:
        raise RuntimeError("a runtime claim did not resolve to a sandbox")
    try:
        image = sandbox.snapshot_filesystem(timeout=120, ttl=snapshot_ttl())
    except modal.exception.NotFoundError as exc:
        clear_unrecoverable_runtime(
            computer,
            event="BACKLOT_DEAD_SANDBOX_DETACHED",
            exc=exc,
        )
        return None
    try:
        sandbox.terminate(wait=True)
    except modal.exception.NotFoundError as exc:
        clear_unrecoverable_runtime(
            computer,
            event="BACKLOT_DEAD_SANDBOX_DETACHED",
            exc=exc,
            captured_snapshot_id=image.object_id,
        )
        return image.object_id
    execute(
        """
        UPDATE computers SET
            status = 'stopped', snapshot_image_id = ?, sandbox_id = NULL,
            agent_url = NULL, agent_token = NULL, vnc_url = NULL, vnc_token = NULL,
            vnc_password = NULL, started_at = NULL, expires_at = NULL,
            error_reason = NULL, status_changed_at = ?, stranded_since = NULL
        WHERE id = ? AND sandbox_id = ?
        """,
        (image.object_id, now(), computer["id"], computer["sandbox_id"]),
    )
    return image.object_id


def stop_runtime(computer_id: str) -> sqlite3.Row:
    with lifecycle_lock_for(computer_id):
        computer = get_computer(computer_id)
        # Gate on the sandbox, not on the status. snapshot_running snapshots before it
        # terminates, so a snapshot that throws leaves the sandbox alive while the row
        # flips to 'error'. Bailing on anything != 'running' made that machine
        # unreachable by every later pass, so the only thing that ever stopped it was
        # Modal's 23 hour cap: a live sandbox billing against a row nobody rechecks.
        if not computer["sandbox_id"]:
            return computer
        snapshot_running(computer)
        return get_computer(computer_id)


def terminate_runtime(computer: sqlite3.Row) -> None:
    if computer["sandbox_id"]:
        liveness = reconcile_runtime_liveness(computer)
        computer, sandbox = liveness.computer, liveness.sandbox
        if liveness.state == "terminal":
            return
        if liveness.state == "unknown":
            raise_provider_unreachable(
                liveness, event="BACKLOT_TERMINATE_LIVENESS_UNKNOWN"
            )
        if sandbox is None:
            raise RuntimeError("a runtime claim did not resolve to a sandbox")
        sandbox.terminate(wait=True)


def touch(computer_id: str) -> None:
    execute("UPDATE computers SET last_active_at = ? WHERE id = ?", (now(), computer_id))


def agent_request(
    computer_id: str,
    action: str,
    body: dict[str, Any] | None = None,
    method: str = "POST",
    *,
    computer: sqlite3.Row | None = None,
) -> dict[str, Any]:
    if computer is None:
        computer, _ = runtime_for_consumer(
            get_computer(computer_id), unknown_event="BACKLOT_AGENT_LIVENESS_UNKNOWN"
        )
    try:
        response = httpx.request(
            method,
            f"{computer['agent_url']}/{action}",
            json=body,
            headers={"Authorization": f"Bearer {computer['agent_token']}"},
            timeout=310,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        # A command killed by its own timeout and an unreachable desktop are both
        # transport-layer failures here. Telling them apart by grepping the message for
        # "408" is a string match on an error string, so carry a code instead.
        status = getattr(getattr(exc, "response", None), "status_code", None)
        code = "command_timeout" if status == 408 else "agent_unreachable"
        requested_timeout = (body or {}).get("timeout")
        detail: dict[str, Any] = {
            "code": code,
            "computer_id": computer_id,
            "action": action,
            "agent_status": status,
            "message": str(exc)[:300],
        }
        if code == "command_timeout":
            # The raw message is an httpx URL dump that says nothing about the cause.
            # An install step legitimately outruns the 30s default, and the caller has
            # no way to know that is what happened unless the error says so.
            # The model fills its default in before this sees the body, so a caller who
            # omitted "timeout" is indistinguishable here from one who sent 30. Report
            # the limit that actually applied and say what the default is, rather than
            # a "was this your choice" flag that cannot be answered honestly.
            detail["timeout_seconds"] = requested_timeout or DEFAULT_ACTION_TIMEOUT
            detail["hint"] = (
                f"The command was killed after {detail['timeout_seconds']}s. This is the "
                "per-command timeout, not a Backlot fault and not a queue. If you did not "
                f'set "timeout", {DEFAULT_ACTION_TIMEOUT}s is the default. Pass a larger '
                f'"timeout" in the request body, up to {MAX_ACTION_TIMEOUT}s. Anything '
                "longer must be detached and polled: see section 8 of the provisioning "
                "contract."
            )
        raise HTTPException(
            502,
            detail,
        ) from exc
    touch(computer_id)
    return response.json()


def vnc_payload(computer: sqlite3.Row) -> dict[str, str]:
    computer, _ = runtime_for_consumer(
        computer, unknown_event="BACKLOT_VNC_LIVENESS_UNKNOWN"
    )
    query = urllib.parse.urlencode(
        {
            "autoconnect": "1",
            "resize": "scale",
            "path": "websockify",
            "_modal_connect_token": computer["vnc_token"],
            "password": computer["vnc_password"],
        }
    )
    return {
        "password": computer["vnc_password"],
        "url": f"{computer['vnc_url']}/vnc.html?{query}",
    }


# Backlot's own control port. A browser-reachable tunnel to it is never what a caller
# means by "let a customer open my app", and handing one out would put the machine's
# command surface on the public internet behind a query-string token.
AGENT_PORT = 8080


def app_payload(computer: sqlite3.Row, port: int) -> dict[str, Any]:
    """Browser-reachable credentials for a web app running inside the machine.

    agent_url is Backlot's own control endpoint and vnc_url is a desktop. Neither is the
    app, so before this existed the only way to reach a web app inside a machine was curl
    from inside the machine, which a browser cannot do.

    Minted per request rather than stored, for the same reason nothing caches agent_url:
    the tunnel host moves on every stop, start and 23 hour rollover, and the old one
    404s. A stored URL is a stale URL waiting to be handed to a customer. Minting also
    means this works on machines that already exist, with no migration and no per-machine
    setting to get wrong.

    The caller names the port because the caller is the one who knows what its template
    runs. Backlot deliberately does not.
    """
    if port == AGENT_PORT:
        raise HTTPException(422, f"port {AGENT_PORT} is Backlot's own control port")
    # A reaped machine still wakes on demand, but a provider-missing runtime returns a
    # typed result and requires explicit start. Reconciliation itself never boots.
    computer, sandbox = runtime_for_consumer(
        computer,
        unknown_event="BACKLOT_APP_LIVENESS_UNKNOWN",
        require_sandbox=True,
    )
    if sandbox is None:
        raise RuntimeError("app token minting requires a live sandbox")
    credentials = sandbox.create_connect_token(
        {"computer_id": computer["id"], "purpose": "app", "port": str(port)}, port=port
    )
    query = urllib.parse.urlencode({"_modal_connect_token": credentials.token})
    return {
        "port": port,
        # host + token are for callers that need to land on a specific path with their own
        # query string, such as a single sign-on handoff. url is the app's front door.
        "host": credentials.url,
        "token": credentials.token,
        "url": f"{credentials.url}/?{query}",
    }


def clone_snapshot(source: sqlite3.Row) -> str:
    if source["status"] == "running":
        liveness = reconcile_runtime_liveness(source)
        source, sandbox = liveness.computer, liveness.sandbox
        if liveness.state == "unknown":
            raise_provider_unreachable(liveness, event="BACKLOT_CLONE_LIVENESS_UNKNOWN")
        if liveness.state == "live":
            if sandbox is None:
                raise RuntimeError("a runtime claim did not resolve to a sandbox")
            return sandbox.snapshot_filesystem(timeout=120, ttl=snapshot_ttl()).object_id
    if not source["snapshot_image_id"]:
        raise HTTPException(409, "Stopped computer has no disk snapshot")
    return source["snapshot_image_id"]


# Waking every minute cost $0.05/hour with an empty fleet, roughly $36/month to run
# Backlot with no customers on it. Measured, receipts/build-cost.json.
SUPERVISOR_WAKE_MINUTES = 5
SUPERVISOR_TICK_SECONDS = 60

BUILD_MEMORY_DEFAULT_MIB = 8192
BUILD_MEMORY_MAX_MIB = 65536
BUILD_CPU_MAX = 16
HARDWARE_KEYS = {"cpu", "ram", "memory_mib", "disk_size_gb"}
# bash reports a SIGKILLed child as 128+9. The OOM killer is by far the most common
# cause in a build, and the raw message is just "Killed" with no mention of memory.
OOM_EXIT_CODE = 137
# Mirrors Bash/Exec in backlot/agent.py. A command longer than this is killed and the
# caller sees a 502, which reads as an infrastructure fault unless the error says
# otherwise.
DEFAULT_ACTION_TIMEOUT = 30
MAX_ACTION_TIMEOUT = 300
NODE_ABORT_EXIT_CODE = 134

# A parallel build is the case that matters and it does NOT present as exit 137. A
# worker is killed, the build tool catches it and exits 1, and the kill shows up only
# as text. Node aborts with 134 and prints a heap message instead of being killed at
# all. Matching only the parent's exit code calls both a compile error, which sends
# someone hunting a bug that is really a memory ceiling.
# cgroup v2 is not exposed in these sandboxes (memory.max and memory.events are absent),
# so there is no oom_kill counter to read and text is the only signal available.
OOM_SIGNATURES = re.compile(
    r"\bKilled\b|signal 9|SIGKILL|exited 137|exit code 137"
    r"|out of memory|heap out of memory|Reached heap limit"
    r"|ENOMEM|Cannot allocate memory|MemoryError",
    re.I,
)
# ulimit -n is 1024 in a build sandbox. A parallel compile of many packages exhausts
# that and dies partway through, which looks exactly like a memory failure.
FD_SIGNATURES = re.compile(r"EMFILE|too many open files", re.I)


REDACTED = "[redacted]"
AUTHORIZATION_RE = re.compile(
    r"(\bAuthorization\s*:\s*(?:Basic|Bearer)\s+)[^\s'\"\\]+", re.I
)
COMMON_TOKEN_RE = re.compile(
    r"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{16,}"
    r"|sk-[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16})\b"
)

# Names and value shapes that mean "this is a credential". Used only to warn: rejecting
# would break a consumer mid-integration, and a build that fails closed teaches people
# to work around the check rather than move the value.
SECRET_KEY_RE = re.compile(
    r"(?:^|_)(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|APIKEY|API_KEY|ACCESS_KEY"
    r"|PRIVATE_KEY|AUTH|AUTHORIZATION|PAT)(?:$|_)",
    re.I,
)
SECRET_VALUE_RE = re.compile(
    r"^(gh[pousr]_|github_pat_|xox[baprs]-|sk-|glpat-|AKIA|Bearer\s+\S)", re.I
)

# Below this length a value is more likely to collide with ordinary build output than to
# be a credential, and blanking every "1" would make logs useless.
MIN_REDACTABLE_SECRET = 8


def redactor_for(values: Iterable[str]) -> Callable[[str], str]:
    """Blank known secret values out of anything about to be stored or returned.

    Longest first, so a secret that contains a shorter one does not leave a tail behind.
    """
    targets = sorted(
        {value for value in values if value and len(value) >= MIN_REDACTABLE_SECRET},
        key=len,
        reverse=True,
    )

    def redact(text: str) -> str:
        if not text:
            return text
        for value in targets:
            text = text.replace(value, REDACTED)
        text = AUTHORIZATION_RE.sub(rf"\1{REDACTED}", text)
        text = COMMON_TOKEN_RE.sub(REDACTED, text)
        return text

    return redact


def supervision_redactor(computer: sqlite3.Row | dict[str, Any]) -> Callable[[str], str]:
    """Redact machine credentials from a supervision failure before it reaches logs."""
    row = dict(computer)
    values = [
        row.get("agent_token"),
        row.get("vnc_token"),
        row.get("vnc_password"),
    ]
    try:
        env = json.loads(row.get("env_json") or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        env = {}
    if isinstance(env, dict):
        values.extend(str(value) for value in env.values())
    return redactor_for(str(value) for value in values if value is not None)


def log_provider_liveness_unknown(liveness: RuntimeLiveness, *, event: str) -> None:
    """Log a provider lookup failure without turning it into registry state."""
    if liveness.state != "unknown" or liveness.error is None:
        raise RuntimeError("provider-unknown logging requires an unknown liveness result")
    computer = liveness.computer
    redact = supervision_redactor(computer)
    message = redact(str(liveness.error))
    print(
        f"{event} computer_id={computer['id']} workspace_id={computer['workspace_id']} "
        f"sandbox={computer['sandbox_id']} "
        f"exception_type={type(liveness.error).__name__} "
        f"message={json.dumps(message)} action=registry_unchanged",
        flush=True,
    )


def raise_provider_unreachable(liveness: RuntimeLiveness, *, event: str) -> None:
    """Expose the stable retryable request result for unknown provider liveness."""
    log_provider_liveness_unknown(liveness, event=event)
    if liveness.error is None:
        raise RuntimeError("provider-unknown result did not retain its exception")
    raise ProviderTaskUnavailable(liveness.computer, liveness.error) from liveness.error


def log_supervision_error(computer: sqlite3.Row, exc: BaseException) -> None:
    """Write one searchable, redacted line with the exception and its traceback."""
    redact = supervision_redactor(computer)
    message = redact(str(exc))
    trace = redact(traceback.format_exc())
    print(
        "BACKLOT_SUPERVISION_ERROR "
        f"computer_id={computer['id']} workspace_id={computer['workspace_id']} "
        f"exception_type={type(exc).__name__} message={json.dumps(message)} "
        f"traceback={json.dumps(trace)}",
        flush=True,
    )


def secretish_env_keys(env: dict[str, str]) -> list[str]:
    """Which env names look like credentials. Names only. Never return a value."""
    return sorted(
        key
        for key, value in env.items()
        if SECRET_KEY_RE.search(key) or SECRET_VALUE_RE.match(str(value or ""))
    )


def tail_for_error(output: str, lines: int = 40, limit: int = 4000) -> str:
    """Keep the end of the output, where the cause is.

    A noisy build streams hundreds of progress lines, and truncating from the front
    throws away the error and keeps the spinner.
    """
    kept = "\n".join(output.splitlines()[-lines:])
    return kept[-limit:]


def build_resources(hardware: dict[str, Any]) -> tuple[float, int]:
    """Resolve build sandbox resources.

    `ram` is accepted in GiB to match ComputerCreate, because silently ignoring it and
    running at the default is how four real builds got OOM killed without anyone being
    able to see why.
    """
    unknown = set(hardware) - HARDWARE_KEYS
    if unknown:
        raise HTTPException(
            422,
            {
                "code": "unknown_hardware_key",
                "unknown": sorted(unknown),
                "accepted": sorted(HARDWARE_KEYS),
            },
        )
    if "memory_mib" in hardware:
        memory = int(hardware["memory_mib"])
    elif "ram" in hardware:
        memory = int(hardware["ram"]) * 1024
    else:
        memory = BUILD_MEMORY_DEFAULT_MIB
    if not 512 <= memory <= BUILD_MEMORY_MAX_MIB:
        raise HTTPException(
            422,
            {
                "code": "memory_out_of_range",
                "requested_mib": memory,
                "min_mib": 512,
                "max_mib": BUILD_MEMORY_MAX_MIB,
            },
        )
    cpu = float(hardware.get("cpu", 1))
    if not 0 < cpu <= BUILD_CPU_MAX:
        raise HTTPException(
            422,
            {"code": "cpu_out_of_range", "requested": cpu, "max": BUILD_CPU_MAX},
        )
    return cpu, memory


def build_template(spec: TemplateBuild) -> dict[str, Any]:
    if not TEMPLATE_REF_RE.fullmatch(spec.ref):
        raise HTTPException(422, "ref must look like namespace/name@1.0.0")
    if one("SELECT ref FROM templates WHERE ref = ?", (spec.ref,)):
        raise HTTPException(409, "Template ref already exists")
    cpu, memory = build_resources(spec.hardware)
    # Secrets reach the sandbox exactly like env and are dropped on the floor after.
    # spec.env is persisted; spec.secrets is not, so a name collision must not let a
    # persisted value quietly win over the one the caller meant to keep out of storage.
    redact = redactor_for(spec.secrets.values())
    exposed = secretish_env_keys(spec.env)
    if exposed:
        print(
            f"BACKLOT_TEMPLATE_ENV_LOOKS_LIKE_SECRET ref={spec.ref} keys={','.join(exposed)}",
            flush=True,
        )
    sandbox = modal.Sandbox.create(
        "sleep",
        "600",
        app=app,
        image=desktop_image,
        timeout=600,
        cpu=cpu,
        memory=memory,
        env={**spec.env, **spec.secrets},
        # Filesystem and exec calls race sandbox startup, and wait_until_ready refuses
        # to wait at all without a probe. `true` succeeding IS the condition we need,
        # since it proves exec works, which is what mkdir and the build commands rely on.
        readiness_probe=modal.Probe.with_exec("true"),
        experimental_options={"vm_runtime": True},
    )
    image = None
    try:
        sandbox.wait_until_ready(timeout=120)
        for path, content in spec.files.items():
            target = PurePosixPath(path)
            if not target.is_absolute() or ".." in target.parts:
                raise HTTPException(422, f"Unsafe template file path: {path}")
            # Modal's filesystem API (mkdir/open) fails with FilesystemExecutionError
            # against vm_runtime sandboxes, which is what Backlot builds on. exec works,
            # so files go in through exec. base64 keeps arbitrary content, quotes and
            # newlines included, away from the shell.
            encoded = base64.b64encode(content.encode()).decode()
            script = (
                f"mkdir -p {shlex.quote(str(target.parent))} && "
                f"printf %s {shlex.quote(encoded)} | base64 -d > {shlex.quote(str(target))}"
            )
            writer = sandbox.exec("bash", "-lc", script, timeout=120)
            stderr = writer.stderr.read()
            if writer.wait() != 0:
                raise HTTPException(
                    422, f"Template file write failed for {path}: {redact(stderr)}"
                )
        commands = spec.build.get("run", [])
        if isinstance(commands, str):
            commands = [commands]
        logs: list[dict[str, Any]] = []
        for command in commands:
            process = sandbox.exec("bash", "-lc", str(command), timeout=300)
            stdout = process.stdout.read()
            stderr = process.stderr.read()
            code = process.wait()
            if code != 0:
                combined = "\n".join(part for part in (stderr, stdout) if part).strip()
                output = (stderr or stdout or "").strip()
                fd_hit = FD_SIGNATURES.search(combined)
                oom_hit = OOM_SIGNATURES.search(combined)
                if fd_hit:
                    raise HTTPException(
                        422,
                        {
                            "code": "build_file_descriptor_limit",
                            "command": redact(str(command))[:200],
                            "exit_code": code,
                            "matched": fd_hit.group(0),
                            "ulimit_nofile": 1024,
                            "hint": (
                                "The build exhausted open file descriptors. The sandbox soft "
                                "limit is 1024, which a parallel compile of many packages will "
                                "hit partway through. Raise it as the first build.run command: "
                                "ulimit -n 8192, or reduce build concurrency."
                            ),
                            "output_tail": redact(tail_for_error(output)),
                            "logs": logs,
                        },
                    )
                # "Killed" with no mention of memory reads like a crash inside the tool.
                # Name the real cause and the limit that caused it.
                if code == OOM_EXIT_CODE or oom_hit or (
                    code == NODE_ABORT_EXIT_CODE and oom_hit
                ):
                    raise HTTPException(
                        422,
                        {
                            "code": "build_out_of_memory",
                            "command": redact(str(command))[:200],
                            "memory_mib": memory,
                            "cpu": cpu,
                            "exit_code": code,
                            "matched": oom_hit.group(0) if oom_hit else f"exit {code}",
                            "hint": (
                                "The build, or a worker it spawned, ran out of memory. Raise it "
                                f'with hardware {{"ram": 16}} or {{"memory_mib": 16384}}, up to '
                                f"{BUILD_MEMORY_MAX_MIB} MiB. Note that raising cpu raises the "
                                "memory floor: parallel workers multiply peak usage, so a build "
                                "that fits at cpu 1 can be killed at cpu 8 with the same ram."
                            ),
                            "output_tail": redact(tail_for_error(output)),
                            "logs": logs,
                        },
                    )
                raise HTTPException(
                    422,
                    {
                        "code": "build_command_failed",
                        "command": redact(str(command))[:200],
                        "exit_code": code,
                        "output_tail": redact(tail_for_error(output)),
                        "logs": logs,
                    },
                )
            logs.append(
                {
                    "command": redact(str(command))[:200],
                    "exit_code": code,
                    "output_tail": redact(tail_for_error(stdout or "", lines=20, limit=2000)),
                }
            )
        image = sandbox.snapshot_filesystem(timeout=120, ttl=None)
    finally:
        sandbox.terminate(wait=True)
    # Redacted on the way in, not on the way out. spec_json holds build.run and files
    # verbatim, so a credential inlined into a command or written into a file would be
    # persisted just as permanently as one in env. Reading it back redacted would not
    # help: the value would still be sitting in a row that cannot be deleted.
    execute(
        "INSERT INTO templates(ref, image_id, spec_json, created_at) VALUES (?, ?, ?, ?)",
        (spec.ref, image.object_id, redact(spec.model_dump_json()), now()),
    )
    # Build output used to be reachable only by making a step fail, so measuring
    # anything about the build environment meant deliberately breaking the build.
    return {"ref": spec.ref, "image_id": image.object_id, "logs": logs}


def register_template(spec: TemplateRegister) -> dict[str, Any]:
    """Register an existing image without resolving or otherwise touching it in Modal."""
    if not TEMPLATE_REF_RE.fullmatch(spec.ref):
        raise HTTPException(422, "ref must look like namespace/name@1.0.0")
    resolution_parts(spec.hardware.resolution)
    # Construct the row through TemplateBuild so a registered template has the exact
    # persisted shape of an equivalent build with no env, files, secrets, or commands.
    spec_json = TemplateBuild(
        ref=spec.ref,
        name=spec.name,
        purpose=spec.purpose,
        hardware=spec.hardware.model_dump(),
    ).model_dump_json()

    with runtime_lock:
        with closing(connect()) as connection, connection:
            existing = connection.execute(
                "SELECT * FROM templates WHERE ref = ?", (spec.ref,)
            ).fetchone()
            if existing:
                if existing["image_id"] != spec.image_id:
                    raise HTTPException(
                        409,
                        {
                            "code": "template_registration_conflict",
                            "ref": spec.ref,
                            "field": "image_id",
                            "stored": existing["image_id"],
                            "requested": spec.image_id,
                        },
                    )
                if existing["spec_json"] != spec_json:
                    raise HTTPException(
                        409,
                        {
                            "code": "template_registration_conflict",
                            "ref": spec.ref,
                            "field": "spec_json",
                            "stored_sha256": hashlib.sha256(
                                existing["spec_json"].encode()
                            ).hexdigest(),
                            "requested_sha256": hashlib.sha256(
                                spec_json.encode()
                            ).hexdigest(),
                        },
                    )
                return template_public(existing)

            created_at = now()
            connection.execute(
                "INSERT INTO templates(ref, image_id, spec_json, created_at) "
                "VALUES (?, ?, ?, ?)",
                (spec.ref, spec.image_id, spec_json, created_at),
            )
            created = connection.execute(
                "SELECT * FROM templates WHERE ref = ?", (spec.ref,)
            ).fetchone()
        persist()
    assert created is not None
    return template_public(created)


def compare_and_swap_template_binding(
    computer_id: str, body: TemplateBinding
) -> tuple[int, sqlite3.Row | None]:
    """Atomically bind one stopped row; the statement's only write is template_ref."""
    with runtime_lock:
        with closing(connect()) as connection, connection:
            cursor = connection.execute(
                """
                UPDATE computers SET template_ref = ?
                 WHERE id = ? AND workspace_id = ? AND status = 'stopped'
                   AND sandbox_id IS NULL AND snapshot_image_id IS ?
                   AND template_ref IS ?
                """,
                (
                    body.template_ref,
                    computer_id,
                    body.expected_workspace_id,
                    body.expected_snapshot_image_id,
                    body.expected_template_ref,
                ),
            )
            rowcount = cursor.rowcount
            failed_row = (
                connection.execute(
                    "SELECT * FROM computers WHERE id = ?", (computer_id,)
                ).fetchone()
                if rowcount == 0
                else None
            )
        if rowcount == 1:
            persist()
    return rowcount, failed_row


def template_binding_failures(
    row: sqlite3.Row | None, body: TemplateBinding
) -> list[str]:
    if row is None:
        return ["not_found"]
    checks = (
        ("not_stopped", row["status"] != "stopped"),
        ("sandbox_present", row["sandbox_id"] is not None),
        ("workspace_mismatch", row["workspace_id"] != body.expected_workspace_id),
        ("template_ref_mismatch", row["template_ref"] != body.expected_template_ref),
        (
            "snapshot_mismatch",
            row["snapshot_image_id"] != body.expected_snapshot_image_id,
        ),
    )
    return [name for name, failed in checks if failed]


def openai_messages(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    system: list[str] = []
    converted: list[dict[str, Any]] = []
    for message in messages:
        role = message.get("role")
        content = message.get("content", "")
        if isinstance(content, list):
            content = "\n".join(
                item.get("text", "") for item in content if item.get("type") == "text"
            )
        if role == "system":
            system.append(str(content))
        elif role in ("user", "assistant"):
            converted.append({"role": role, "content": str(content)})
    return "\n".join(system), converted


def load_thread(thread_id: str | None, computer_id: str) -> list[dict[str, Any]]:
    if not thread_id:
        return []
    row = one(
        "SELECT messages_json FROM threads WHERE id = ? AND computer_id = ?",
        (thread_id, computer_id),
    )
    return json.loads(row["messages_json"]) if row else []


def save_thread(thread_id: str, computer_id: str, messages: list[dict[str, Any]]) -> None:
    execute(
        """
        INSERT INTO threads(id, computer_id, messages_json, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET messages_json = excluded.messages_json,
                                      updated_at = excluded.updated_at
        """,
        (thread_id, computer_id, json.dumps(messages), now()),
    )


def computer_action(
    computer_id: str,
    inputs: dict[str, Any],
    *,
    computer: sqlite3.Row | None = None,
) -> dict[str, Any]:
    def request(
        action: str, body: dict[str, Any] | None = None, method: str = "POST"
    ) -> dict[str, Any]:
        return agent_request(
            computer_id, action, body, method, computer=computer
        )

    action = inputs.get("action")
    try:
        if action == "screenshot":
            result = request("screenshot", method="GET")
        elif action in ("left_click", "right_click", "middle_click", "double_click"):
            coordinate = inputs.get("coordinate")
            payload: dict[str, Any] = {
                "x": coordinate[0] if coordinate else 0,
                "y": coordinate[1] if coordinate else 0,
                "button": {
                    "right_click": "right",
                    "middle_click": "middle",
                }.get(action, "left"),
                "double": action == "double_click",
            }
            result = request("click", payload)
        elif action == "left_click_drag":
            start = inputs["start_coordinate"]
            end = inputs["coordinate"]
            result = request(
                "drag",
                {
                    "start_x": start[0],
                    "start_y": start[1],
                    "end_x": end[0],
                    "end_y": end[1],
                    "duration": inputs.get("duration", 0.5),
                },
            )
        elif action == "type":
            result = request("type", {"text": inputs["text"]})
        elif action == "key":
            result = request("key", {"key": inputs["text"]})
        elif action == "scroll":
            result = request(
                "scroll",
                {
                    "direction": inputs["scroll_direction"],
                    "amount": inputs.get("scroll_amount", 3),
                },
            )
        elif action == "wait":
            result = request("wait", {"seconds": inputs.get("duration", 1)})
        elif action == "mouse_move":
            x, y = inputs["coordinate"]
            result = request(
                "bash", {"command": f"xdotool mousemove {int(x)} {int(y)}"}
            )
        elif action == "cursor_position":
            result = request(
                "bash",
                {"command": "xdotool getmouselocation --shell"},
            )
        elif action in ("left_mouse_down", "left_mouse_up"):
            command = "xdotool mousedown 1" if action.endswith("down") else "xdotool mouseup 1"
            result = request("bash", {"command": command})
        elif action == "hold_key":
            key = inputs["text"]
            if not re.fullmatch(r"[A-Za-z0-9_+\-]+", key):
                raise ValueError("Invalid hold_key")
            duration = min(60.0, max(0.0, float(inputs.get("duration", 1))))
            result = request(
                "bash",
                {"command": f"xdotool keydown {key}; sleep {duration}; xdotool keyup {key}"},
            )
        else:
            raise ValueError(f"Unsupported computer action: {action}")
        clean = {key: value for key, value in result.items() if key != "screenshot"}
        clean.setdefault("success", True)
        for field in ("stdout", "stderr"):
            if field in clean:
                clean[field] = str(clean[field])[:4000]
        return clean
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def desktop_message(
    computer_id: str, *, computer: sqlite3.Row | None = None
) -> dict[str, Any]:
    screenshot = agent_request(
        computer_id, "screenshot", method="GET", computer=computer
    )
    return {
        "role": "user",
        "content": [
            {"type": "text", "text": "Current Linux desktop:"},
            {
                "type": "image_url",
                "image_url": {
                    "url": f"data:image/png;base64,{screenshot['screenshot']}",
                },
            },
        ],
    }


COMPUTER_TOOL = {
    "type": "function",
    "function": {
        "name": "computer",
        "description": "Observe and operate the current Linux desktop.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "screenshot",
                        "left_click",
                        "right_click",
                        "middle_click",
                        "double_click",
                        "left_click_drag",
                        "type",
                        "key",
                        "scroll",
                        "wait",
                        "mouse_move",
                        "cursor_position",
                        "left_mouse_down",
                        "left_mouse_up",
                        "hold_key",
                    ],
                },
                "coordinate": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "minItems": 2,
                    "maxItems": 2,
                },
                "start_coordinate": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "minItems": 2,
                    "maxItems": 2,
                },
                "text": {"type": "string"},
                "scroll_direction": {
                    "type": "string",
                    "enum": ["up", "down", "left", "right"],
                },
                "scroll_amount": {"type": "integer", "minimum": 0, "maximum": 100},
                "duration": {"type": "number", "minimum": 0, "maximum": 60},
            },
            "required": ["action"],
        },
    },
}


def run_chat(body: ChatCompletion) -> dict[str, Any]:
    computer, _ = runtime_for_consumer(
        get_computer(body.computer_id), unknown_event="BACKLOT_CHAT_LIVENESS_UNKNOWN"
    )
    system, incoming = openai_messages(body.messages)
    thread_id = body.thread_id or f"thread_{uuid.uuid4().hex}"
    messages = load_thread(body.thread_id, body.computer_id)
    messages.extend(incoming)
    messages.append(desktop_message(body.computer_id, computer=computer))
    provider_model = os.environ.get("BACKLOT_PROVIDER_MODEL", "openai/gpt-4.1-mini")
    provider_url = os.environ.get(
        "BACKLOT_PROVIDER_URL", "https://openrouter.ai/api/v1/chat/completions"
    )
    provider_key = os.environ.get("OPENROUTER_API_KEY")
    if not provider_key:
        raise HTTPException(503, "OPENROUTER_API_KEY is not configured")
    final_text = ""
    finish_reason = "length"
    usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    for _ in range(body.max_steps):
        response = httpx.post(
            provider_url,
            headers={
                "Authorization": f"Bearer {provider_key}",
                "HTTP-Referer": "https://example.invalid",
                "X-Title": "Backlot",
            },
            json={
                "model": provider_model,
                "max_tokens": body.max_tokens,
                "messages": [
                    {
                        "role": "system",
                        "content": system
                        or (
                            "Complete the user's task on the Linux desktop. "
                            "Use the computer tool for every interaction, inspect each "
                            "new screenshot, and stop only when the visible task is done."
                        ),
                    },
                    *messages,
                ],
                "tools": [COMPUTER_TOOL],
                "tool_choice": "auto",
            },
            timeout=180,
        )
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise HTTPException(502, f"OpenRouter failed: {response.text[:1000]}") from exc
        data = response.json()
        choice = data["choices"][0]
        message = choice["message"]
        tool_calls = message.get("tool_calls") or []
        final_text = message.get("content") or ""
        assistant_message = {"role": "assistant", "content": final_text}
        if tool_calls:
            assistant_message["tool_calls"] = tool_calls
        messages.append(assistant_message)
        provider_usage = data.get("usage") or {}
        usage["prompt_tokens"] += provider_usage.get("prompt_tokens", 0)
        usage["completion_tokens"] += provider_usage.get("completion_tokens", 0)
        if not tool_calls:
            finish_reason = "stop"
            break
        for call in tool_calls:
            try:
                arguments = json.loads(call["function"]["arguments"])
            except (KeyError, json.JSONDecodeError) as exc:
                result = {"success": False, "error": f"Invalid tool arguments: {exc}"}
            else:
                # Do not carry the opening row through the whole tool loop. A machine
                # can be reaped or rolled over while the model is thinking; each later
                # agent request must re-read and reconcile the current runtime.
                result = computer_action(body.computer_id, arguments)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call["id"],
                    "content": json.dumps(result),
                }
            )
        messages.append(desktop_message(body.computer_id))
    usage["total_tokens"] = usage["prompt_tokens"] + usage["completion_tokens"]
    save_thread(thread_id, body.computer_id, messages)
    return {
        "id": f"chatcmpl_{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": now(),
        "model": provider_model,
        "requested_model": body.model,
        "provider_model": provider_model,
        "thread_id": thread_id,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": final_text},
                "finish_reason": finish_reason,
            }
        ],
        "usage": usage,
    }


def stream_completion(completion: dict[str, Any]):
    choice = completion["choices"][0]
    chunk = {
        "id": completion["id"],
        "object": "chat.completion.chunk",
        "created": completion["created"],
        "model": completion["model"],
        "choices": [
            {
                "index": 0,
                "delta": {
                    "role": "assistant",
                    "content": choice["message"]["content"],
                },
                "finish_reason": choice["finish_reason"],
            }
        ],
    }
    yield f"data: {json.dumps(chunk)}\n\n"
    yield "data: [DONE]\n\n"


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


def make_api() -> FastAPI:
    api = FastAPI(title="Backlot", version="0.1.0", lifespan=lifespan)

    @api.middleware("http")
    async def bind_execution_class(request: Request, call_next):
        """Bind the request's execution class before any route runs.

        Absent header means unbounded, which is every caller that exists today,
        so this changes nothing for them. Only the strings "1", "true" and "yes"
        turn the refusal on: anything else, including a typo or an empty value,
        leaves the machine bootable. That direction is deliberate. Failing open
        here costs at most one boot the caller could already have had, whereas
        failing closed on a malformed header would refuse work for a caller who
        never asked to be bounded, and would do it on the live customer path.

        The token is reset in a finally block. Under a worker that reuses the
        context across requests, a leaked True would refuse boots for unrelated
        callers, which is exactly the silent, hard-to-attribute failure this
        whole gate exists to prevent.
        """
        raw = request.headers.get(BOUNDED_EXECUTION_HEADER, "")
        token = BOUNDED_EXECUTION.set(raw.strip().lower() in {"1", "true", "yes"})
        try:
            return await call_next(request)
        finally:
            BOUNDED_EXECUTION.reset(token)

    @api.get("/health")
    def health() -> dict[str, Any]:
        # A literal 200 proves only that a container answered. Touch the registry so a
        # readable database is part of the claim.
        try:
            reload_registry()
            workspaces = one("SELECT COUNT(*) AS n FROM workspaces")["n"]
        except Exception:
            raise HTTPException(503, {"code": "registry_unreadable", "service": APP_NAME})
        return {
            "ok": True,
            "service": APP_NAME,
            "registry": "readable",
            "workspaces": workspaces,
            # Reported always, enforced only on the bounded surface. Drift that
            # is visible on every health check is drift somebody can act on
            # before it is load-bearing; drift discovered during an incident is
            # not.
            "clock": clock_state(),
            # Reported so the absence of key material is visible on a health
            # read rather than discovered the first time someone asks for a
            # signed acknowledgement.
            "signing": signing_state(),
        }

    @api.get("/workspaces/{workspace_id}/health")
    @api.get("/projects/{workspace_id}/health")
    def workspace_health(workspace_id: str, current: Principal = Depends(principal)):
        get_workspace(workspace_id, current)
        current_time = now()
        rows = many(
            "SELECT * FROM computers WHERE workspace_id = ? ORDER BY created_at",
            (workspace_id,),
        )
        computers = [runtime_health(row, current_time) for row in rows]
        degraded = [c for c in computers if not c["healthy"]]
        return {
            "workspace_id": workspace_id,
            "healthy": not degraded,
            "reason": degraded[0]["reason"] if degraded else None,
            "checked_at": current_time,
            "counts": {
                "total": len(computers),
                "running": sum(1 for c in computers if c["status"] == "running"),
                "stopped": sum(1 for c in computers if c["status"] == "stopped"),
                "error": sum(1 for c in computers if c["status"] == "error"),
                "stale": sum(1 for c in computers if c["stale"]),
            },
            "computers": computers,
        }

    @api.get("/", response_class=HTMLResponse)
    @api.get("/admin", response_class=HTMLResponse)
    @api.get("/library", response_class=HTMLResponse)
    def yard() -> str:
        return YARD_HTML

    @api.get("/computer/{computer_id}", response_class=HTMLResponse)
    @api.get("/computer/{computer_id}/desktop", response_class=HTMLResponse)
    def computer_yard(computer_id: str) -> str:
        return YARD_HTML

    @api.post("/workspaces")
    @api.post("/projects")
    def create_workspace(body: WorkspaceCreate, current: Principal = Depends(principal)):
        require_admin(current)
        workspace_id = f"ws_{uuid.uuid4().hex}"
        # Ownership comes from the authenticating key, never from the request body, so a
        # caller cannot claim to be someone else and cannot forget to say who they are.
        execute(
            """
            INSERT INTO workspaces(id, name, created_at, created_by, created_by_key)
            VALUES (?, ?, ?, ?, ?)
            """,
            (workspace_id, body.name, now(), current.key_name, current.key_id),
        )
        return row_dict(get_workspace(workspace_id, current))

    @api.get("/workspaces")
    @api.get("/projects")
    def list_workspaces(
        created_by: str | None = None, current: Principal = Depends(principal)
    ):
        if created_by is not None:
            # Lets a reconciler ask "which of these are mine" instead of guessing from
            # names. Scope still applies: a scoped key sees only its own workspace.
            rows = many(
                "SELECT * FROM workspaces WHERE created_by = ? ORDER BY created_at",
                (created_by,),
            )
            if current.workspace_id:
                rows = [r for r in rows if r["id"] == current.workspace_id]
            return [row_dict(row) for row in rows]
        if current.workspace_id:
            return [row_dict(get_workspace(current.workspace_id, current))]
        return [row_dict(row) for row in many("SELECT * FROM workspaces ORDER BY created_at")]

    @api.get("/workspaces/{workspace_id}")
    @api.get("/projects/{workspace_id}")
    def read_workspace(workspace_id: str, current: Principal = Depends(principal)):
        return row_dict(get_workspace(workspace_id, current))

    @api.delete("/workspaces/{workspace_id}")
    @api.delete("/projects/{workspace_id}")
    def delete_workspace(workspace_id: str, current: Principal = Depends(principal)):
        get_workspace(workspace_id, current)
        require_admin(current)
        try:
            execute("DELETE FROM workspaces WHERE id = ?", (workspace_id,))
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "Workspace still has computers") from exc
        print(
            f"BACKLOT_WORKSPACE_DELETED id={workspace_id} by={current.key_name} "
            f"key={current.key_id}",
            flush=True,
        )
        return {"deleted": True, "id": workspace_id}

    @api.get("/api-keys")
    def list_keys(current: Principal = Depends(principal)):
        require_admin(current)
        return [
            {
                "id": row["id"],
                "name": row["name"],
                "workspace_id": row["workspace_id"],
                "created_at": row["created_at"],
            }
            for row in many(
                """
                SELECT id, name, workspace_id, created_at
                FROM api_keys
                WHERE workspace_id IS NOT NULL
                ORDER BY created_at
                """
            )
        ]

    @api.post("/api-keys")
    def create_key(body: ApiKeyCreate, current: Principal = Depends(principal)):
        require_admin(current)
        get_workspace(body.workspace_id, current)
        raw = f"backlot_{secrets.token_urlsafe(32)}"
        key_id = f"key_{uuid.uuid4().hex}"
        execute(
            """
            INSERT INTO api_keys(id, name, key_hash, workspace_id, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (key_id, body.name, hash_key(raw), body.workspace_id, now()),
        )
        return {"id": key_id, "key": raw, "workspace_id": body.workspace_id}

    @api.delete("/api-keys/{key_id}")
    def revoke_key(key_id: str, current: Principal = Depends(principal)):
        require_admin(current)
        key = one("SELECT workspace_id FROM api_keys WHERE id = ?", (key_id,))
        if not key or key["workspace_id"] is None:
            raise HTTPException(404, "Workspace API key not found")
        execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        return {"deleted": True, "id": key_id}

    @api.post("/computers")
    def create_computer(body: ComputerCreate, current: Principal = Depends(principal)):
        get_workspace(body.workspace_id, current)
        resolution_parts(body.resolution)
        if body.template_ref and not one(
            "SELECT ref FROM templates WHERE ref = ?", (body.template_ref,)
        ):
            raise HTTPException(422, "Unknown template_ref")
        ceiling = workspace_computer_ceiling()
        in_workspace = one(
            "SELECT COUNT(*) AS n FROM computers WHERE workspace_id = ?",
            (body.workspace_id,),
        )["n"]
        if in_workspace >= ceiling:
            # Loud on purpose: every VM past this point would have billed OpSpot.
            print(
                f"BACKLOT_CEILING_HIT workspace={body.workspace_id} "
                f"computers={in_workspace} ceiling={ceiling}",
                flush=True,
            )
            raise HTTPException(
                429,
                {
                    "code": "workspace_computer_ceiling",
                    "ceiling": ceiling,
                    "computers": in_workspace,
                },
            )
        computer_id = f"computer_{uuid.uuid4().hex}"
        execute(
            """
            INSERT INTO computers(
                id, workspace_id, name, ram, cpu, disk_size_gb, resolution,
                template_ref, idle_timeout_minutes, status, env_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'stopped', ?, ?)
            """,
            (
                computer_id,
                body.workspace_id,
                body.name,
                body.ram,
                body.cpu,
                body.disk_size_gb,
                body.resolution,
                body.template_ref,
                body.idle_timeout_minutes,
                validate_env(body.env),
                now(),
            ),
        )
        try:
            return computer_public(start_runtime(computer_id, implicit=False))
        except Exception:
            execute("DELETE FROM computers WHERE id = ?", (computer_id,))
            print(
                f"BACKLOT_COMPUTER_DELETED id={computer_id} "
                f"workspace={body.workspace_id} by={current.key_name} "
                f"key={current.key_id} reason=first_boot_rollback",
                flush=True,
            )
            raise

    @api.get("/computers")
    def list_computers(
        workspace_id: str | None = None, current: Principal = Depends(principal)
    ):
        if workspace_id:
            # Enforce scope on the filter instead of ignoring it. Silently returning the
            # caller's own rows for somebody else's workspace_id makes a reconcile read
            # "nothing here" and boot the duplicate the reconcile exists to prevent.
            get_workspace(workspace_id, current)
            rows = many(
                "SELECT * FROM computers WHERE workspace_id = ? ORDER BY created_at",
                (workspace_id,),
            )
        elif current.workspace_id:
            rows = many(
                "SELECT * FROM computers WHERE workspace_id = ? ORDER BY created_at",
                (current.workspace_id,),
            )
        else:
            rows = many("SELECT * FROM computers ORDER BY created_at")
        return [computer_public(row) for row in rows]

    @api.get("/computers/{computer_id}")
    def read_computer(computer_id: str, current: Principal = Depends(principal)):
        liveness = reconcile_runtime_liveness(get_computer(computer_id, current))
        if liveness.state == "unknown":
            # This was a registry-only read before provider reconciliation existed.
            # Unknown provider health restores that behavior for this pass without
            # turning an observability failure into customer state.
            log_provider_liveness_unknown(
                liveness, event="BACKLOT_SINGLE_READ_LIVENESS_UNKNOWN"
            )
        return computer_public(liveness.computer)

    @api.delete("/computers/{computer_id}")
    def delete_computer(computer_id: str, current: Principal = Depends(principal)):
        computer = get_computer(computer_id, current)
        terminate_runtime(computer)
        execute("DELETE FROM computers WHERE id = ?", (computer_id,))
        # Two machines vanished and nobody could say what removed them, because a row
        # leaving the registry was the one lifecycle event Backlot never recorded. The
        # key name, not just its id, so a rotation does not orphan the trail.
        print(
            f"BACKLOT_COMPUTER_DELETED id={computer_id} "
            f"workspace={computer['workspace_id']} by={current.key_name} "
            f"key={current.key_id} reason=api_delete",
            flush=True,
        )
        return {"deleted": True, "id": computer_id}

    @api.get("/computers/{computer_id}/vnc-password")
    def vnc_password(computer_id: str, current: Principal = Depends(principal)):
        return vnc_payload(get_computer(computer_id, current))

    @api.get("/computers/{computer_id}/app-url")
    def app_url(
        computer_id: str,
        port: int = Query(ge=1, le=65535),
        current: Principal = Depends(principal),
    ):
        return app_payload(get_computer(computer_id, current), port)

    @api.get("/runtime-keys")
    def runtime_key_set(current: Principal = Depends(principal)):
        """Public verification material for this runtime. Authenticated.

        Public keys are safe to publish, but INTERNAL-ONLY is product law for
        this lane and "safe to publish" is not a reason to grow an
        unauthenticated surface. Any consumer that needs to verify a Backlot
        signature already holds a bearer key.

        Both the active and the overlapping previous key are listed, because a
        lease minted before a rotation is verified against the OLD thumbprint
        until it is provably dead at exp + clock_skew_bound. Publishing only the
        active key would silently invalidate every lease in flight at the moment
        of rotation.
        """
        keys = runtime_keys()
        return {
            "algorithm": "Ed25519",
            "alg": "EdDSA",
            "keys": [
                {"use": label, "thumbprint": entry["thumbprint"], **entry["jwk"]}
                for label, entry in keys.items()
            ],
            "rotation": (
                "Overlap based. The previous key stays published and loaded "
                "until the last lease bound to it is dead at exp + "
                "clock_skew_bound. Retiring it earlier invalidates leases that "
                "were valid when they were minted."
            ),
        }

    @api.post("/admin/clock-trust")
    def clock_trust(body: ClockTrust, current: Principal = Depends(principal)):
        """Declare the clock untrusted for a bounded window. Admin key only.

        One-directional by construction: it can withdraw trust, never grant it,
        so it cannot mask real drift. Bounded and self-expiring, so a forgotten
        override cannot become permanent. Measured on the monotonic clock, so a
        wall-clock jump cannot be used to escape it early.
        """
        require_admin(current)
        state = declare_clock_untrusted(body.untrusted_for_seconds)
        print(
            f"BACKLOT_CLOCK_TRUST_DECLARED seconds={body.untrusted_for_seconds} "
            f"by={current.key_name} key={current.key_id} trusted={state['trusted']}"
        )
        return state

    @api.post("/computers/{computer_id}/start")
    def start(computer_id: str, current: Principal = Depends(principal)):
        get_computer(computer_id, current)
        # The explicit provisioning path. A bounded caller reaches a boot
        # through here, deliberately, or not at all.
        return computer_public(start_runtime(computer_id, implicit=False))

    @api.post("/computers/{computer_id}/stop")
    def stop(computer_id: str, current: Principal = Depends(principal)):
        get_computer(computer_id, current)
        return computer_public(stop_runtime(computer_id))

    @api.post("/computers/{computer_id}/restart")
    def restart(computer_id: str, current: Principal = Depends(principal)):
        get_computer(computer_id, current)
        stop_runtime(computer_id)
        return computer_public(start_runtime(computer_id, implicit=False))

    @api.post("/clone")
    def clone(body: CloneComputer, current: Principal = Depends(principal)):
        source = get_computer(body.computer_id, current)
        clone_id = f"computer_{uuid.uuid4().hex}"
        snapshot_id = clone_snapshot(source)
        execute(
            """
            INSERT INTO computers(
                id, workspace_id, name, ram, cpu, disk_size_gb, resolution,
                template_ref, idle_timeout_minutes, status, snapshot_image_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'stopped', ?, ?)
            """,
            (
                clone_id,
                source["workspace_id"],
                body.name or f"{source['name']} copy",
                source["ram"],
                source["cpu"],
                source["disk_size_gb"],
                source["resolution"],
                source["template_ref"],
                source["idle_timeout_minutes"],
                snapshot_id,
                now(),
            ),
        )
        return computer_public(get_computer(clone_id, current))

    @api.patch("/computers/{computer_id}/resize")
    def resize(
        computer_id: str,
        body: ComputerResize,
        current: Principal = Depends(principal),
    ):
        computer = get_computer(computer_id, current)
        was_running = computer["status"] == "running"
        if was_running:
            stop_runtime(computer_id)
        execute(
            "UPDATE computers SET ram = ?, cpu = ? WHERE id = ?",
            (body.ram or computer["ram"], body.cpu or computer["cpu"], computer_id),
        )
        resized = (
            start_runtime(computer_id, implicit=False)
            if was_running
            else get_computer(computer_id)
        )
        return {**computer_public(resized), "rebooted": was_running}

    @api.patch("/computers/{computer_id}/move")
    def move(
        computer_id: str,
        body: ComputerMove,
        current: Principal = Depends(principal),
    ):
        computer = get_computer(computer_id, current)
        require_admin(current)
        get_workspace(body.workspace_id, current)
        execute(
            "UPDATE computers SET workspace_id = ? WHERE id = ?",
            (body.workspace_id, computer_id),
        )
        return computer_public(get_computer(computer_id))

    @api.patch("/computers/{computer_id}/template-binding")
    def update_template_binding(
        computer_id: str,
        body: TemplateBinding,
        current: Principal = Depends(principal),
    ):
        require_admin(current)
        try:
            rowcount, failed_row = compare_and_swap_template_binding(computer_id, body)
        except sqlite3.IntegrityError as exc:
            if body.template_ref is not None and not one(
                "SELECT ref FROM templates WHERE ref = ?", (body.template_ref,)
            ):
                raise HTTPException(
                    404,
                    {"code": "unknown_template_ref", "ref": body.template_ref},
                ) from exc
            raise
        if rowcount == 0:
            failures = template_binding_failures(failed_row, body)
            assert failures, "zero-row binding update had no failed precondition"
            detail = {
                "code": failures[0],
                "computer_id": computer_id,
                "failed_preconditions": failures,
            }
            raise HTTPException(409, detail)
        assert rowcount == 1, f"template binding updated {rowcount} rows"
        return computer_public(get_computer(computer_id))

    @api.get("/computers/{computer_id}/screenshot")
    def screenshot(computer_id: str, current: Principal = Depends(principal)):
        get_computer(computer_id, current)
        return agent_request(computer_id, "screenshot", method="GET")

    @api.post("/computers/{computer_id}/{action}")
    async def action(
        computer_id: str,
        action: str,
        request: Request,
        current: Principal = Depends(principal),
    ):
        get_computer(computer_id, current)
        model = ACTION_MODELS.get(action)
        if not model:
            raise HTTPException(404, "Unknown action")
        try:
            body = model.model_validate(await request.json())
        except (ValidationError, ValueError) as exc:
            raise HTTPException(422, detail=json.loads(exc.json())) from exc
        return await asyncio.to_thread(
            agent_request, computer_id, action, body.model_dump()
        )

    @api.get("/templates")
    def list_templates(current: Principal = Depends(principal)):
        require_admin(current)
        return [template_public(row) for row in many("SELECT * FROM templates ORDER BY created_at")]

    @api.post("/templates/build")
    def create_template(body: TemplateBuild, current: Principal = Depends(principal)):
        require_admin(current)
        return build_template(body)

    @api.post("/templates/register")
    def register_existing_template(
        body: TemplateRegister, current: Principal = Depends(principal)
    ):
        require_admin(current)
        return register_template(body)

    @api.delete("/templates/{namespace}/{name}")
    def delete_template(
        namespace: str, name: str, current: Principal = Depends(principal)
    ):
        require_admin(current)
        ref = f"{namespace}/{name}"
        row = one("SELECT ref FROM templates WHERE ref = ?", (ref,))
        if not row:
            raise HTTPException(404, "Template not found")
        if ref == CURATED_TEMPLATE_REF:
            raise HTTPException(
                409,
                {"code": "curated_template_protected", "ref": ref},
            )
        in_use = one(
            "SELECT COUNT(*) AS n FROM computers WHERE template_ref = ?", (ref,)
        )["n"]
        if in_use:
            # The image backs their disk. Deleting the row would orphan them.
            raise HTTPException(
                409,
                {"code": "template_in_use", "ref": ref, "computers": in_use},
            )
        execute("DELETE FROM templates WHERE ref = ?", (ref,))
        # Modal exposes no image delete, so the underlying image survives regardless.
        return {"deleted": True, "ref": ref, "image_retained": True}

    @api.post("/supervise")
    def run_supervisor(current: Principal = Depends(principal)):
        """Reap idle machines and roll over expiring ones, inside the single writer.

        The scheduled supervisor used to mount the registry volume and write it from its
        own container. Modal volumes are last-write-wins with no distributed locking, so
        a supervisor commit made from a copy loaded before a web write erased that write,
        and a successfully built template disappeared that way. web carries
        max_containers=1, so doing the writes here makes that intent real.
        """
        require_admin(current)
        running = supervise_once()
        return {"running": running, "checked_at": now()}

    @api.get("/template-schema")
    def template_schema():
        return {
            "apiVersion": "backlot/v1",
            "supported": ["hardware", "env", "secrets", "build.run", "files"],
            # env, files and build.run are persisted in the registry row. secrets is
            # not, and its values are redacted from logs. A caller reading this endpoint
            # to decide where to put a token needs that difference stated, not implied.
            "persisted": ["hardware", "env", "build.run", "files"],
            "not_persisted": ["secrets"],
            "ref": "namespace/name@semver",
        }

    @api.post("/v1/chat/completions")
    async def chat(body: ChatCompletion, current: Principal = Depends(principal)):
        get_computer(body.computer_id, current)
        completion = await asyncio.to_thread(run_chat, body)
        if body.stream:
            return StreamingResponse(stream_completion(completion), media_type="text/event-stream")
        return completion

    return api


api = make_api()


@app.function(image=desktop_image)
def desktop_image_ready():
    return True


@app.function(
    image=control_image,
    volumes={"/data": registry_volume},
    secrets=[backlot_secret],
    # ONE container, still, and that is what keeps the registry single-writer: one
    # process, one mount. What changed is that this container now serves several
    # requests at once. Feeding it one input at a time meant a 30s stop blocked every
    # unrelated call behind it, and a caller whose timeout was shorter than the queue
    # saw a failure while these logs recorded a clean 200.
    max_containers=1,
    timeout=600,
)
@modal.concurrent(max_inputs=8)
@modal.asgi_app()
def web():
    return api


def supervisor_tick(base_url: str, key: str) -> int:
    """Ask the single writer to do one pass. Returns how many machines are running."""
    response = httpx.post(
        f"{base_url.rstrip('/')}/supervise",
        headers={"Authorization": f"Bearer {key}"},
        timeout=600,
    )
    response.raise_for_status()
    return int(response.json()["running"])


@app.function(
    image=control_image,
    secrets=[backlot_secret],
    schedule=modal.Period(minutes=SUPERVISOR_WAKE_MINUTES),
    timeout=600,
)
def supervise():
    # Deliberately NO volume mount. This container must not be able to write the
    # registry: two writers against a last-write-wins volume is what silently erased a
    # successfully built template. It drives the web endpoint instead, which is the
    # single writer by max_containers=1.
    base_url = os.environ.get("BACKLOT_BASE_URL") or web.get_web_url()
    key = (os.environ.get("BACKLOT_BOOTSTRAP_KEY") or "").strip()
    if not key:
        print("BACKLOT_SUPERVISOR_NO_KEY: cannot drive the control plane", flush=True)
        return
    deadline = now() + SUPERVISOR_WAKE_MINUTES * 60 - 45
    while True:
        try:
            running = supervisor_tick(base_url, key)
        except Exception as exc:  # noqa: BLE001
            # A supervisor that cannot reach the control plane must not spin: it would
            # burn a resident container doing nothing and hide the outage.
            print(f"BACKLOT_SUPERVISOR_UNREACHABLE {type(exc).__name__}", flush=True)
            return
        # Nothing to reap means nothing to trade away by sleeping. Returning here is
        # what makes an empty fleet cheap: one short wake instead of a container held
        # open per minute. The moment a machine exists we stay resident and keep the
        # reap interval at SUPERVISOR_TICK_SECONDS, so customer-facing latency is
        # unchanged.
        if not running or now() >= deadline:
            return
        time.sleep(SUPERVISOR_TICK_SECONDS)


def abandon_stranded(computer: sqlite3.Row) -> None:
    """Stop paying for a machine whose disk cannot be captured.

    Clearing sandbox_id is the point: the row stops claiming to own a sandbox, so it
    stops being retried and stops being counted as live. The disk is gone either way
    once snapshotting has failed this long, so the choice is only how much of it to pay
    for. Recorded as its own reason so it never reads as ordinary supervision failure.
    """
    liveness = reconcile_runtime_liveness(computer)
    computer, sandbox = liveness.computer, liveness.sandbox
    if liveness.state == "terminal":
        return
    if liveness.state == "unknown":
        raise_provider_unreachable(liveness, event="BACKLOT_ABANDON_LIVENESS_UNKNOWN")
    if sandbox is None:
        raise RuntimeError("a stranded runtime claim did not resolve to a sandbox")
    try:
        sandbox.terminate(wait=True)
    except modal.exception.NotFoundError as exc:
        clear_unrecoverable_runtime(
            computer,
            event="BACKLOT_DEAD_SANDBOX_DETACHED",
            exc=exc,
        )
        return
    clear_unrecoverable_runtime(computer, event="BACKLOT_STRANDED_TERMINATED")


def supervise_once() -> int:
    """Reap idle machines and roll over expiring ones. Returns how many hold a sandbox.

    "Holds a sandbox" rather than "is running" is the number that matters: it is what is
    costing money, and it is what should keep the supervisor resident. A stranded error
    row is billing exactly as hard as a healthy one.

    Reloads first, every tick. The registry is one sqlite file on a Modal Volume and
    Modal documents last-write-wins on concurrent modification of the same file, with no
    distributed locking. The supervisor is a second writer alongside the web container,
    so anything it commits from a stale copy erases whatever the web container wrote in
    between. Reloading once per supervise() left that window open for the whole resident
    period; per tick it is seconds. This narrows the race, it does not remove it. See
    health-contract.md for the real fix.
    """
    reload_registry()
    current = now()
    # Anything still holding a sandbox, not just anything marked running. A failed reap
    # records status='error' with the sandbox untouched, and selecting on 'running'
    # alone made that machine invisible to every later pass while it kept billing.
    # A consumer treating error rows as absent was being charged for a machine it had
    # been told did not exist.
    rows = many(
        """
        SELECT * FROM computers
        WHERE status = 'running' OR (status = 'error' AND sandbox_id IS NOT NULL)
        """
    )
    for computer in rows:
        try:
            liveness = reconcile_runtime_liveness(computer)
            computer = liveness.computer
            if liveness.state == "terminal":
                continue
            if liveness.state == "unknown":
                log_provider_liveness_unknown(
                    liveness, event="BACKLOT_SUPERVISOR_LIVENESS_UNKNOWN"
                )
                continue
            stranded = computer["status"] == "error" and computer["sandbox_id"]
            idle = current - (computer["last_active_at"] or current)
            if stranded and current - (
                computer["stranded_since"] or current
            ) >= STRANDED_TERMINATE_SECONDS:
                abandon_stranded(computer)
            elif stranded or idle >= computer["idle_timeout_minutes"] * 60:
                stop_runtime(computer["id"])
            elif computer["expires_at"] and computer["expires_at"] <= current + 120:
                stop_runtime(computer["id"])
                start_runtime(computer["id"], implicit=False)
        except ProviderTaskUnavailable:
            # A second provider lookup can fail after the initial tick probe (for
            # example inside snapshot_running). Its call site already logged the
            # unknown result; never turn it into stranded state here.
            continue
        except Exception as exc:
            log_supervision_error(computer, exc)
            mark_error(
                computer["id"],
                failure_reason(
                    exc, computer["snapshot_image_id"], default=ERROR_SUPERVISION_FAILED
                ),
            )
    return len(rows)


YARD_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Backlot</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Libre+Franklin:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      color-scheme: light;
      font-family: "Libre Franklin", "Helvetica Neue", Helvetica, Arial, sans-serif;
      --violet: #5a34d6;
      --violet-dark: #3b2196;
      --plum: #211042;
      --gold: #e0a458;
      --green: #35bc5b;
      --ink: #14161c;
      --muted: #7c7a72;
      --canvas: #fafaf7;
      --card: #fff;
      --subtle: #f2f1ec;
      --line: #e5e3dc;
      --danger: #c1402c;
      --radius: 10px;
      --radius-card: 14px;
      --focus: 0 0 0 3px rgba(90, 52, 214, .32);
      --shadow: 0 1px 3px rgba(20, 22, 28, .06), 0 1px 2px rgba(20, 22, 28, .04);
      --shadow-raised: 0 14px 40px rgba(20, 22, 28, .1);
    }

    * { box-sizing: border-box; }
    [hidden] { display: none !important; }
    body { margin: 0; min-width: 320px; background: var(--canvas); color: var(--ink); }
    button, input, select, textarea, summary { font: inherit; }
    button, select, input { min-height: 44px; }
    button { cursor: pointer; }
    button:disabled { cursor: wait; opacity: .55; }
    button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible, summary:focus-visible {
      outline: 0;
      box-shadow: var(--focus);
    }

    .shell { min-height: 100vh; display: grid; grid-template-columns: 236px minmax(0, 1fr); }
    .rail {
      position: sticky;
      top: 0;
      height: 100vh;
      display: flex;
      flex-direction: column;
      gap: 28px;
      padding: 24px 18px;
      background: var(--plum);
      color: var(--canvas);
    }
    .brand { display: flex; align-items: center; gap: 10px; font-size: 19px; font-weight: 800; }
    .brand i { color: var(--gold); }
    .rail-label {
      display: block;
      margin: 0 0 8px;
      color: rgba(250, 250, 247, .62);
      font-size: 12px;
      font-weight: 800;
      letter-spacing: .08em;
      text-transform: uppercase;
    }
    .rail select {
      width: 100%;
      padding: 0 36px 0 12px;
      border: 1px solid rgba(250, 250, 247, .22);
      border-radius: var(--radius);
      background: #2a1652;
      color: var(--canvas);
    }
    .nav-item {
      display: flex;
      align-items: center;
      gap: 10px;
      width: 100%;
      padding: 0 14px;
      border: 1px solid rgba(250, 250, 247, .14);
      border-radius: var(--radius);
      background: rgba(250, 250, 247, .1);
      color: var(--canvas);
      font-weight: 700;
      text-align: left;
    }
    .nav-item kbd {
      margin-left: auto;
      padding: 2px 6px;
      border: 1px solid rgba(250, 250, 247, .2);
      border-radius: 6px;
      color: rgba(250, 250, 247, .7);
      font: 11px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    .rail-foot { margin-top: auto; color: rgba(250, 250, 247, .6); font-size: 13px; line-height: 1.5; }

    .content { min-width: 0; }
    .topbar {
      position: sticky;
      z-index: 20;
      top: 0;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 18px;
      min-height: 76px;
      padding: 14px clamp(20px, 4vw, 48px);
      border-bottom: 1px solid var(--line);
      background: rgba(250, 250, 247, .96);
    }
    .topbar h1 { margin: 0; font-size: 26px; letter-spacing: -.02em; }
    .topbar p { margin: 4px 0 0; color: var(--muted); font-size: 14px; }
    .auth { display: flex; align-items: center; gap: 10px; }
    .auth input {
      width: min(280px, 32vw);
      padding: 0 12px;
      border: 1px solid #d2cfc6;
      border-radius: var(--radius);
      background: var(--card);
      color: var(--ink);
    }
    .button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 0 16px;
      border: 1px solid var(--violet);
      border-radius: var(--radius);
      background: var(--violet);
      color: white;
      font-weight: 700;
    }
    .button:hover { background: #4a29b8; }
    .button:active { transform: translateY(1px); background: var(--violet-dark); }
    .button-secondary { border-color: var(--line); background: var(--card); color: var(--ink); }
    .button-secondary:hover { border-color: #d2cfc6; background: var(--subtle); }
    .button-danger { border-color: var(--danger); background: var(--danger); }

    .yard { padding: 34px clamp(20px, 4vw, 48px) 56px; }
    .yard-head { display: flex; align-items: end; justify-content: space-between; gap: 18px; margin-bottom: 18px; }
    .yard-head h2 { margin: 0; font-size: 20px; }
    .yard-head p { margin: 5px 0 0; color: var(--muted); font-size: 14px; }
    .machine-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(290px, 1fr)); gap: 18px; }
    .machine-card, .new-card {
      min-width: 0;
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: var(--radius-card);
      background: var(--card);
      box-shadow: var(--shadow);
    }
    .machine-card { position: relative; }
    .machine-card:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(20, 22, 28, .07); }
    .preview {
      position: relative;
      width: 100%;
      aspect-ratio: 16 / 9;
      display: grid;
      place-items: center;
      overflow: hidden;
      padding: 0;
      border: 0;
      border-bottom: 1px solid var(--line);
      border-radius: 0;
      background: var(--plum);
      color: rgba(250, 250, 247, .68);
    }
    .preview img { width: 100%; height: 100%; object-fit: cover; }
    .preview span { display: flex; align-items: center; gap: 8px; font-weight: 600; }
    .machine-body { padding: 16px; }
    .machine-title { display: flex; align-items: start; justify-content: space-between; gap: 12px; }
    .machine-title h3 { overflow: hidden; margin: 0; font-size: 17px; text-overflow: ellipsis; white-space: nowrap; }
    .status {
      flex: none;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      min-height: 26px;
      padding: 3px 8px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--subtle);
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: capitalize;
    }
    .status.running { border-color: #a9e9bc; background: #eaf9ee; color: #1e7239; }
    .status.error { border-color: #f6d7cf; background: #fbeded; color: var(--danger); }
    .dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
    .machine-meta { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 13px; color: var(--muted); font-size: 13px; }
    .machine-meta span { padding: 4px 7px; border-radius: 6px; background: var(--subtle); }
    .card-actions { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-top: 15px; }
    .open-button { padding: 0 12px; }
    .menu { position: relative; }
    .menu summary {
      width: 44px;
      min-height: 44px;
      display: grid;
      place-items: center;
      list-style: none;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--card);
      cursor: pointer;
    }
    .menu summary::-webkit-details-marker { display: none; }
    .menu-list {
      position: absolute;
      z-index: 30;
      right: 0;
      bottom: 48px;
      width: 190px;
      padding: 6px;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--card);
      box-shadow: var(--shadow-raised);
    }
    .menu-list button {
      width: 100%;
      min-height: 44px;
      display: flex;
      align-items: center;
      gap: 9px;
      padding: 0 10px;
      border: 0;
      border-radius: 7px;
      background: transparent;
      color: var(--ink);
      text-align: left;
    }
    .menu-list button:hover { background: var(--subtle); }
    .menu-list .destructive { color: var(--danger); }

    .new-card {
      min-height: 330px;
      display: grid;
      place-items: center;
      padding: 24px;
      border: 1.5px dashed #d5c5a6;
      background: #fbf4e9;
      color: var(--ink);
    }
    .new-card:hover { border-color: #ce8c3c; background: #f6e7d0; }
    .new-card-inner { display: grid; justify-items: center; gap: 10px; text-align: center; }
    .new-card-icon {
      width: 52px;
      height: 52px;
      display: grid;
      place-items: center;
      border-radius: 50%;
      background: var(--gold);
    }
    .new-card strong { font-size: 17px; }
    .new-card small { max-width: 24ch; color: var(--muted); line-height: 1.45; }

    .empty {
      grid-column: 1 / -1;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 10px;
      min-height: 320px;
      padding: 48px 28px;
      border: 1px dashed var(--line);
      border-radius: var(--radius-card);
      background: var(--card);
      color: var(--muted);
      text-align: center;
    }
    .empty svg { width: 30px; height: 30px; stroke: var(--violet); opacity: .65; }
    .empty strong { display: block; color: var(--ink); font-size: 17px; font-weight: 700; }
    .empty span { display: block; max-width: 44ch; line-height: 1.5; }
    /* Service state is public, so show it before a key is entered rather than
       leaving the operator staring at a dead page wondering if Backlot is up. */
    .health {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 5px 11px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--card);
      font-size: 12.5px;
      font-weight: 600;
      color: var(--muted);
      white-space: nowrap;
    }
    .health .dot {
      width: 8px; height: 8px; border-radius: 50%;
      background: var(--muted); flex: none;
    }
    .health[data-state="ok"] { color: var(--ink); border-color: rgba(53, 188, 91, .4); }
    .health[data-state="ok"] .dot { background: var(--green); box-shadow: 0 0 0 3px rgba(53, 188, 91, .18); }
    .health[data-state="down"] { color: var(--danger); border-color: rgba(193, 64, 44, .4); }
    .health[data-state="down"] .dot { background: var(--danger); }
    @media (prefers-reduced-motion: no-preference) {
      .health[data-state="ok"] .dot { animation: pulse 2.4s ease-in-out infinite; }
    }
    @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .55; } }
    .admin-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 18px; }
    .admin-panel {
      min-width: 0;
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: var(--radius-card);
      background: var(--card);
      box-shadow: var(--shadow);
    }
    .admin-panel-head, .admin-card-head, .key-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    .admin-panel-head { margin-bottom: 14px; }
    .admin-panel h3, .admin-card h4 { margin: 0; }
    .admin-list { display: grid; gap: 10px; }
    .admin-card, .key-row {
      min-width: 0;
      padding: 13px;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--canvas);
    }
    .admin-card-head > div, .key-row > div { min-width: 0; }
    .admin-card small, .key-row small {
      display: block;
      overflow: hidden;
      margin-top: 5px;
      color: var(--muted);
      font: 12px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .admin-meta { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 12px; color: var(--muted); font-size: 13px; }
    .admin-meta span { padding: 4px 7px; border-radius: 6px; background: var(--subtle); }
    .admin-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
    .key-row strong { display: block; }
    .key-row .button { flex: none; }
    .one-time-key {
      width: 100%;
      padding: 0 12px;
      border: 1px solid #d2cfc6;
      border-radius: var(--radius);
      background: var(--subtle);
      color: var(--ink);
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    .notice { min-height: 24px; margin: 0 0 12px; color: var(--muted); font-size: 14px; }
    .notice.error { color: var(--danger); }
    .template-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(310px, 1fr)); gap: 18px; }
    .template-card {
      display: grid;
      gap: 16px;
      padding: 20px;
      border: 1px solid var(--line);
      border-radius: var(--radius-card);
      background: var(--card);
      box-shadow: var(--shadow);
    }
    .template-card h3, .template-card p { margin: 0; }
    .template-card p { color: var(--muted); line-height: 1.5; }
    .template-hardware { display: flex; flex-wrap: wrap; gap: 7px; }
    .template-hardware span {
      padding: 5px 8px;
      border-radius: 7px;
      background: var(--subtle);
      color: var(--muted);
      font-size: 13px;
    }
    .template-launch { display: grid; grid-template-columns: minmax(130px, 1fr) minmax(140px, 1fr) auto; gap: 8px; }
    .template-launch input, .template-launch select {
      min-width: 0;
      padding: 0 10px;
      border: 1px solid #d2cfc6;
      border-radius: var(--radius);
      background: var(--card);
      color: var(--ink);
    }
    .template-spec summary {
      min-height: 44px;
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--violet);
      cursor: pointer;
      font-weight: 700;
    }
    .template-spec pre {
      max-height: 220px;
      overflow: auto;
      margin: 0;
      padding: 12px;
      border-radius: 8px;
      background: var(--plum);
      color: var(--canvas);
      font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    .palette-dialog { width: min(640px, calc(100vw - 28px)); }
    .palette-search {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 12px 16px;
      border-bottom: 1px solid var(--line);
    }
    .palette-search input {
      width: 100%;
      border: 0;
      background: transparent;
      color: var(--ink);
      font-size: 17px;
      outline: 0;
    }
    .palette-results { display: grid; gap: 4px; padding: 8px; }
    .palette-result {
      min-height: 50px;
      display: flex;
      align-items: center;
      gap: 10px;
      width: 100%;
      padding: 8px 10px;
      border: 0;
      border-radius: 8px;
      background: transparent;
      color: var(--ink);
      text-align: left;
    }
    .palette-result:hover, .palette-result.active { background: var(--subtle); }
    .palette-result span { min-width: 0; }
    .palette-result strong, .palette-result small { display: block; }
    .palette-result small { margin-top: 3px; color: var(--muted); }

    dialog {
      width: min(520px, calc(100vw - 28px));
      max-height: calc(100vh - 36px);
      overflow: auto;
      padding: 0;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: var(--card);
      color: var(--ink);
      box-shadow: var(--shadow-raised);
    }
    dialog::backdrop { background: rgba(33, 16, 66, .44); backdrop-filter: blur(2px); }
    .dialog-head, .dialog-foot { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 18px 20px; }
    .dialog-head { border-bottom: 1px solid var(--line); }
    .dialog-head h2 { margin: 0; font-size: 20px; }
    .dialog-body { display: grid; gap: 14px; padding: 20px; }
    .dialog-foot { border-top: 1px solid var(--line); }
    .field { display: grid; gap: 7px; }
    .field label { font-size: 13px; font-weight: 700; }
    .field input, .field select, .field textarea {
      width: 100%;
      padding: 0 12px;
      border: 1px solid #d2cfc6;
      border-radius: var(--radius);
      background: var(--card);
      color: var(--ink);
    }
    .field textarea { padding-block: 10px; resize: vertical; }
    .advanced { padding: 12px 0 0; border-top: 1px solid var(--line); }
    .advanced summary { min-height: 44px; display: flex; align-items: center; gap: 8px; color: var(--violet); cursor: pointer; font-weight: 700; }
    .advanced-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; padding-top: 12px; }

    body.computer-mode .shell { grid-template-columns: 1fr; }
    body.computer-mode .rail, body.computer-mode .topbar, body.computer-mode #fleetView, body.computer-mode #adminView,
    body.computer-mode #templatesView { display: none; }
    body.computer-mode .yard { padding: 0; }
    .desktop { min-height: 100vh; background: var(--canvas); }
    .desktop[hidden] { display: none; }
    .desktop-head {
      min-height: 66px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      padding: 10px 16px;
      border-bottom: 1px solid var(--line);
      background: var(--card);
    }
    .desktop-identity, .desktop-actions { display: flex; align-items: center; gap: 8px; }
    .desktop-identity { min-width: 0; }
    .desktop-identity strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .desktop-actions { flex-wrap: wrap; justify-content: end; }
    .desktop > .notice { min-height: 0; margin: 0; padding: 6px 18px; background: var(--card); }
    .desktop-stage {
      height: min(72vh, calc(100vh - 230px));
      min-height: 420px;
      display: grid;
      place-items: center;
      overflow: hidden;
      background: var(--plum);
    }
    .rfb-host { width: 100%; height: 100%; overflow: hidden; background: #000; }
    .rfb-host canvas { width: 100%; height: 100%; }
    .desktop-state {
      max-width: 460px;
      display: grid;
      justify-items: center;
      gap: 14px;
      padding: 32px;
      color: var(--canvas);
      text-align: center;
    }
    .desktop-state h2, .desktop-state p { margin: 0; }
    .desktop-state p { color: rgba(250, 250, 247, .68); line-height: 1.5; }
    .command-rail { border-top: 1px solid var(--line); background: var(--card); }
    .command-rail summary {
      min-height: 50px;
      display: flex;
      align-items: center;
      gap: 9px;
      padding: 0 18px;
      color: var(--ink);
      cursor: pointer;
      font-weight: 800;
      list-style: none;
    }
    .command-rail summary::-webkit-details-marker { display: none; }
    .command-panel { padding: 0 18px 18px; }
    .command-form { display: flex; gap: 8px; }
    .command-form input {
      width: 100%;
      padding: 0 12px;
      border: 1px solid #d2cfc6;
      border-radius: var(--radius);
      background: var(--canvas);
      color: var(--ink);
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    .command-history {
      max-height: 190px;
      display: grid;
      gap: 8px;
      overflow: auto;
      margin-top: 10px;
    }
    .command-entry {
      padding: 10px 12px;
      border-radius: 8px;
      background: var(--subtle);
      font: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    .command-entry strong { display: block; margin-bottom: 4px; color: var(--violet); }
    .command-entry pre { margin: 0; overflow-wrap: anywhere; white-space: pre-wrap; }
    .command-entry.error strong { color: var(--danger); }
    .settings-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .setting {
      padding: 12px;
      border-radius: 8px;
      background: var(--subtle);
    }
    .setting small { display: block; margin-bottom: 5px; color: var(--muted); }
    .setting strong { overflow-wrap: anywhere; }
    .desktop.standalone .command-rail { display: none; }
    .desktop.standalone .desktop-stage { height: calc(100vh - 92px); min-height: 0; }
    .icon-button { width: 44px; padding: 0; }

    @media (max-width: 840px) {
      .shell { grid-template-columns: 1fr; }
      .rail { position: static; height: auto; display: grid; grid-template-columns: 1fr 1fr; padding: 16px; }
      .rail .brand, .rail-foot { display: none; }
      .topbar { position: static; align-items: start; flex-direction: column; }
      .auth { width: 100%; flex-wrap: wrap; }
      .auth input { width: 100%; order: 2; }
      .auth .button { order: 3; }
      .health { order: 1; width: 100%; justify-content: center; }
      .empty { min-height: 240px; padding: 32px 20px; }
      .desktop-head { align-items: start; flex-direction: column; }
      .desktop-actions { justify-content: start; }
      .desktop-stage { min-height: 360px; }
      .admin-grid { grid-template-columns: 1fr; }
      .template-launch { grid-template-columns: 1fr; }
    }
    @media (max-width: 560px) {
      .rail { grid-template-columns: 1fr; gap: 12px; }
      .yard-head { align-items: start; flex-direction: column; }
      .machine-grid { grid-template-columns: 1fr; }
      .advanced-grid { grid-template-columns: 1fr; }
      .command-form, .settings-grid { grid-template-columns: 1fr; flex-direction: column; }
    }
    @media (prefers-reduced-motion: no-preference) {
      .machine-card, .new-card, .button { transition: all 200ms cubic-bezier(.2, 0, 0, 1); }
    }
  </style>
</head>
<body>
  <div class="shell">
    <aside class="rail">
      <div class="brand"><i data-lucide="boxes"></i><span>Backlot</span></div>
      <div>
        <label class="rail-label" for="workspace">Workspace</label>
        <select id="workspace" aria-label="Select workspace">
          <option value="">Load a key first</option>
        </select>
      </div>
      <button id="fleetNav" class="nav-item" type="button" aria-current="page"><i data-lucide="monitor"></i>Computers</button>
      <button id="templatesNav" class="nav-item" type="button"><i data-lucide="layout-template"></i>Templates</button>
      <button id="adminNav" class="nav-item" type="button"><i data-lucide="key-round"></i>Workspace admin</button>
      <button id="paletteButton" class="nav-item" type="button"><i data-lucide="search"></i>Search<kbd>⌘K</kbd></button>
      <p class="rail-foot">Internal infrastructure<br>Linux desktops on demand</p>
    </aside>

    <div class="content">
      <header class="topbar">
        <div>
          <h1 id="pageTitle">Computers</h1>
          <p id="workspaceSummary">Enter the bootstrap key to load the yard.</p>
        </div>
        <div class="auth">
          <span id="serviceHealth" class="health" role="status" aria-live="polite">
            <span class="dot"></span><span id="serviceHealthText">Checking service</span>
          </span>
          <input id="key" type="password" autocomplete="off" aria-label="Backlot API key" placeholder="Backlot API key">
          <button id="loadButton" class="button" type="button"><i data-lucide="refresh-cw"></i>Load</button>
        </div>
      </header>

      <main class="yard">
        <div id="fleetView">
          <div class="yard-head">
            <div>
              <h2>Machine yard</h2>
              <p>Open, stop, start, and inspect every Linux desktop from one place.</p>
            </div>
            <button id="refreshButton" class="button button-secondary" type="button"><i data-lucide="rotate-cw"></i>Refresh</button>
          </div>
          <p id="notice" class="notice" role="status" aria-live="polite"></p>
          <section id="machines" class="machine-grid" aria-label="Computers">
            <div class="empty">
              <i data-lucide="key-round"></i>
              <strong>Enter an API key to load the yard</strong>
              <span>The bootstrap key lives in 1Password, vault King Mouse M5, item BACKLOT_BOOTSTRAP_KEY. It is held in memory only and never stored by this page.</span>
            </div>
          </section>
        </div>

        <div id="adminView" hidden>
          <div class="yard-head">
            <div>
              <h2>Workspace access</h2>
              <p>Create internal workspaces and manage scoped API keys without exposing raw key material.</p>
            </div>
            <button id="createWorkspaceButton" class="button" type="button"><i data-lucide="plus"></i>New workspace</button>
          </div>
          <p id="adminNotice" class="notice" role="status" aria-live="polite"></p>
          <div class="admin-grid">
            <section class="admin-panel" aria-labelledby="workspaceAdminTitle">
              <div class="admin-panel-head">
                <h3 id="workspaceAdminTitle">Workspaces</h3>
              </div>
              <div id="workspaceCards" class="admin-list"></div>
            </section>
            <section class="admin-panel" aria-labelledby="keyAdminTitle">
              <div class="admin-panel-head">
                <h3 id="keyAdminTitle">Scoped API keys</h3>
                <button id="createKeyButton" class="button button-secondary" type="button"><i data-lucide="key-round"></i>Issue key</button>
              </div>
              <div id="keyRows" class="admin-list"></div>
            </section>
          </div>
        </div>

        <div id="templatesView" hidden>
          <div class="yard-head">
            <div>
              <h2>Desktop templates</h2>
              <p>Launch a curated Linux desktop with its intended defaults, no wizard required.</p>
            </div>
            <button id="templatesRefreshButton" class="button button-secondary" type="button"><i data-lucide="rotate-cw"></i>Refresh</button>
          </div>
          <p id="templatesNotice" class="notice" role="status" aria-live="polite"></p>
          <section id="templateCards" class="template-grid" aria-label="Desktop templates"></section>
        </div>

        <section id="desktop" class="desktop" hidden>
          <div class="desktop-head">
            <div class="desktop-identity">
              <button id="closeDesktop" class="button button-secondary icon-button" type="button" aria-label="Back to computers"><i data-lucide="arrow-left"></i></button>
              <strong id="desktopName">Linux desktop</strong>
              <span id="desktopStatus" class="status"><span class="dot"></span><span>stopped</span></span>
            </div>
            <div class="desktop-actions">
              <button id="desktopStart" class="button button-secondary" type="button"><i data-lucide="play"></i>Start</button>
              <button id="desktopStop" class="button button-secondary" type="button"><i data-lucide="square"></i>Stop</button>
              <button id="desktopRestart" class="button button-secondary" type="button"><i data-lucide="rotate-cw"></i>Restart</button>
              <button id="desktopSettings" class="button button-secondary" type="button"><i data-lucide="settings"></i>Settings</button>
              <button id="desktopClipboard" class="button button-secondary" type="button"><i data-lucide="clipboard"></i>Clipboard</button>
              <button id="desktopStandalone" class="button button-secondary" type="button"><i data-lucide="panel-top-open"></i>Standalone</button>
              <button id="desktopFullscreen" class="button button-secondary" type="button"><i data-lucide="maximize"></i>Fullscreen</button>
            </div>
          </div>
          <p id="desktopNotice" class="notice" role="status" aria-live="polite"></p>
          <div id="screen" class="desktop-stage"></div>
          <details id="commandRail" class="command-rail" open>
            <summary><i data-lucide="square-terminal"></i>Commands</summary>
            <div class="command-panel">
              <form id="commandForm" class="command-form">
                <input id="commandInput" aria-label="Shell command" autocomplete="off" placeholder="Run a shell command, for example: pwd">
                <button id="commandRun" class="button" type="submit"><i data-lucide="play"></i>Run</button>
              </form>
              <div id="commandHistory" class="command-history" aria-live="polite"></div>
            </div>
          </details>
        </section>
      </main>
    </div>
  </div>

  <dialog id="paletteDialog" class="palette-dialog">
    <div class="palette-search">
      <i data-lucide="search"></i>
      <input id="paletteInput" type="search" autocomplete="off" aria-label="Search Backlot" placeholder="Search workspaces, computers, or actions">
      <button class="button button-secondary icon-button" type="button" data-close-palette aria-label="Close search"><i data-lucide="x"></i></button>
    </div>
    <div id="paletteResults" class="palette-results" role="listbox" aria-label="Search results"></div>
  </dialog>

  <dialog id="createDialog">
    <form id="createForm">
      <div class="dialog-head">
        <h2>New computer</h2>
        <button class="button button-secondary icon-button" type="button" data-close-create aria-label="Close"><i data-lucide="x"></i></button>
      </div>
      <div class="dialog-body">
        <div class="field">
          <label for="computerName">Computer name</label>
          <input id="computerName" name="name" maxlength="100" required>
        </div>
        <details class="advanced">
          <summary><i data-lucide="sliders-horizontal"></i>Advanced</summary>
          <div class="advanced-grid">
            <div class="field">
              <label for="createWorkspace">Workspace</label>
              <select id="createWorkspace" name="workspace_id" required></select>
            </div>
            <div class="field">
              <label for="createCpu">CPU</label>
              <select id="createCpu" name="cpu">
                <option value="1">1 core</option>
                <option value="2">2 cores</option>
                <option value="4">4 cores</option>
                <option value="8">8 cores</option>
                <option value="16">16 cores</option>
              </select>
            </div>
            <div class="field">
              <label for="createRam">Memory</label>
              <select id="createRam" name="ram">
                <option value="4">4 GiB</option>
                <option value="8">8 GiB</option>
                <option value="16">16 GiB</option>
                <option value="32">32 GiB</option>
                <option value="64">64 GiB</option>
              </select>
            </div>
            <div class="field">
              <label for="createDisk">Disk size</label>
              <input id="createDisk" name="disk_size_gb" type="number" min="1" placeholder="Default">
            </div>
            <div class="field">
              <label for="createResolution">Resolution</label>
              <select id="createResolution" name="resolution">
                <option value="1280x720x24">1280 x 720</option>
                <option value="1440x900x24">1440 x 900</option>
                <option value="1920x1080x24">1920 x 1080</option>
              </select>
            </div>
            <div class="field">
              <label for="createIdle">Idle stop</label>
              <input id="createIdle" name="idle_timeout_minutes" type="number" min="1" max="1440" value="30">
            </div>
          </div>
          <div class="field" style="margin-top:14px">
            <label for="createTemplate">Template ref</label>
            <input id="createTemplate" name="template_ref" placeholder="Optional">
          </div>
        </details>
      </div>
      <div class="dialog-foot">
        <button class="button button-secondary" type="button" data-close-create>Cancel</button>
        <button id="createButton" class="button" type="submit"><i data-lucide="play"></i>Create and start</button>
      </div>
    </form>
  </dialog>

  <dialog id="workspaceCreateDialog">
    <form id="workspaceCreateForm">
      <div class="dialog-head">
        <h2>New workspace</h2>
        <button class="button button-secondary icon-button" type="button" data-close-workspace-create aria-label="Close"><i data-lucide="x"></i></button>
      </div>
      <div class="dialog-body">
        <div class="field">
          <label for="workspaceName">Workspace name</label>
          <input id="workspaceName" name="name" maxlength="100" required autocomplete="off">
        </div>
      </div>
      <div class="dialog-foot">
        <button class="button button-secondary" type="button" data-close-workspace-create>Cancel</button>
        <button id="workspaceCreateSubmit" class="button" type="submit">Create workspace</button>
      </div>
    </form>
  </dialog>

  <dialog id="keyCreateDialog">
    <form id="keyCreateForm">
      <div class="dialog-head">
        <h2>Issue scoped API key</h2>
        <button class="button button-secondary icon-button" type="button" data-close-key-create aria-label="Close"><i data-lucide="x"></i></button>
      </div>
      <div class="dialog-body">
        <div class="field">
          <label for="keyName">Key name</label>
          <input id="keyName" name="name" maxlength="100" required autocomplete="off">
        </div>
        <div class="field">
          <label for="keyWorkspace">Workspace</label>
          <select id="keyWorkspace" name="workspace_id" required></select>
        </div>
      </div>
      <div class="dialog-foot">
        <button class="button button-secondary" type="button" data-close-key-create>Cancel</button>
        <button id="keyCreateSubmit" class="button" type="submit">Issue key</button>
      </div>
    </form>
  </dialog>

  <dialog id="keyRevealDialog">
    <div class="dialog-head">
      <h2>Copy this key now</h2>
    </div>
    <div class="dialog-body">
      <p class="notice">Backlot will not show this raw key again. The admin list stores metadata only.</p>
      <input id="oneTimeKey" class="one-time-key" type="text" readonly aria-label="One-time API key" autocomplete="off">
    </div>
    <div class="dialog-foot">
      <button id="copyOneTimeKey" class="button button-secondary" type="button"><i data-lucide="copy"></i>Copy key</button>
      <button class="button" type="button" data-close-key-reveal>Done</button>
    </div>
  </dialog>

  <dialog id="workspaceSettingsDialog">
    <div class="dialog-head">
      <h2>Workspace settings</h2>
      <button class="button button-secondary icon-button" type="button" data-close-workspace-settings aria-label="Close settings"><i data-lucide="x"></i></button>
    </div>
    <div id="workspaceSettingsBody" class="dialog-body"></div>
    <div class="dialog-foot">
      <button id="deleteWorkspaceButton" class="button button-danger" type="button">Delete workspace</button>
      <button class="button button-secondary" type="button" data-close-workspace-settings>Done</button>
    </div>
  </dialog>

  <dialog id="confirmationDialog">
    <div class="dialog-head">
      <h2>Confirm action</h2>
    </div>
    <div class="dialog-body">
      <p id="confirmationMessage" class="notice"></p>
    </div>
    <div class="dialog-foot">
      <button class="button button-secondary" type="button" data-confirm-cancel>Cancel</button>
      <button id="confirmationButton" class="button button-danger" type="button">Confirm</button>
    </div>
  </dialog>

  <dialog id="settingsDialog">
    <div class="dialog-head">
      <h2>Computer settings</h2>
      <button class="button button-secondary icon-button" type="button" data-close-settings aria-label="Close settings"><i data-lucide="x"></i></button>
    </div>
    <div class="dialog-body">
      <div id="settingsGrid" class="settings-grid"></div>
      <p class="notice">Files on disk survive stop and start. Running processes, open windows, and terminal sessions do not.</p>
    </div>
    <div class="dialog-foot">
      <button class="button button-secondary" type="button" data-close-settings>Done</button>
    </div>
  </dialog>

  <dialog id="clipboardDialog">
    <div class="dialog-head">
      <h2>VM clipboard</h2>
      <button class="button button-secondary icon-button" type="button" data-close-clipboard aria-label="Close clipboard"><i data-lucide="x"></i></button>
    </div>
    <div class="dialog-body">
      <div class="field">
        <label for="clipboardText">Text</label>
        <textarea id="clipboardText" rows="7" aria-label="VM clipboard"></textarea>
      </div>
    </div>
    <div class="dialog-foot">
      <button class="button button-secondary" type="button" data-close-clipboard>Cancel</button>
      <button id="clipboardSend" class="button" type="button">Send to VM</button>
    </div>
  </dialog>

  <script src="https://unpkg.com/lucide@0.468.0/dist/umd/lucide.min.js"></script>
  <script type="module">
    import RFBModule from 'https://cdn.jsdelivr.net/npm/@novnc/novnc@1.5.0/+esm';
    let RFB = RFBModule;
    while (RFB && typeof RFB !== 'function' && RFB.default) RFB = RFB.default;
    window.BacklotRFB = RFB;
    window.dispatchEvent(new Event('backlot-rfb-ready'));
  </script>
  <script>
    const key = document.querySelector('#key');
    const workspaceSelect = document.querySelector('#workspace');
    const createWorkspace = document.querySelector('#createWorkspace');
    const keyWorkspace = document.querySelector('#keyWorkspace');
    const machinesRoot = document.querySelector('#machines');
    const notice = document.querySelector('#notice');
    const adminNotice = document.querySelector('#adminNotice');
    const templatesNotice = document.querySelector('#templatesNotice');
    const templateCards = document.querySelector('#templateCards');
    const paletteDialog = document.querySelector('#paletteDialog');
    const paletteInput = document.querySelector('#paletteInput');
    const paletteResults = document.querySelector('#paletteResults');
    const createDialog = document.querySelector('#createDialog');
    const createForm = document.querySelector('#createForm');
    const workspaceCreateDialog = document.querySelector('#workspaceCreateDialog');
    const workspaceCreateForm = document.querySelector('#workspaceCreateForm');
    const keyCreateDialog = document.querySelector('#keyCreateDialog');
    const keyCreateForm = document.querySelector('#keyCreateForm');
    const keyRevealDialog = document.querySelector('#keyRevealDialog');
    const oneTimeKey = document.querySelector('#oneTimeKey');
    const workspaceSettingsDialog = document.querySelector('#workspaceSettingsDialog');
    const workspaceSettingsBody = document.querySelector('#workspaceSettingsBody');
    const confirmationDialog = document.querySelector('#confirmationDialog');
    const confirmationMessage = document.querySelector('#confirmationMessage');
    const confirmationButton = document.querySelector('#confirmationButton');
    const workspaceCards = document.querySelector('#workspaceCards');
    const keyRows = document.querySelector('#keyRows');
    const desktop = document.querySelector('#desktop');
    const desktopNotice = document.querySelector('#desktopNotice');
    const screen = document.querySelector('#screen');
    const settingsDialog = document.querySelector('#settingsDialog');
    const settingsGrid = document.querySelector('#settingsGrid');
    const clipboardDialog = document.querySelector('#clipboardDialog');
    const clipboardText = document.querySelector('#clipboardText');
    const commandHistory = document.querySelector('#commandHistory');
    const state = {
      workspaces: [],
      machines: [],
      keys: [],
      templates: [],
      workspaceId: '',
      computerId: '',
      standalone: false,
      view: location.pathname === '/admin' ? 'admin' : (location.pathname === '/library' ? 'templates' : 'fleet'),
      settingsWorkspaceId: '',
    };
    const thumbnails = new Map();
    const thumbnailLoads = new Set();
    const routeMatch = location.pathname.match(/^[/]computer[/]([^/]+)/);
    if (routeMatch) {
      state.computerId = decodeURIComponent(routeMatch[1]);
      state.standalone = location.pathname.endsWith('/desktop');
    }

    let apiKey = '';
    let activeRfb = null;
    let confirmationResolve = null;

    function icons() {
      if (window.lucide) window.lucide.createIcons({attrs: {'aria-hidden': 'true', width: 19, height: 19}});
    }

    // /health needs no key, so the operator learns whether the control plane is up
    // before authenticating instead of guessing from a blank page. Registry-only,
    // so polling it cannot wake or bill a machine.
    async function refreshServiceHealth() {
      const pill = document.querySelector('#serviceHealth');
      const label = document.querySelector('#serviceHealthText');
      if (!pill || !label) return;
      try {
        const response = await fetch('/health', {cache: 'no-store'});
        const body = await response.json();
        if (!response.ok || !body.ok) throw new Error('unhealthy');
        const count = body.workspaces;
        const plural = count === 1 ? 'workspace' : 'workspaces';
        pill.dataset.state = 'ok';
        label.textContent = 'Control plane up, ' + count + ' ' + plural;
        pill.title = 'Registry ' + body.registry + '. Checked ' + new Date().toLocaleTimeString();
      } catch (error) {
        pill.dataset.state = 'down';
        label.textContent = 'Control plane unreachable';
        pill.title = 'GET /health did not answer';
      }
    }

    function setNotice(message = '', error = false) {
      notice.textContent = message;
      notice.classList.toggle('error', error);
    }

    function setAdminNotice(message = '', error = false) {
      adminNotice.textContent = message;
      adminNotice.classList.toggle('error', error);
    }

    function setTemplatesNotice(message = '', error = false) {
      templatesNotice.textContent = message;
      templatesNotice.classList.toggle('error', error);
    }

    function setDesktopNotice(message = '', error = false) {
      desktopNotice.textContent = message;
      desktopNotice.classList.toggle('error', error);
    }

    function errorText(error) {
      return error instanceof Error ? error.message : String(error);
    }

    function confirmAction(message, label) {
      confirmationMessage.textContent = message;
      confirmationButton.textContent = label;
      confirmationDialog.showModal();
      return new Promise(resolve => { confirmationResolve = resolve; });
    }

    function finishConfirmation(confirmed) {
      confirmationDialog.close();
      const resolve = confirmationResolve;
      confirmationResolve = null;
      if (resolve) resolve(confirmed);
    }

    async function api(path, options = {}) {
      const token = key.value || apiKey;
      if (!token) throw new Error('Enter a Backlot API key.');
      apiKey = token;
      key.value = '';
      const headers = new Headers(options.headers || {});
      headers.set('Authorization', `Bearer ${token}`);
      if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
      const response = await fetch(path, {...options, headers});
      if (!response.ok) throw new Error(await response.text());
      return response.json();
    }

    function optionFor(workspace) {
      const option = document.createElement('option');
      option.value = workspace.id;
      option.textContent = workspace.name;
      return option;
    }

    function renderWorkspaceOptions() {
      workspaceSelect.replaceChildren();
      createWorkspace.replaceChildren();
      keyWorkspace.replaceChildren();
      for (const workspace of state.workspaces) {
        workspaceSelect.append(optionFor(workspace));
        createWorkspace.append(optionFor(workspace));
        keyWorkspace.append(optionFor(workspace));
      }
      if (!state.workspaces.length) {
        const empty = document.createElement('option');
        empty.value = '';
        empty.textContent = 'No workspaces';
        workspaceSelect.append(empty);
        createWorkspace.append(empty.cloneNode(true));
        keyWorkspace.append(empty.cloneNode(true));
      }
      const known = state.workspaces.some(workspace => workspace.id === state.workspaceId);
      state.workspaceId = known ? state.workspaceId : (state.workspaces[0]?.id || '');
      workspaceSelect.value = state.workspaceId;
      createWorkspace.value = state.workspaceId;
      keyWorkspace.value = state.workspaceId;
      updateSummary();
    }

    function updateSummary() {
      if (state.view === 'admin') {
        document.querySelector('#workspaceSummary').textContent =
          `${state.workspaces.length} workspace${state.workspaces.length === 1 ? '' : 's'} · ${state.keys.length} scoped key${state.keys.length === 1 ? '' : 's'}`;
        return;
      }
      if (state.view === 'templates') {
        document.querySelector('#workspaceSummary').textContent =
          `${state.templates.length} curated template${state.templates.length === 1 ? '' : 's'} · ${state.workspaces.length} launch workspace${state.workspaces.length === 1 ? '' : 's'}`;
        return;
      }
      const current = state.workspaces.find(workspace => workspace.id === state.workspaceId);
      const count = state.machines.filter(machine => machine.workspace_id === state.workspaceId).length;
      document.querySelector('#workspaceSummary').textContent = current
        ? `${current.name} · ${count} computer${count === 1 ? '' : 's'}`
        : 'No workspace is available.';
    }

    function statusBadge(machine) {
      const badge = document.createElement('span');
      badge.className = `status ${machine.status}`;
      const dot = document.createElement('span');
      dot.className = 'dot';
      badge.append(dot, document.createTextNode(machine.status));
      return badge;
    }

    function menuButton(label, icon, handler, destructive = false) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = destructive ? 'destructive' : '';
      button.innerHTML = `<i data-lucide="${icon}"></i>`;
      button.append(document.createTextNode(label));
      button.addEventListener('click', handler);
      return button;
    }

    function machineMenu(machine) {
      const menu = document.createElement('details');
      menu.className = 'menu';
      const summary = document.createElement('summary');
      summary.setAttribute('aria-label', `Actions for ${machine.name}`);
      summary.innerHTML = '<i data-lucide="ellipsis"></i>';
      const list = document.createElement('div');
      list.className = 'menu-list';

      if (machine.status === 'running') {
        list.append(menuButton('Stop', 'square', () => lifecycle(machine, 'stop')));
        list.append(menuButton('Restart', 'rotate-cw', () => lifecycle(machine, 'restart')));
      } else {
        list.append(menuButton('Start', 'play', () => lifecycle(machine, 'start')));
      }
      list.append(menuButton('Clone', 'copy', () => cloneMachine(machine)));
      list.append(menuButton('Resize', 'maximize-2', () => resizeMachine(machine)));
      list.append(menuButton('Move', 'folder-input', () => moveMachine(machine)));
      list.append(menuButton('Delete', 'trash-2', () => deleteMachine(machine), true));
      menu.append(summary, list);
      return menu;
    }

    function machineCard(machine) {
      const card = document.createElement('article');
      card.className = 'machine-card';
      const preview = document.createElement('button');
      preview.type = 'button';
      preview.className = 'preview';
      preview.setAttribute('aria-label', `Open ${machine.name}`);
      preview.addEventListener('click', () => openMachine(machine));
      const cached = thumbnails.get(machine.id);
      if (typeof cached === 'string') {
        const image = document.createElement('img');
        image.alt = `${machine.name} desktop`;
        image.src = cached;
        preview.append(image);
      } else {
        const label = document.createElement('span');
        label.innerHTML = '<i data-lucide="monitor"></i>';
        const previewText = cached === false
          ? 'Preview unavailable'
          : (machine.status === 'running' ? 'Loading desktop' : 'Disk preserved');
        label.append(document.createTextNode(previewText));
        preview.append(label);
        if (machine.status === 'running' && cached !== false) loadThumbnail(machine);
      }

      const body = document.createElement('div');
      body.className = 'machine-body';
      const title = document.createElement('div');
      title.className = 'machine-title';
      const heading = document.createElement('h3');
      heading.textContent = machine.name;
      title.append(heading, statusBadge(machine));

      const meta = document.createElement('div');
      meta.className = 'machine-meta';
      for (const value of ['Linux', `${machine.cpu} CPU`, `${machine.ram} GiB`, machine.resolution.split('x').slice(0, 2).join(' × ')]) {
        const chip = document.createElement('span');
        chip.textContent = value;
        meta.append(chip);
      }

      const actions = document.createElement('div');
      actions.className = 'card-actions';
      const open = document.createElement('button');
      open.type = 'button';
      open.className = 'button button-secondary open-button';
      open.innerHTML = '<i data-lucide="monitor-up"></i>';
      open.append(document.createTextNode('Open desktop'));
      open.addEventListener('click', () => openMachine(machine));
      actions.append(open, machineMenu(machine));
      body.append(title, meta, actions);
      card.append(preview, body);
      return card;
    }

    function newCard() {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'new-card';
      button.disabled = !state.workspaceId;
      button.addEventListener('click', () => openCreate());
      const inner = document.createElement('span');
      inner.className = 'new-card-inner';
      inner.innerHTML = '<span class="new-card-icon"><i data-lucide="plus"></i></span><strong>New computer</strong><small>One click starts a Linux desktop in this workspace.</small>';
      button.append(inner);
      return button;
    }

    function renderMachines() {
      machinesRoot.replaceChildren();
      const machines = state.machines.filter(machine => machine.workspace_id === state.workspaceId);
      for (const machine of machines) machinesRoot.append(machineCard(machine));
      machinesRoot.append(newCard());
      if (!machines.length) {
        const empty = document.createElement('p');
        empty.className = 'empty';
        empty.textContent = state.workspaceId
          ? 'No computers here yet. Use New computer to start one.'
          : 'Create a workspace through the admin API before adding a computer.';
        machinesRoot.append(empty);
      }
      updateSummary();
      icons();
    }

    function emptyAdmin(message) {
      const empty = document.createElement('p');
      empty.className = 'empty';
      empty.textContent = message;
      return empty;
    }

    function workspaceAdminCard(workspace) {
      const card = document.createElement('article');
      card.className = 'admin-card';
      const head = document.createElement('div');
      head.className = 'admin-card-head';
      const identity = document.createElement('div');
      const name = document.createElement('h4');
      name.textContent = workspace.name;
      const id = document.createElement('small');
      id.textContent = workspace.id;
      identity.append(name, id);
      const settings = document.createElement('button');
      settings.type = 'button';
      settings.className = 'button button-secondary';
      settings.innerHTML = '<i data-lucide="settings"></i>';
      settings.append(document.createTextNode('Settings'));
      settings.addEventListener('click', () => openWorkspaceSettings(workspace));
      head.append(identity, settings);

      const keyCount = state.keys.filter(item => item.workspace_id === workspace.id).length;
      const computerCount = state.machines.filter(machine => machine.workspace_id === workspace.id).length;
      const meta = document.createElement('div');
      meta.className = 'admin-meta';
      for (const value of [
        `${computerCount} computer${computerCount === 1 ? '' : 's'}`,
        `${keyCount} scoped key${keyCount === 1 ? '' : 's'}`,
        `Created ${new Date(workspace.created_at * 1000).toLocaleDateString()}`,
      ]) {
        const chip = document.createElement('span');
        chip.textContent = value;
        meta.append(chip);
      }
      const actions = document.createElement('div');
      actions.className = 'admin-actions';
      const issue = document.createElement('button');
      issue.type = 'button';
      issue.className = 'button';
      issue.innerHTML = '<i data-lucide="key-round"></i>';
      issue.append(document.createTextNode('Issue key'));
      issue.addEventListener('click', () => openKeyCreate(workspace.id));
      actions.append(issue);
      card.append(head, meta, actions);
      return card;
    }

    function keyAdminRow(item) {
      const row = document.createElement('article');
      row.className = 'key-row';
      const identity = document.createElement('div');
      const name = document.createElement('strong');
      name.textContent = item.name;
      const workspace = state.workspaces.find(candidate => candidate.id === item.workspace_id);
      const metadata = document.createElement('small');
      metadata.textContent = `${workspace?.name || 'Unknown workspace'} · ${item.id} · ${new Date(item.created_at * 1000).toLocaleDateString()}`;
      identity.append(name, metadata);
      const revoke = document.createElement('button');
      revoke.type = 'button';
      revoke.className = 'button button-secondary';
      revoke.textContent = 'Revoke';
      revoke.addEventListener('click', () => revokeKey(item));
      row.append(identity, revoke);
      return row;
    }

    function renderAdmin() {
      workspaceCards.replaceChildren();
      keyRows.replaceChildren();
      for (const workspace of state.workspaces) workspaceCards.append(workspaceAdminCard(workspace));
      for (const item of state.keys) keyRows.append(keyAdminRow(item));
      if (!state.workspaces.length) workspaceCards.append(emptyAdmin('No workspaces yet.'));
      if (!state.keys.length) keyRows.append(emptyAdmin('No scoped keys yet.'));
      document.querySelector('#createKeyButton').disabled = !state.workspaces.length;
      updateSummary();
      icons();
    }

    function templateCard(template) {
      const card = document.createElement('article');
      card.className = 'template-card';
      const identity = document.createElement('div');
      const heading = document.createElement('h3');
      heading.textContent = template.name;
      const purpose = document.createElement('p');
      purpose.textContent = template.purpose;
      identity.append(heading, purpose);

      const hardware = document.createElement('div');
      hardware.className = 'template-hardware';
      const defaults = template.defaults;
      for (const value of [
        `${defaults.cpu} CPU`,
        `${defaults.ram} GiB`,
        'Platform managed disk',
        defaults.resolution.split('x').slice(0, 2).join(' × '),
      ]) {
        const chip = document.createElement('span');
        chip.textContent = value;
        hardware.append(chip);
      }

      const launch = document.createElement('form');
      launch.className = 'template-launch';
      const name = document.createElement('input');
      name.name = 'name';
      name.required = true;
      name.maxLength = 100;
      name.value = `desktop-${String(Math.floor(Math.random() * 10000)).padStart(4, '0')}`;
      name.setAttribute('aria-label', `Computer name for ${template.name}`);
      const workspace = document.createElement('select');
      workspace.name = 'workspace_id';
      workspace.required = true;
      workspace.setAttribute('aria-label', `Workspace for ${template.name}`);
      for (const item of state.workspaces) workspace.append(optionFor(item));
      workspace.value = state.workspaceId || state.workspaces[0]?.id || '';
      const submit = document.createElement('button');
      submit.type = 'submit';
      submit.className = 'button';
      submit.innerHTML = '<i data-lucide="play"></i>';
      submit.append(document.createTextNode('Launch'));
      submit.disabled = !state.workspaces.length;
      launch.append(name, workspace, submit);
      launch.addEventListener('submit', async event => {
        event.preventDefault();
        const body = {
          workspace_id: workspace.value,
          name: name.value.trim(),
          cpu: defaults.cpu,
          ram: defaults.ram,
          resolution: defaults.resolution,
          idle_timeout_minutes: defaults.idle_timeout_minutes,
          template_ref: template.ref,
        };
        if (defaults.disk_size_gb) body.disk_size_gb = defaults.disk_size_gb;
        submit.disabled = true;
        setTemplatesNotice(`Starting ${body.name}...`);
        try {
          const created = await api('/computers', {method: 'POST', body: JSON.stringify(body)});
          state.workspaceId = body.workspace_id;
          await showFleet();
          const machine = state.machines.find(item => item.id === created.id);
          if (machine) await openMachine(machine);
        } catch (error) {
          setTemplatesNotice(errorText(error), true);
        } finally {
          submit.disabled = false;
        }
      });

      const details = document.createElement('details');
      details.className = 'template-spec';
      const summary = document.createElement('summary');
      summary.innerHTML = '<i data-lucide="braces"></i>Operator JSON';
      const spec = document.createElement('pre');
      spec.textContent = JSON.stringify({ref: template.ref, defaults}, null, 2);
      details.append(summary, spec);
      card.append(identity, hardware, launch, details);
      return card;
    }

    function renderTemplates() {
      templateCards.replaceChildren();
      for (const template of state.templates) templateCards.append(templateCard(template));
      if (!state.templates.length) templateCards.append(emptyAdmin('No curated templates are available.'));
      updateSummary();
      icons();
    }

    async function loadThumbnail(machine) {
      if (thumbnailLoads.has(machine.id)) return;
      thumbnailLoads.add(machine.id);
      try {
        const result = await api(`/computers/${machine.id}/screenshot`);
        thumbnails.set(machine.id, `data:image/png;base64,${result.screenshot}`);
      } catch {
        thumbnails.set(machine.id, false);
      } finally {
        thumbnailLoads.delete(machine.id);
        renderMachines();
      }
    }

    async function load(message = state.view === 'admin' ? 'Workspace access refreshed.' : (state.view === 'templates' ? 'Templates refreshed.' : 'Yard refreshed.')) {
      if (!key.value && !apiKey) {
        (state.view === 'admin' ? setAdminNotice : (state.view === 'templates' ? setTemplatesNotice : setNotice))('Enter a Backlot API key.', true);
        return;
      }
      const announce = state.view === 'admin' ? setAdminNotice : (state.view === 'templates' ? setTemplatesNotice : setNotice);
      announce(state.view === 'admin' ? 'Loading workspace access...' : (state.view === 'templates' ? 'Loading templates...' : 'Loading yard...'));
      try {
        if (state.view === 'admin') {
          [state.workspaces, state.machines, state.keys] = await Promise.all([
            api('/workspaces'),
            api('/computers'),
            api('/api-keys'),
          ]);
        } else if (state.view === 'templates') {
          [state.workspaces, state.machines, state.templates] = await Promise.all([
            api('/workspaces'),
            api('/computers'),
            api('/templates'),
          ]);
        } else {
          [state.workspaces, state.machines] = await Promise.all([api('/workspaces'), api('/computers')]);
        }
        renderWorkspaceOptions();
        renderMachines();
        if (state.view === 'admin') renderAdmin();
        if (state.view === 'templates') renderTemplates();
        if (state.computerId) {
          const current = state.machines.find(machine => machine.id === state.computerId);
          if (current) await renderComputer(current, false);
        }
        announce(message);
      } catch (error) {
        state.workspaces = [];
        state.machines = [];
        state.keys = [];
        state.templates = [];
        renderWorkspaceOptions();
        renderMachines();
        if (state.view === 'admin') renderAdmin();
        if (state.view === 'templates') renderTemplates();
        announce(errorText(error), true);
      }
    }

    function openCreate(workspaceId = state.workspaceId) {
      if (!workspaceId) return;
      document.querySelector('#computerName').value = `computer-${String(Math.floor(Math.random() * 10000)).padStart(4, '0')}`;
      createWorkspace.value = workspaceId;
      createDialog.showModal();
      document.querySelector('#computerName').select();
      icons();
    }

    async function createMachine(event) {
      event.preventDefault();
      const data = new FormData(createForm);
      const body = {
        workspace_id: data.get('workspace_id'),
        name: data.get('name'),
        cpu: Number(data.get('cpu')),
        ram: Number(data.get('ram')),
        resolution: data.get('resolution'),
        idle_timeout_minutes: Number(data.get('idle_timeout_minutes')),
      };
      if (data.get('disk_size_gb')) body.disk_size_gb = Number(data.get('disk_size_gb'));
      if (data.get('template_ref')) body.template_ref = data.get('template_ref');
      const submit = document.querySelector('#createButton');
      submit.disabled = true;
      submit.textContent = 'Starting computer...';
      try {
        await api('/computers', {method: 'POST', body: JSON.stringify(body)});
        createDialog.close();
        await load(`${body.name} is running.`);
      } catch (error) {
        setNotice(errorText(error), true);
      } finally {
        submit.disabled = false;
        submit.innerHTML = '<i data-lucide="play"></i>Create and start';
        icons();
      }
    }

    function applyView(view, updateHistory = true) {
      disconnectRfb();
      state.view = view;
      state.computerId = '';
      state.standalone = false;
      document.body.classList.remove('computer-mode');
      desktop.hidden = true;
      screen.replaceChildren();
      document.querySelector('#fleetView').hidden = view !== 'fleet';
      document.querySelector('#adminView').hidden = view !== 'admin';
      document.querySelector('#templatesView').hidden = view !== 'templates';
      document.querySelector('#fleetNav').setAttribute('aria-current', view === 'fleet' ? 'page' : 'false');
      document.querySelector('#adminNav').setAttribute('aria-current', view === 'admin' ? 'page' : 'false');
      document.querySelector('#templatesNav').setAttribute('aria-current', view === 'templates' ? 'page' : 'false');
      document.querySelector('#pageTitle').textContent =
        view === 'admin' ? 'Workspace admin' : (view === 'templates' ? 'Templates' : 'Computers');
      if (updateHistory) history.pushState(null, '', view === 'admin' ? '/admin' : (view === 'templates' ? '/library' : '/'));
      updateSummary();
      icons();
    }

    async function showFleet(updateHistory = true) {
      applyView('fleet', updateHistory);
      renderMachines();
      if (key.value || apiKey) await load('Yard refreshed.');
    }

    async function showAdmin(updateHistory = true) {
      applyView('admin', updateHistory);
      renderAdmin();
      if (key.value || apiKey) await load('Workspace access refreshed.');
    }

    async function showTemplates(updateHistory = true) {
      applyView('templates', updateHistory);
      renderTemplates();
      if (key.value || apiKey) await load('Templates refreshed.');
    }

    function paletteItems() {
      const items = [
        {
          label: 'New computer',
          detail: 'Create in the selected workspace',
          icon: 'plus',
          run: async () => {
            applyView('fleet');
            renderMachines();
            openCreate();
          },
        },
        {
          label: 'Templates',
          detail: 'Open the curated template library',
          icon: 'layout-template',
          run: () => showTemplates(),
        },
      ];
      for (const workspace of state.workspaces) {
        items.push({
          label: workspace.name,
          detail: `Workspace · ${workspace.id}`,
          icon: 'folder',
          run: async () => {
            state.workspaceId = workspace.id;
            await showFleet();
          },
        });
      }
      for (const machine of state.machines) {
        items.push({
          label: machine.name,
          detail: `Computer · ${machine.status}`,
          icon: 'monitor',
          run: () => openMachine(machine),
        });
      }
      return items;
    }

    function renderPalette() {
      const query = paletteInput.value.trim().toLowerCase();
      const items = paletteItems().filter(item =>
        !query || `${item.label} ${item.detail}`.toLowerCase().includes(query)
      );
      paletteResults.replaceChildren();
      for (const [index, item] of items.entries()) {
        const result = document.createElement('button');
        result.type = 'button';
        result.className = `palette-result${index === 0 ? ' active' : ''}`;
        result.setAttribute('role', 'option');
        result.setAttribute('aria-selected', index === 0 ? 'true' : 'false');
        const icon = document.createElement('i');
        icon.dataset.lucide = item.icon;
        const copy = document.createElement('span');
        const label = document.createElement('strong');
        label.textContent = item.label;
        const detail = document.createElement('small');
        detail.textContent = item.detail;
        copy.append(label, detail);
        result.append(icon, copy);
        result.addEventListener('click', async () => {
          paletteDialog.close();
          await item.run();
        });
        paletteResults.append(result);
      }
      if (!items.length) paletteResults.append(emptyAdmin('No matching workspace, computer, or action.'));
      icons();
    }

    function openPalette() {
      if (paletteDialog.open) {
        paletteDialog.close();
        return;
      }
      paletteInput.value = '';
      renderPalette();
      paletteDialog.showModal();
      paletteInput.focus();
    }

    function movePaletteSelection(direction) {
      const results = [...paletteResults.querySelectorAll('.palette-result')];
      if (!results.length) return;
      const current = Math.max(0, results.findIndex(result => result.classList.contains('active')));
      const next = (current + direction + results.length) % results.length;
      for (const [index, result] of results.entries()) {
        result.classList.toggle('active', index === next);
        result.setAttribute('aria-selected', index === next ? 'true' : 'false');
      }
      results[next].scrollIntoView({block: 'nearest'});
    }

    function openWorkspaceCreate() {
      document.querySelector('#workspaceName').value = '';
      workspaceCreateDialog.showModal();
      document.querySelector('#workspaceName').focus();
      icons();
    }

    async function createWorkspaceAdmin(event) {
      event.preventDefault();
      const name = new FormData(workspaceCreateForm).get('name').trim();
      const submit = document.querySelector('#workspaceCreateSubmit');
      submit.disabled = true;
      try {
        const created = await api('/workspaces', {method: 'POST', body: JSON.stringify({name})});
        state.workspaceId = created.id;
        workspaceCreateDialog.close();
        await load(`${name} created.`);
      } catch (error) {
        setAdminNotice(errorText(error), true);
      } finally {
        submit.disabled = false;
      }
    }

    function openKeyCreate(workspaceId = state.workspaceId) {
      if (!state.workspaces.length) return;
      document.querySelector('#keyName').value = '';
      keyWorkspace.value = workspaceId || state.workspaces[0].id;
      keyCreateDialog.showModal();
      document.querySelector('#keyName').focus();
      icons();
    }

    async function createKeyAdmin(event) {
      event.preventDefault();
      const data = new FormData(keyCreateForm);
      const body = {name: data.get('name').trim(), workspace_id: data.get('workspace_id')};
      const submit = document.querySelector('#keyCreateSubmit');
      submit.disabled = true;
      try {
        const created = await api('/api-keys', {method: 'POST', body: JSON.stringify(body)});
        keyCreateDialog.close();
        oneTimeKey.value = created.key;
        document.querySelector('#copyOneTimeKey').lastChild.textContent = 'Copy key';
        keyRevealDialog.showModal();
        await load(`${body.name} issued. Copy the raw key now.`);
      } catch (error) {
        setAdminNotice(errorText(error), true);
      } finally {
        submit.disabled = false;
      }
    }

    function closeKeyReveal() {
      oneTimeKey.value = '';
      keyRevealDialog.close();
    }

    async function copyKeyReveal() {
      if (!oneTimeKey.value) return;
      try {
        await navigator.clipboard.writeText(oneTimeKey.value);
        document.querySelector('#copyOneTimeKey').lastChild.textContent = 'Copied';
      } catch (error) {
        setAdminNotice(errorText(error), true);
      }
    }

    async function revokeKey(item) {
      if (!await confirmAction(
        `Revoke ${item.name}? Requests using this key will stop working immediately.`,
        'Revoke key',
      )) return;
      try {
        await api(`/api-keys/${item.id}`, {method: 'DELETE'});
        await load(`${item.name} revoked.`);
      } catch (error) {
        setAdminNotice(errorText(error), true);
      }
    }

    function openWorkspaceSettings(workspace) {
      state.settingsWorkspaceId = workspace.id;
      const computerCount = state.machines.filter(machine => machine.workspace_id === workspace.id).length;
      const keyCount = state.keys.filter(item => item.workspace_id === workspace.id).length;
      workspaceSettingsBody.replaceChildren(
        setting('Name', workspace.name),
        setting('Workspace ID', workspace.id),
        setting('Created', new Date(workspace.created_at * 1000).toLocaleString()),
        setting('Computers', computerCount),
        setting('Scoped keys', keyCount),
      );
      workspaceSettingsDialog.showModal();
      icons();
    }

    async function deleteWorkspaceAdmin() {
      const workspace = state.workspaces.find(item => item.id === state.settingsWorkspaceId);
      if (!workspace) return;
      const computerCount = state.machines.filter(machine => machine.workspace_id === workspace.id).length;
      if (computerCount) {
        setAdminNotice('Delete this workspace’s computers first.', true);
        workspaceSettingsDialog.close();
        return;
      }
      if (!await confirmAction(
        `Delete ${workspace.name}? Its scoped keys will be revoked.`,
        'Delete workspace',
      )) return;
      try {
        await api(`/workspaces/${workspace.id}`, {method: 'DELETE'});
        workspaceSettingsDialog.close();
        state.settingsWorkspaceId = '';
        if (state.workspaceId === workspace.id) state.workspaceId = '';
        await load(`${workspace.name} deleted.`);
      } catch (error) {
        setAdminNotice(errorText(error), true);
      }
    }

    async function lifecycle(machine, action) {
      const announce = state.computerId ? setDesktopNotice : setNotice;
      announce(`${action[0].toUpperCase()}${action.slice(1)}ing ${machine.name}...`);
      try {
        await api(`/computers/${machine.id}/${action}`, {method: 'POST'});
        thumbnails.delete(machine.id);
        await load(`${machine.name} ${action === 'stop' ? 'stopped with disk preserved.' : 'is running.'}`);
        if (state.computerId) {
          setDesktopNotice(`${machine.name} ${action === 'stop' ? 'stopped with disk preserved.' : 'is running.'}`);
        }
      } catch (error) {
        announce(errorText(error), true);
      }
    }

    async function cloneMachine(machine) {
      const name = prompt('Clone name', `${machine.name} copy`);
      if (!name) return;
      try {
        await api('/clone', {method: 'POST', body: JSON.stringify({computer_id: machine.id, name})});
        await load(`${name} cloned with disk preserved.`);
      } catch (error) { setNotice(errorText(error), true); }
    }

    async function resizeMachine(machine) {
      const ram = Number(prompt('Memory in GiB: 4, 8, 16, 32, or 64', String(machine.ram)));
      const cpu = Number(prompt('CPU cores: 1, 2, 4, 8, or 16', String(machine.cpu)));
      if (!ram || !cpu) return;
      try {
        await api(`/computers/${machine.id}/resize`, {method: 'PATCH', body: JSON.stringify({ram, cpu})});
        thumbnails.delete(machine.id);
        await load(`${machine.name} resized.`);
      } catch (error) { setNotice(errorText(error), true); }
    }

    async function moveMachine(machine) {
      const choices = state.workspaces.filter(workspace => workspace.id !== machine.workspace_id);
      if (!choices.length) {
        setNotice('Create another workspace before moving this computer.', true);
        return;
      }
      const target = prompt(`Move to workspace ID:\\n${choices.map(workspace => `${workspace.name}: ${workspace.id}`).join('\\n')}`, choices[0].id);
      if (!target) return;
      try {
        await api(`/computers/${machine.id}/move`, {method: 'PATCH', body: JSON.stringify({workspace_id: target})});
        await load(`${machine.name} moved.`);
      } catch (error) { setNotice(errorText(error), true); }
    }

    async function deleteMachine(machine) {
      if (!await confirmAction(
        `Delete ${machine.name}? Its disk snapshot will be removed from Backlot.`,
        'Delete computer',
      )) return;
      try {
        await api(`/computers/${machine.id}`, {method: 'DELETE'});
        thumbnails.delete(machine.id);
        await load(`${machine.name} deleted.`);
      } catch (error) { setNotice(errorText(error), true); }
    }

    function currentMachine() {
      return state.machines.find(machine => machine.id === state.computerId);
    }

    function setting(label, value) {
      const item = document.createElement('div');
      item.className = 'setting';
      const caption = document.createElement('small');
      caption.textContent = label;
      const content = document.createElement('strong');
      content.textContent = String(value ?? 'Not set');
      item.append(caption, content);
      return item;
    }

    function renderSettings(machine) {
      settingsGrid.replaceChildren(
        setting('Name', machine.name),
        setting('Computer ID', machine.id),
        setting('Status', machine.status),
        setting('Created', new Date(machine.created_at * 1000).toLocaleString()),
        setting('CPU', `${machine.cpu} ${machine.cpu === 1 ? 'core' : 'cores'}`),
        setting('Memory', `${machine.ram} GiB`),
        // disk_size_gb is stored but never applied: Modal exposes no disk parameter and
        // the real disk is platform managed. Showing the requested number would state
        // something untrue about a customer's machine.
        setting('Disk', 'Platform managed (not configurable)'),
        setting('Resolution', machine.resolution.split('x').slice(0, 2).join(' × ')),
        setting('Idle stop', `${machine.idle_timeout_minutes} minutes`),
        setting('Persistent disk', machine.snapshot_image_id ? 'Snapshot available' : 'No stopped snapshot yet'),
      );
    }

    function renderDesktopState(machine) {
      disconnectRfb();
      const empty = document.createElement('div');
      empty.className = 'desktop-state';
      const icon = document.createElement('i');
      icon.dataset.lucide = machine.status === 'error' ? 'triangle-alert' : 'power';
      const heading = document.createElement('h2');
      heading.textContent = machine.status === 'error' ? 'Desktop needs a restart' : 'Computer is stopped';
      const copy = document.createElement('p');
      copy.textContent = machine.status === 'error'
        ? 'Restart the computer to rebuild its runtime from the preserved disk.'
        : 'The disk is preserved. Start the computer to open a fresh Linux session.';
      const start = document.createElement('button');
      start.type = 'button';
      start.className = 'button';
      start.textContent = machine.status === 'error' ? 'Restart computer' : 'Start computer';
      start.addEventListener('click', () => lifecycle(machine, machine.status === 'error' ? 'restart' : 'start'));
      empty.append(icon, heading, copy, start);
      screen.replaceChildren(empty);
    }

    function updateStandaloneLabel() {
      document.querySelector('#desktopStandalone').lastChild.textContent = state.standalone ? 'Canvas' : 'Standalone';
    }

    function disconnectRfb() {
      if (!activeRfb) return;
      activeRfb.disconnect();
      activeRfb = null;
    }

    async function rfbClass() {
      if (window.BacklotRFB) return window.BacklotRFB;
      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('noVNC client failed to load.')), 10000);
        window.addEventListener('backlot-rfb-ready', () => {
          clearTimeout(timeout);
          resolve();
        }, {once: true});
      });
      return window.BacklotRFB;
    }

    async function renderComputer(machine, updateHistory = true) {
      disconnectRfb();
      state.computerId = machine.id;
      document.body.classList.add('computer-mode');
      desktop.hidden = false;
      desktop.classList.toggle('standalone', state.standalone);
      updateStandaloneLabel();
      document.querySelector('#desktopName').textContent = machine.name;
      const badge = document.querySelector('#desktopStatus');
      badge.className = `status ${machine.status}`;
      badge.replaceChildren();
      const dot = document.createElement('span');
      dot.className = 'dot';
      badge.append(dot, document.createTextNode(machine.status));
      document.querySelector('#desktopStart').hidden = machine.status === 'running';
      document.querySelector('#desktopStop').hidden = machine.status !== 'running';
      document.querySelector('#desktopRestart').hidden = machine.status !== 'running' && machine.status !== 'error';
      document.querySelector('#commandRail').hidden = machine.status !== 'running';
      renderSettings(machine);
      if (updateHistory) {
        history.pushState(null, '', `/computer/${encodeURIComponent(machine.id)}${state.standalone ? '/desktop' : ''}`);
      }
      setDesktopNotice('');
      if (machine.status !== 'running') {
        renderDesktopState(machine);
        icons();
        return;
      }
      const opening = document.createElement('div');
      opening.className = 'desktop-state';
      opening.textContent = 'Opening authenticated desktop...';
      screen.replaceChildren(opening);
      try {
        const vnc = await api(`/computers/${machine.id}/vnc-password`);
        const target = new URL(vnc.url);
        const connectToken = target.searchParams.get('_modal_connect_token');
        if (!connectToken) throw new Error('Desktop connection token is missing.');
        const socket = new URL(`${target.protocol === 'https:' ? 'wss:' : 'ws:'}//${target.host}/websockify`);
        socket.searchParams.set('_modal_connect_token', connectToken);
        const host = document.createElement('div');
        host.className = 'rfb-host';
        host.setAttribute('aria-label', `${machine.name} Linux desktop`);
        screen.replaceChildren(host);
        const RFB = await rfbClass();
        activeRfb = new RFB(host, socket.toString(), {credentials: {password: vnc.password}});
        activeRfb.scaleViewport = true;
        activeRfb.resizeSession = false;
        activeRfb.addEventListener('connect', () => setDesktopNotice(`${machine.name} desktop opened.`), {once: true});
        activeRfb.addEventListener('disconnect', event => {
          if (event.detail.clean) return;
          setDesktopNotice('Desktop connection closed unexpectedly.', true);
        });
        activeRfb.addEventListener('clipboard', event => {
          clipboardText.value = event.detail.text || '';
        });
      } catch (error) {
        renderDesktopState({...machine, status: 'error'});
        setDesktopNotice(errorText(error), true);
      }
      icons();
    }

    async function openMachine(machine) {
      commandHistory.replaceChildren();
      state.view = 'fleet';
      state.standalone = false;
      await renderComputer(machine);
    }

    function closeComputer(updateHistory = true) {
      applyView('fleet', updateHistory);
      desktop.classList.remove('standalone');
      commandHistory.replaceChildren();
      renderMachines();
    }

    function toggleStandalone() {
      const machine = currentMachine();
      if (!machine) return;
      state.standalone = !state.standalone;
      desktop.classList.toggle('standalone', state.standalone);
      history.pushState(null, '', `/computer/${encodeURIComponent(machine.id)}${state.standalone ? '/desktop' : ''}`);
      updateStandaloneLabel();
    }

    async function runCommand(event) {
      event.preventDefault();
      const machine = currentMachine();
      const input = document.querySelector('#commandInput');
      const command = input.value.trim();
      if (!machine || machine.status !== 'running' || !command) return;
      input.value = '';
      const entry = document.createElement('article');
      entry.className = 'command-entry';
      const prompt = document.createElement('strong');
      prompt.textContent = `$ ${command}`;
      const output = document.createElement('pre');
      output.textContent = 'Running...';
      entry.append(prompt, output);
      commandHistory.append(entry);
      entry.scrollIntoView({block: 'nearest'});
      const run = document.querySelector('#commandRun');
      run.disabled = true;
      try {
        const result = await api(`/computers/${machine.id}/bash`, {
          method: 'POST',
          body: JSON.stringify({command}),
        });
        entry.classList.toggle('error', !result.success);
        output.textContent = [result.stdout, result.stderr].filter(Boolean).join('\\n') || `(exit ${result.exit_code})`;
        setDesktopNotice(`Command finished with exit ${result.exit_code}.`, !result.success);
      } catch (error) {
        entry.classList.add('error');
        output.textContent = errorText(error);
        setDesktopNotice(errorText(error), true);
      } finally {
        run.disabled = false;
      }
    }

    document.querySelector('#loadButton').addEventListener('click', () => load());
    document.querySelector('#refreshButton').addEventListener('click', () => load());
    document.querySelector('#fleetNav').addEventListener('click', () => showFleet());
    document.querySelector('#templatesNav').addEventListener('click', () => showTemplates());
    document.querySelector('#adminNav').addEventListener('click', () => showAdmin());
    document.querySelector('#paletteButton').addEventListener('click', openPalette);
    document.querySelector('#templatesRefreshButton').addEventListener('click', () => load('Templates refreshed.'));
    workspaceSelect.addEventListener('change', () => {
      state.workspaceId = workspaceSelect.value;
      createWorkspace.value = state.workspaceId;
      renderMachines();
      if (state.view === 'templates') renderTemplates();
    });
    createForm.addEventListener('submit', createMachine);
    document.querySelector('#createWorkspaceButton').addEventListener('click', openWorkspaceCreate);
    workspaceCreateForm.addEventListener('submit', createWorkspaceAdmin);
    for (const button of document.querySelectorAll('[data-close-workspace-create]')) {
      button.addEventListener('click', () => workspaceCreateDialog.close());
    }
    document.querySelector('#createKeyButton').addEventListener('click', () => openKeyCreate());
    keyCreateForm.addEventListener('submit', createKeyAdmin);
    for (const button of document.querySelectorAll('[data-close-key-create]')) {
      button.addEventListener('click', () => keyCreateDialog.close());
    }
    document.querySelector('#copyOneTimeKey').addEventListener('click', copyKeyReveal);
    for (const button of document.querySelectorAll('[data-close-key-reveal]')) {
      button.addEventListener('click', closeKeyReveal);
    }
    keyRevealDialog.addEventListener('close', () => {
      oneTimeKey.value = '';
      document.querySelector('#copyOneTimeKey').lastChild.textContent = 'Copy key';
    });
    document.querySelector('#deleteWorkspaceButton').addEventListener('click', deleteWorkspaceAdmin);
    for (const button of document.querySelectorAll('[data-close-workspace-settings]')) {
      button.addEventListener('click', () => workspaceSettingsDialog.close());
    }
    document.querySelector('[data-confirm-cancel]').addEventListener('click', () => finishConfirmation(false));
    confirmationButton.addEventListener('click', () => finishConfirmation(true));
    confirmationDialog.addEventListener('cancel', event => {
      event.preventDefault();
      finishConfirmation(false);
    });
    for (const button of document.querySelectorAll('[data-close-create]')) {
      button.addEventListener('click', () => createDialog.close());
    }
    for (const button of document.querySelectorAll('[data-close-settings]')) {
      button.addEventListener('click', () => settingsDialog.close());
    }
    for (const button of document.querySelectorAll('[data-close-clipboard]')) {
      button.addEventListener('click', () => clipboardDialog.close());
    }
    document.querySelector('#closeDesktop').addEventListener('click', () => closeComputer());
    document.querySelector('#desktopStart').addEventListener('click', () => {
      const machine = currentMachine();
      if (machine) lifecycle(machine, 'start');
    });
    document.querySelector('#desktopStop').addEventListener('click', () => {
      const machine = currentMachine();
      if (machine) lifecycle(machine, 'stop');
    });
    document.querySelector('#desktopRestart').addEventListener('click', () => {
      const machine = currentMachine();
      if (machine) lifecycle(machine, 'restart');
    });
    document.querySelector('#desktopSettings').addEventListener('click', () => {
      const machine = currentMachine();
      if (!machine) return;
      renderSettings(machine);
      settingsDialog.showModal();
      icons();
    });
    document.querySelector('#desktopClipboard').addEventListener('click', () => {
      clipboardDialog.showModal();
      clipboardText.focus();
      icons();
    });
    document.querySelector('#clipboardSend').addEventListener('click', () => {
      if (!activeRfb) return;
      activeRfb.clipboardPasteFrom(clipboardText.value);
      clipboardDialog.close();
      setDesktopNotice('Clipboard sent to the VM.');
    });
    document.querySelector('#desktopStandalone').addEventListener('click', toggleStandalone);
    document.querySelector('#desktopFullscreen').addEventListener('click', async () => {
      try {
        await screen.requestFullscreen();
      } catch (error) {
        setDesktopNotice(errorText(error), true);
      }
    });
    document.querySelector('#commandForm').addEventListener('submit', runCommand);
    paletteInput.addEventListener('input', renderPalette);
    paletteInput.addEventListener('keydown', event => {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        movePaletteSelection(event.key === 'ArrowDown' ? 1 : -1);
      } else if (event.key === 'Enter') {
        event.preventDefault();
        paletteResults.querySelector('.palette-result.active')?.click();
      }
    });
    for (const button of document.querySelectorAll('[data-close-palette]')) {
      button.addEventListener('click', () => paletteDialog.close());
    }
    document.addEventListener('keydown', event => {
      const target = event.target;
      const typing = target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement ||
        target instanceof HTMLSelectElement || target?.isContentEditable;
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        openPalette();
      } else if (event.key === '/' && !typing && !paletteDialog.open) {
        event.preventDefault();
        openPalette();
      }
    });
    key.addEventListener('keydown', event => {
      if (event.key === 'Enter') load();
    });
    window.addEventListener('popstate', async () => {
      if (location.pathname === '/admin') {
        await showAdmin(false);
        return;
      }
      if (location.pathname === '/library') {
        await showTemplates(false);
        return;
      }
      const match = location.pathname.match(/^[/]computer[/]([^/]+)/);
      if (!match) {
        await showFleet(false);
        return;
      }
      state.view = 'fleet';
      state.computerId = decodeURIComponent(match[1]);
      state.standalone = location.pathname.endsWith('/desktop');
      const machine = currentMachine();
      if (machine) renderComputer(machine, false);
    });
    if (location.pathname === '/admin') applyView('admin', false);
    if (location.pathname === '/library') applyView('templates', false);
    icons();
    refreshServiceHealth();
    setInterval(refreshServiceHealth, 30000);
  </script>
</body>
</html>
"""
