from __future__ import annotations

import json
import os
import secrets
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import uuid4

from mcp_zero_trust_layer.evidence.canonical import canonical


@contextmanager
def database(path: Path) -> Iterator[sqlite3.Connection]:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(fd).st_mode & 0o077:
            raise ValueError("evidence database must be private (0600)")
    finally:
        os.close(fd)
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA synchronous=FULL")
        with connection:
            yield connection
    finally:
        connection.close()


class EvidenceStore:
    """SQLite is authoritative; JSONL outbox delivery is at-least-once by event_id."""

    def __init__(self, path: Path):
        self.path = path
        with database(path) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS evidence_v1_settings (name TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS evidence_v1_operations (
                    operation_id TEXT PRIMARY KEY, tenant TEXT NOT NULL,
                    scope TEXT UNIQUE NOT NULL, fingerprint TEXT NOT NULL,
                    bundle TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS evidence_v1_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL,
                    operation_id TEXT NOT NULL, payload TEXT NOT NULL,
                    delivered INTEGER NOT NULL DEFAULT 0);
            """)
            db.execute("INSERT OR IGNORE INTO evidence_v1_settings VALUES('salt',?)",
                       (secrets.token_hex(32),))
            self.salt = bytes.fromhex(db.execute(
                "SELECT value FROM evidence_v1_settings WHERE name='salt'").fetchone()[0])

    @staticmethod
    def append(db: sqlite3.Connection, operation: str, event: dict[str, Any]) -> None:
        event = {"event_id": "ev_" + uuid4().hex, "event_type": "execution_evidence",
                 "operation_id": operation, **event}
        db.execute("INSERT INTO evidence_v1_events(event_id,operation_id,payload) VALUES(?,?,?)",
                   (event["event_id"], operation, canonical(event).decode()))

    def reserve(self, bundle: dict[str, Any], scope: str, fingerprint: str,
                consume: Callable[[sqlite3.Connection], bool] | None = None) -> str | None:
        auth = bundle["permit"]["authorization"]["payload"]
        operation = auth["operation_id"]
        with database(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT * FROM evidence_v1_operations WHERE scope=?",
                                  (scope,)).fetchone()
            if previous:
                if previous["fingerprint"] != fingerprint:
                    raise ValueError("IDEMPOTENCY_CONFLICT")
                return str(previous["operation_id"])
            if consume is not None and not consume(db):
                raise ValueError("APPROVAL_NOT_ACTIVE")
            db.execute("INSERT INTO evidence_v1_operations VALUES(?,?,?,?,?)",
                       (operation, auth["tenant"], scope, fingerprint, canonical(bundle).decode()))
            self.append(db, operation, {"phase": "dispatch_intent", "effect": "unknown"})
        return None

    def get(self, operation: str, tenant: str) -> dict[str, Any]:
        with database(self.path) as db:
            row = db.execute("SELECT bundle FROM evidence_v1_operations "
                             "WHERE operation_id=? AND tenant=?", (operation, tenant)).fetchone()
            conflict = db.execute("SELECT 1 FROM evidence_v1_events WHERE operation_id=? "
                                  "AND json_extract(payload,'$.phase')='receipt_conflict'",
                                  (operation,)).fetchone()
        if row is None:
            raise ValueError("OPERATION_NOT_FOUND")
        if conflict:
            raise ValueError("RECEIPT_CONFLICT")
        return json.loads(row["bundle"])

    def record(self, operation: str, tenant: str, event: dict[str, Any],
               receipt: dict[str, Any] | None = None) -> None:
        with database(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT bundle FROM evidence_v1_operations "
                             "WHERE operation_id=? AND tenant=?", (operation, tenant)).fetchone()
            if row is None:
                raise ValueError("OPERATION_NOT_FOUND")
            bundle = json.loads(row["bundle"])
            if receipt is not None:
                old = bundle.get("receipt")
                if (old is not None and old != receipt and
                    (old["payload"]["effect"] != "pending" or
                     receipt["payload"]["sequence"] <= old["payload"]["sequence"])):
                    # Only pending receipts may advance; terminal outcomes are immutable.
                    self.append(db, operation, {"phase": "receipt_conflict", "effect": "unknown"})
                    conflict = True
                else:
                    conflict = False
                    bundle["receipt"] = receipt
                    db.execute("UPDATE evidence_v1_operations SET bundle=? WHERE operation_id=?",
                               (canonical(bundle).decode(), operation))
            else:
                conflict = False
            self.append(db, operation, event)
        if conflict:
            raise ValueError("RECEIPT_CONFLICT")

    def events(self, operation: str, tenant: str) -> list[dict[str, Any]]:
        self.get(operation, tenant)
        with database(self.path) as db:
            return [json.loads(row[0]) for row in db.execute(
                "SELECT payload FROM evidence_v1_events WHERE operation_id=? ORDER BY seq",
                (operation,))]

    def flush(self, emit: Callable[[dict[str, Any]], None]) -> None:
        with database(self.path) as db:
            rows = db.execute("SELECT seq,payload FROM evidence_v1_events "
                              "WHERE delivered=0 ORDER BY seq LIMIT 1000").fetchall()
            for row in rows:
                emit(json.loads(row["payload"]))
                db.execute("UPDATE evidence_v1_events SET delivered=1 WHERE seq=?", (row["seq"],))
