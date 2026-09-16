"""Bounded gateway-owned session identifiers, separate from upstream identifiers."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from uuid import uuid4

from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.upstream.http import HTTPUpstreamClient


@dataclass
class Session:
    server: str
    owner: tuple[str, str | None, str | None]
    touched: float


class SessionRegistry:
    def __init__(self, upstream: HTTPUpstreamClient, *, ttl: float = 3600, capacity: int = 10000):
        self.upstream = upstream
        self.ttl = ttl
        self.capacity = capacity
        self.entries: dict[str, Session] = {}
        self.lock = threading.Lock()

    def resolve(self, server: str, identity: Identity, supplied: str | None, *, initialize: bool) -> str | None:
        owner = (identity.subject, identity.client_id, identity.agent_id)
        with self.lock:
            now = time.monotonic()
            for key, existing in list(self.entries.items()):
                if now - existing.touched >= self.ttl:
                    self._remove(key)
            if supplied:
                entry = self.entries.get(supplied)
                if entry is None or entry.server != server or entry.owner != owner:
                    raise KeyError("Unknown session")
                if initialize:
                    raise ValueError("Initialize must start a new session")
                entry.touched = now
                return supplied
            if not initialize:
                # Stateless requests cannot reuse a previous upstream session.
                return None
            if len(self.entries) >= self.capacity:
                raise OverflowError("Session capacity reached")
            key = uuid4().hex
            self.entries[key] = Session(server, owner, now)
            self.upstream.register_session(server, key)
            return key

    def active(self, key: str) -> bool:
        with self.lock:
            return key in self.entries

    def remove(self, key: str) -> None:
        with self.lock:
            self._remove(key)

    def _remove(self, key: str) -> None:
        entry = self.entries.pop(key, None)
        if entry is not None:
            self.upstream.forget_session(entry.server, key)
