# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Small in-process TTL cache for list calls. Lives for the life of one Lambda sandbox."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Hashable
from typing import Any, TypeVar

T = TypeVar("T")


class TTLCache:
    def __init__(self, clock: Callable[[], float] = time.monotonic, max_entries: int = 512) -> None:
        self._clock = clock
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._entries: dict[Hashable, tuple[float, Any]] = {}

    def get_or_load(self, key: Hashable, ttl_seconds: float, loader: Callable[[], T]) -> T:
        """Return the cached value for ``key`` or call ``loader``. Failures are never cached."""
        now = self._clock()
        if ttl_seconds > 0:
            with self._lock:
                hit = self._entries.get(key)
                if hit is not None and hit[0] > now:
                    return hit[1]
        value = loader()
        if ttl_seconds > 0:
            with self._lock:
                if len(self._entries) >= self._max_entries:
                    self._entries = {k: v for k, v in self._entries.items() if v[0] > now}
                    if len(self._entries) >= self._max_entries:
                        self._entries.clear()
                self._entries[key] = (now + ttl_seconds, value)
        return value

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
