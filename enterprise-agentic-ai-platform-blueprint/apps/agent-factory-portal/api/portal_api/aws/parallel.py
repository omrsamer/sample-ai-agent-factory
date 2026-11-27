# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Bounded fan-out helper."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor

MAX_WORKERS = 8


def pmap[T, R](fn: Callable[[T], R], items: Sequence[T], max_workers: int = MAX_WORKERS) -> list[R | BaseException]:
    """Apply ``fn`` to every item on a bounded pool, keeping order.

    A failure is returned in place of the result, so one unreachable account or
    one failing resource never fails the whole response.
    """
    if not items:
        return []

    def guarded(item: T) -> R | BaseException:
        try:
            return fn(item)
        except Exception as exc:  # noqa: BLE001 - reported to the caller per item
            return exc

    if len(items) == 1:
        return [guarded(items[0])]
    with ThreadPoolExecutor(max_workers=min(max_workers, len(items)), thread_name_prefix="portal") as pool:
        return list(pool.map(guarded, items))
