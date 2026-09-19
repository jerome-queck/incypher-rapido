"""Injectable monotonic clock for bounded controller waits."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Protocol


class AsyncClock(Protocol):
    """Small clock seam; wall-clock timestamps remain owned by durable state."""

    def monotonic(self) -> float: ...

    async def sleep(self, seconds: float) -> None: ...


class SystemClock:
    """Production clock with the exact pre-injection primitives."""

    def __init__(
        self,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._monotonic = monotonic
        self._sleep = sleep

    def monotonic(self) -> float:
        return self._monotonic()

    async def sleep(self, seconds: float) -> None:
        await self._sleep(seconds)


class ManualClock:
    """Cooperative accelerated clock for benign controller-contract tests."""

    def __init__(self, initial: float = 0.0) -> None:
        if initial < 0:
            raise ValueError("initial monotonic time must be non-negative")
        self._now = float(initial)
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self._now

    async def sleep(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("sleep duration must be non-negative")
        delay = float(seconds)
        self.sleeps.append(delay)
        self._now += delay
        await asyncio.sleep(0)

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("advance duration must be non-negative")
        self._now += float(seconds)


__all__ = ["AsyncClock", "ManualClock", "SystemClock"]
