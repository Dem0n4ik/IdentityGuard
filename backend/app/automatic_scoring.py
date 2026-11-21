"""Automatically evaluate hours once their arrival grace period has passed."""

import asyncio
import logging
import sqlite3
from collections.abc import Awaitable, Callable

from polars.exceptions import PolarsError
from temporalio.service import RPCError

logger = logging.getLogger(__name__)


async def repeat(
    stop: asyncio.Event, tick: Callable[[], Awaitable[None]], interval: float = 15
) -> None:
    while not stop.is_set():
        try:
            await tick()
        except (OSError, sqlite3.Error, RPCError, PolarsError) as error:
            logger.warning("Automatic scoring will retry (%s)", type(error).__name__)
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            continue
