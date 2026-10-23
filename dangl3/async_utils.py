"""Compatibility for trusted V1 synchronous dependency injection."""

import asyncio
from collections.abc import Callable
import inspect
from typing import Any


async def invoke(function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Native async in production; legacy sync fixtures never block the event loop."""
    if inspect.iscoroutinefunction(function):
        return await function(*args, **kwargs)
    value = await asyncio.to_thread(function, *args, **kwargs)
    return await value if inspect.isawaitable(value) else value
