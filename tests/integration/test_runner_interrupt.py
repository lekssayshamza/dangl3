"""A real SIGINT exercises the runner's asyncio cancellation/cleanup path."""

import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time


def test_actual_ctrl_c_returns_130_after_local_servers_close():
    # Only the harness is held at an event barrier. DNS, transport, scanner,
    # cancellation and runner.main are unchanged. The child uses local fixtures.
    code = '''
import asyncio
from integration_lab import runner

class HeldLab(runner.LocalLab):
    def __init__(self):
        super().__init__(3, hold_responses=True)
    async def scan(self):
        task = asyncio.create_task(super().scan())
        try:
            await self.gate.ready.wait()
            print("READY", flush=True)
            return await task
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
    async def __aexit__(self, *args):
        try:
            return await super().__aexit__(*args)
        finally:
            print("CLEANUP", self.cleanup_ok(), flush=True)

runner.LocalLab = HeldLab
raise SystemExit(runner.main())
'''
    process = subprocess.Popen([sys.executable, "-u", "-c", code],
                               cwd=Path(__file__).resolve().parents[2],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    prefix = bytearray()
    deadline = time.monotonic() + 10
    try:
        while b"READY\n" not in prefix:
            remaining = deadline - time.monotonic()
            assert remaining > 0, f"child did not reach request barrier: {prefix!r}"
            readable, _, _ = select.select([process.stdout], [], [], remaining)
            assert readable, f"child did not become ready: {prefix!r}"
            data = os.read(process.stdout.fileno(), 4096)
            assert data, f"child exited before request barrier: {prefix!r}"
            prefix.extend(data)
        process.send_signal(signal.SIGINT)
        output, errors = process.communicate(timeout=10)
        assert process.returncode == 130, (prefix + output, errors)
        assert b"CLEANUP True" in prefix + output
        assert b"cancelled" in errors
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
