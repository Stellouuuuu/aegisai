"""Run the bundled vulnerable lab in-process for `aegis scan --target demo:...`.
Needs `pip install "aegisai[demo]"` and a source checkout.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent.parent / "vulnerable-lab"
DEMO_TARGETS = {
    "demo:vulnerable-chatbot": "vulnerable",
    "demo:patched-chatbot": "patched",
}


class DemoUnavailableError(RuntimeError):
    pass


def start_demo_lab(target: str) -> tuple[str, Callable[[], None]]:
    """Start the lab on a free local port. Returns (chat_url, stop_function)."""
    if target not in DEMO_TARGETS:
        raise DemoUnavailableError(
            f"Unknown demo target {target!r}. Available: {', '.join(DEMO_TARGETS)}"
        )
    if not LAB_DIR.is_dir():
        raise DemoUnavailableError(f"Lab not found at {LAB_DIR} (source checkout required)")
    try:
        import uvicorn
    except ImportError as e:
        raise DemoUnavailableError('Demo mode needs: pip install "aegisai[demo]"') from e

    os.environ["AEGIS_LAB_MODE"] = DEMO_TARGETS[target]
    sys.path.insert(0, str(LAB_DIR))
    from chatbot.app import app

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    else:
        raise DemoUnavailableError("Demo lab did not start in time")

    def stop() -> None:
        server.should_exit = True
        thread.join(timeout=5)

    return f"http://127.0.0.1:{port}/chat", stop
