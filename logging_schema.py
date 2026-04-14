"""
logging_schema.py — Shared request/event logger for the evaluation pipeline.

Every request through any layer must call log_event().
Schema: input, layer_triggered, decision, latency_ms, timestamp
"""

import json
import time
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# ── configure root logger ────────────────────────────────────────────────────
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

_file_handler = logging.FileHandler(LOG_DIR / "pipeline.jsonl")
_file_handler.setLevel(logging.DEBUG)

_stream_handler = logging.StreamHandler()
_stream_handler.setLevel(logging.INFO)

logging.basicConfig(
    level=logging.DEBUG,
    handlers=[_file_handler, _stream_handler],
    format="%(message)s",   # raw JSON lines to file; stream gets same
)

logger = logging.getLogger("pipeline")


# ── canonical event schema ───────────────────────────────────────────────────
def log_event(
    input_text: str,
    layer_triggered: str,          # e.g. "input_scanner", "policy_engine", "output_guard", "tool_sandbox", "b0_baseline"
    decision: str,                 # "allow" | "block" | "redact" | "error"
    latency_ms: float,
    *,
    request_id: Optional[str] = None,
    confidence: Optional[float] = None,
    match_reason: Optional[str] = None,
    role: Optional[str] = None,
    extra: Optional[dict[str, Any]] = None,
) -> dict:
    """
    Emit a structured JSON log line and return the event dict.

    Parameters
    ----------
    input_text      : The raw user/system input (truncated to 500 chars in log).
    layer_triggered : Which pipeline layer produced this event.
    decision        : Outcome of the layer.
    latency_ms      : Wall-clock time for this layer in milliseconds.
    request_id      : UUID shared across all events for a single request.
    confidence      : Scorer confidence (0–1) if applicable.
    match_reason    : Human-readable reason for block/redact.
    role            : RBAC role in effect, if applicable.
    extra           : Any additional layer-specific fields.
    """
    event = {
        "request_id": request_id or str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer_triggered": layer_triggered,
        "decision": decision,
        "latency_ms": round(latency_ms, 3),
        "input_preview": input_text[:500],
        "confidence": confidence,
        "match_reason": match_reason,
        "role": role,
        **(extra or {}),
    }
    logger.debug(json.dumps(event))
    return event


# ── convenience timer context manager ───────────────────────────────────────
class Timer:
    """Usage:  with Timer() as t: ...; print(t.ms)"""
    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_):
        self.ms = (time.perf_counter() - self._start) * 1000
