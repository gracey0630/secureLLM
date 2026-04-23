"""
logging_schema.py — Two-tier logging for the SecureLLM pipeline.

Two functions, two purposes:

  log_request()   — PRIMARY eval logger. Writes one canonical JSON line per
                    request to logs/pipeline.jsonl. Schema matches claude.md exactly
                    so pd.read_json("pipeline.jsonl", lines=True) is eval-ready
                    with no joins. Call this from the pipeline orchestrator (Week 2)
                    once all layer results are collected.

  log_event()     — DEBUG logger. Writes a lightweight per-layer line to
                    logs/debug.jsonl. Call this from inside individual layers
                    (input_scanner, output_guard, etc.) during isolated development
                    before the full orchestrator exists.

Timer           — Context manager for per-layer latency. Used by both callers.
"""

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

_PIPELINE_LOG = LOG_DIR / "pipeline.jsonl"  # eval artifact — do not change path
_DEBUG_LOG    = LOG_DIR / "debug.jsonl"


def _append(path: Path, record: dict) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


# ── PRIMARY: one record per request ──────────────────────────────────────────
def log_request(
    input_text: str,
    layers_enabled: dict[str, bool],    # e.g. {"input_scanner": True, "policy_engine": False, ...}
    layer_results: dict[str, Any],      # per-layer outcome dicts; None for disabled layers
    final_decision: str,                # "pass" | "block" | "redact" | "error"
    latency_ms: dict[str, float],       # {"input_scanner": 42, ..., "total": 86}
    dataset_source: str,                # "hackaprompt" | "deepset" | "lmsys" | "ai4privacy" | "manual"
    ground_truth_label: str,            # "attack" | "legitimate"
    *,
    request_id: Optional[str] = None,
    run_id: str = "",                   # identifies the eval run — filter by this before dataset_source
                                        # e.g. "b0_baseline", "policy_eval", "ablation_full", "demo"
                                        # "" for baseline runs (backward compatible)
) -> dict:
    record = {
        "request_id":         request_id or str(uuid.uuid4()),
        "timestamp":          datetime.now(timezone.utc).isoformat(),
        "input_text":         input_text,
        "layers_enabled":     layers_enabled,
        "layer_results":      layer_results,
        "final_decision":     final_decision,
        "latency_ms":         latency_ms,
        "dataset_source":     dataset_source,
        "ground_truth_label": ground_truth_label,
        "run_id":             run_id,
    }
    _append(_PIPELINE_LOG, record)
    return record


# ── DEBUG: one record per layer event ────────────────────────────────────────
def log_event(
    layer: str,
    decision: str,
    latency_ms: float,
    *,
    request_id: Optional[str] = None,
    extra: Optional[dict[str, Any]] = None,
) -> None:
    record = {
        "request_id": request_id or str(uuid.uuid4()),
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "layer":      layer,
        "decision":   decision,
        "latency_ms": round(latency_ms, 3),
        **(extra or {}),
    }
    _append(_DEBUG_LOG, record)


# ── TIMER ─────────────────────────────────────────────────────────────────────
class Timer:
    """Measure wall-clock ms for a block. Use one Timer per layer.

        with Timer() as t:
            result = scanner.run(text)
        latency_ms["input_scanner"] = t.ms
    """
    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_):
        self.ms = round((time.perf_counter() - self._start) * 1000, 3)
