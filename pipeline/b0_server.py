"""
pipeline/b0_server.py — FastAPI server wrapping the B0 unprotected assistant.

Usage:
    uvicorn pipeline.b0_server:app --port 8000

For bulk evaluation, use baselines/b0_unprotected.py instead.
"""

import os
import sys
from pathlib import Path

import anthropic
from dotenv import load_dotenv
from fastapi import FastAPI
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))
from logging_schema import Timer, log_request

load_dotenv()

MODEL  = "claude-haiku-4-5-20251001"
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

app = FastAPI(title="B0 — Unprotected Baseline")

_LAYERS_OFF  = {"input_scanner": False, "policy_engine": False, "tool_sandbox": False, "output_guard": False}
_RESULTS_OFF = {"input_scanner": None,  "policy_engine": None,  "tool_sandbox": None,  "output_guard": None}


class PromptRequest(BaseModel):
    text: str
    request_id: str = ""
    dataset_source: str = "interactive"
    ground_truth_label: str = "unknown"


class PromptResponse(BaseModel):
    response: str
    latency_ms: float


@app.post("/query", response_model=PromptResponse)
def query(req: PromptRequest):
    with Timer() as t:
        message = client.messages.create(
            model=MODEL,
            max_tokens=512,
            messages=[{"role": "user", "content": req.text}],
        )
    response = message.content[0].text
    log_request(
        input_text=req.text,
        layers_enabled=_LAYERS_OFF,
        layer_results=_RESULTS_OFF,
        final_decision="pass",
        latency_ms={"total": t.ms},
        dataset_source=req.dataset_source,
        ground_truth_label=req.ground_truth_label,
        request_id=req.request_id or None,
    )
    return PromptResponse(response=response, latency_ms=t.ms)


@app.get("/health")
def health():
    return {"status": "ok", "model": MODEL, "security": "none"}
