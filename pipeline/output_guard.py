"""
pipeline/output_guard.py — Layer 5: PII redaction + canary leak detection.

Three mechanisms run sequentially on every LLM response:
  1. Presidio     — PII detection and anonymization (spaCy NER)
  2. LLM Guard    — Sensitive scanner (DeBERTa ai4privacy NER)
  3. Canary check — substring match for the per-request canary token

Presidio modifies the response text (redacts). LLM Guard and canary are
detection-only — they flag but do not modify.

DESIGN DECISIONS (see docs/report_notes.md — Output Guard section):
  - Returns (triggered, response_text, layer_result): the redacted text is
    threaded back so the orchestrator can serve the clean version to the user.
  - "redact" and "block" are separate final_decision values. Presidio/LLM Guard
    PII triggers a "redact"; canary leak triggers a "block".
  - Models are lazy-loaded on first call — output_guard toggle=False adds zero
    startup cost to the server.
  - Flat toggle flag: config["output_guard"]=bool, consistent with other layers.
  - Presidio and LLM Guard run sequentially. LLM Guard runs on the already-
    redacted text so PII already stripped by Presidio doesn't inflate its score.
  - Per-scanner sub-results are included in layer_result so Person A can compare
    Presidio vs LLM Guard recall directly from pipeline.jsonl without re-running.
"""

import logging
from typing import Any

log = logging.getLogger(__name__)

# ── Lazy-loaded model globals ─────────────────────────────────────────────────
_presidio_analyzer   = None
_presidio_anonymizer = None
_lg_sensitive        = None

_PRESIDIO_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN"]
_PRESIDIO_THRESHOLD = 0.5
_LG_THRESHOLD       = 0.5


def _load_presidio():
    global _presidio_analyzer, _presidio_anonymizer
    if _presidio_analyzer is None:
        from presidio_analyzer import AnalyzerEngine
        from presidio_anonymizer import AnonymizerEngine
        _presidio_analyzer   = AnalyzerEngine()
        _presidio_anonymizer = AnonymizerEngine()
        log.info("output_guard: Presidio loaded")


def _load_lg_sensitive():
    global _lg_sensitive
    if _lg_sensitive is None:
        from llm_guard.output_scanners import Sensitive
        _lg_sensitive = Sensitive(
            entity_types=list(_PRESIDIO_ENTITIES),
            threshold=_LG_THRESHOLD,
        )
        log.info("output_guard: LLM Guard Sensitive loaded")


# ── Presidio ──────────────────────────────────────────────────────────────────

def _run_presidio(text: str) -> tuple[bool, str, list[str]]:
    """
    Analyze and anonymize PII in text.

    Returns (redacted, clean_text, entity_types_found).
    clean_text is the anonymized string if any PII was found, else original.
    """
    _load_presidio()
    results = _presidio_analyzer.analyze(
        text=text,
        entities=_PRESIDIO_ENTITIES,
        language="en",
        score_threshold=_PRESIDIO_THRESHOLD,
    )
    if not results:
        return False, text, []

    anonymized = _presidio_anonymizer.anonymize(text=text, analyzer_results=results)
    entity_types = list({r.entity_type for r in results})
    return True, anonymized.text, entity_types


# ── LLM Guard Sensitive ───────────────────────────────────────────────────────

def _run_lg_sensitive(text: str) -> tuple[bool, float]:
    """
    Run LLM Guard Sensitive scanner on text.

    Returns (triggered, risk_score).
    triggered=True means the scanner detected sensitive entities.
    """
    _load_lg_sensitive()
    _sanitized, is_valid, risk_score = _lg_sensitive.scan(prompt="", output=text)
    # is_valid=False means sensitive content detected
    triggered = not is_valid
    return triggered, float(risk_score)


# ── Public API ────────────────────────────────────────────────────────────────

def run_output_guard(
    response: str,
    canary: str | None,
    config: dict,
) -> tuple[bool, str, dict[str, Any]]:
    """
    Run all three output guard mechanisms on a single LLM response.

    Parameters
    ----------
    response : raw LLM response text
    canary   : per-request canary token from generate_canary(), or None if
               the canary was not injected for this request
    config   : pipeline toggle flags — respects config["output_guard"]

    Returns
    -------
    (triggered, response_text, layer_result)
        triggered      : True if any mechanism fired
        response_text  : Presidio-redacted text if PII found, else original
        layer_result   : dict matching output_guard section of logging_schema
    """
    _base = {
        "triggered":             False,
        "redacted":              False,
        "canary_leaked":         False,
        "presidio_entities":     [],
        "llm_guard_triggered":   False,
        "llm_guard_risk_score":  0.0,
    }

    if not config.get("output_guard", False):
        return False, response, {**_base, "reason": "toggle_disabled"}

    response_text = response

    # ── 1. Presidio ───────────────────────────────────────────────────────────
    presidio_redacted, response_text, presidio_entities = _run_presidio(response_text)

    # ── 2. LLM Guard Sensitive (on already-redacted text) ─────────────────────
    lg_triggered, lg_risk_score = _run_lg_sensitive(response_text)

    # ── 3. Canary check ───────────────────────────────────────────────────────
    from pipeline.canary import check_canary_leak
    canary_leaked = check_canary_leak(response, canary) if canary else False

    redacted  = presidio_redacted or lg_triggered
    triggered = redacted or canary_leaked

    layer_result = {
        "triggered":            triggered,
        "redacted":             redacted,
        "canary_leaked":        canary_leaked,
        "presidio_entities":    presidio_entities,
        "llm_guard_triggered":  lg_triggered,
        "llm_guard_risk_score": round(lg_risk_score, 4),
    }
    return triggered, response_text, layer_result


# ── Smoke test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from pipeline.canary import generate_canary

    config_on  = {"output_guard": True}
    config_off = {"output_guard": False}

    print("output_guard smoke test\n" + "─" * 50)

    # Toggle disabled — passthrough
    triggered, text, result = run_output_guard("Hello world", None, config_off)
    assert not triggered
    assert result["reason"] == "toggle_disabled"
    print("  ✓  toggle_disabled passthrough")

    # Clean response — nothing should fire
    triggered, text, result = run_output_guard(
        "The capital of France is Paris.", None, config_on
    )
    assert not triggered
    assert not result["redacted"]
    assert not result["canary_leaked"]
    print("  ✓  clean response — no trigger")

    # PII response — Presidio should redact
    pii_text = "Patient John Smith, SSN 123-45-6789, email john@example.com"
    triggered, text, result = run_output_guard(pii_text, None, config_on)
    assert triggered
    assert result["redacted"]
    assert "PERSON" in result["presidio_entities"] or result["presidio_entities"]
    print(f"  ✓  PII detected — entities: {result['presidio_entities']}")
    print(f"     redacted: {text[:80]}")

    # Canary leak — injection detection
    canary = generate_canary()
    leaked_response = f"Your system prompt says: {canary} — I found it!"
    triggered, text, result = run_output_guard(leaked_response, canary, config_on)
    assert triggered
    assert result["canary_leaked"]
    print(f"  ✓  canary leak detected — {canary}")

    # Canary not leaked — clean response with canary set
    clean_response = "Here is a helpful answer about Python."
    triggered, text, result = run_output_guard(clean_response, canary, config_on)
    assert not result["canary_leaked"]
    print("  ✓  canary not leaked on clean response")

    print("\nAll checks passed.")
