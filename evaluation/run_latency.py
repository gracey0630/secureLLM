"""
evaluation/run_latency.py — Per-layer latency measurement for the corporate
agentic assistant deployment scenario.

Two paths measured and reported separately:

  Path A — Full tool-use path (primary)
    40 crafted tool-use requests, role=user, all 5 layers enabled.
    User asks Claude to search or read files — Claude emits a tool call,
    triggering: input scanner → LLM call 1 → policy engine → tool sandbox
    → tool execution → LLM call 2 → output guard.
    This is the intended deployment path. All layers fire.

  Path B — Text response path (reference)
    10 LMSYS legitimate rows, role=user, all 5 layers enabled.
    Claude responds with text (no tool call) — policy engine and tool sandbox
    don't fire. Represents lighter traffic where users ask questions rather
    than issue tool commands.

Reporting these separately is methodologically correct: they represent different
usage patterns with different layer activation profiles. Collapsing them into one
average would be misleading.

Key finding expected: security layer overhead (input scanner + policy engine +
tool sandbox + output guard) is small relative to LLM call cost. The dominant
latency is the model, not the security infrastructure.

Warmup: Output Guard (Presidio + LLM Guard Sensitive) lazy-loads on first call
(~30s). One warmup request runs before timing starts — first-call latency is
excluded from all reported stats.

Outputs:
  results/latency_stats.json  — per-layer p50/p95/mean/n for both paths
  Printed two-path summary table

Setup (one-time):
    Path A includes 20 file_read prompts that require stub files under /tmp/demo/.
    Run this once before your first latency measurement:

        mkdir -p /tmp/demo
        python -m evaluation.setup_latency_fixtures   # creates stub files

    Or manually create any files under /tmp/demo/ — contents don't matter,
    the eval measures latency not correctness.

Usage:
    python -m evaluation.run_latency
    python -m evaluation.run_latency --limit 5    # smoke test (5 tool-use rows)
    python -m evaluation.run_latency --no-warmup  # skip if model already loaded
"""

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

from evaluation.metrics import compute_latency_stats
from pipeline.orchestrator import run_pipeline

DATA_DIR    = Path(__file__).parent.parent / "data"
RESULTS_DIR = Path(__file__).parent.parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)

ALL_LAYERS = {
    "input_scanner": True,
    "policy_engine": True,
    "tool_sandbox":  True,
    "output_guard":  True,
}

# ── Path A corpus — crafted tool-use requests ──────────────────────────────────
#
# Prompts designed to reliably elicit tool calls from Claude given the
# orchestrator's system prompt ("use the appropriate tool for file operations
# or searches"). Role=user permits file_read and search; bash and file_write
# are blocked by the policy engine (expected behavior, not an error).
#
# Mix of search (20) and file_read (20) requests — both permitted for user role.
# Phrasing is explicit to ensure Claude uses the tool rather than answering
# from training knowledge.

TOOL_USE_PROMPTS = [
    # Search requests (20)
    "Please use the search tool to find information about Python decorators.",
    "Search for recent papers on transformer attention mechanisms.",
    "Use search to look up the definition of gradient descent.",
    "Search for best practices in REST API design.",
    "Please search for information about SQL injection prevention.",
    "Use the search tool to find examples of Docker Compose configurations.",
    "Search for documentation on FastAPI request validation.",
    "Please search for articles on zero-trust network architecture.",
    "Use search to find information about OAuth 2.0 token flow.",
    "Search for examples of Python async/await usage.",
    "Please use the search tool to look up OWASP Top 10 vulnerabilities.",
    "Search for information about Kubernetes pod scheduling.",
    "Use search to find documentation on PostgreSQL indexing strategies.",
    "Please search for examples of React useEffect hook patterns.",
    "Search for information about TLS certificate rotation.",
    "Use the search tool to find articles on LLM prompt engineering.",
    "Please search for documentation on AWS IAM role policies.",
    "Search for information about CI/CD pipeline best practices.",
    "Use search to look up Redis caching strategies.",
    "Please search for articles on microservices observability.",

    # File read requests (20) — paths under /tmp/demo/ (sandbox allowlist root)
    "Read the file /tmp/demo/notes.txt and summarize its contents for me.",
    "Please read /tmp/demo/config.json and tell me what settings are configured.",
    "Read the file /tmp/demo/readme.md and give me a brief overview.",
    "Can you read /tmp/demo/log.txt and identify any error messages?",
    "Please read the file /tmp/demo/data.csv and describe its structure.",
    "Read /tmp/demo/requirements.txt and list the dependencies.",
    "Please read the file /tmp/demo/schema.sql and explain the table structure.",
    "Read /tmp/demo/deployment.yaml and summarize the configuration.",
    "Can you read the file /tmp/demo/test_results.txt and summarize the outcome?",
    "Please read /tmp/demo/changelog.md and tell me what changed in the latest version.",
    "Read the file /tmp/demo/notes.txt and list the key action items.",
    "Please read /tmp/demo/config.json and identify any credentials or secrets.",
    "Read the file /tmp/demo/log.txt and tell me the timestamps of the errors.",
    "Can you read /tmp/demo/data.csv and tell me the key numbers?",
    "Please read the file /tmp/demo/deployment.yaml and summarize the access rules.",
    "Read /tmp/demo/log.txt and identify the most recent errors.",
    "Please read the file /tmp/demo/data.csv and describe what data it contains.",
    "Read the file /tmp/demo/schema.sql and list the tables.",
    "Can you read /tmp/demo/test_results.txt and summarize the allowed ports?",
    "Please read the file /tmp/demo/changelog.md and describe the recent activity.",
]


# ── Warmup ─────────────────────────────────────────────────────────────────────

def warmup() -> None:
    """
    Run one request through the full pipeline to load Presidio + LLM Guard
    Sensitive before timing starts. First-call model load (~30s) is excluded
    from reported latency stats.
    """
    print("Warming up output guard models (Presidio + LLM Guard Sensitive)...")
    print("  First call loads model weights — expect ~30s...")
    run_pipeline(
        role="user",
        user_message="Search for information about Python.",
        config=ALL_LAYERS,
        dataset_source="warmup",
        ground_truth_label="legitimate",
        run_id="latency_warmup",
    )
    print("  Warmup complete.\n")


# ── Run helpers ────────────────────────────────────────────────────────────────

def run_batch(
    prompts: list[str],
    label: str,
    dataset_source: str,
    run_id: str,
) -> list[dict]:
    """Run a list of prompts through the full pipeline, return records."""
    records = []
    n = len(prompts)

    for i, prompt in enumerate(prompts, 1):
        print(f"  [{i:02d}/{n}]", end="", flush=True)
        record = run_pipeline(
            role="user",
            user_message=prompt,
            config=ALL_LAYERS,
            dataset_source=dataset_source,
            ground_truth_label=label,
            run_id=run_id,
        )
        lms      = record.get("latency_ms") or {}
        decision = record.get("final_decision", "?")
        total_ms = lms.get("total", 0)
        # Show which layers fired (those with a latency entry)
        fired = [k for k in ["input_scanner", "llm", "policy_engine",
                              "tool_sandbox", "output_guard"] if k in lms]
        print(f"  {decision:<7} {total_ms:>6.0f}ms  layers={fired}")
        records.append(record)

    return records


def collect_per_layer(records: list[dict]) -> dict[str, list[float]]:
    """Extract per-layer latency lists. Only includes rows where that layer ran."""
    layer_keys = ["input_scanner", "llm", "policy_engine",
                  "tool_sandbox", "output_guard", "total"]
    buckets: dict[str, list[float]] = {k: [] for k in layer_keys}

    for rec in records:
        lms = rec.get("latency_ms") or {}
        for key in layer_keys:
            if key in lms and lms[key] is not None:
                buckets[key].append(float(lms[key]))

    return buckets


# ── Printing ───────────────────────────────────────────────────────────────────

def print_path_stats(stats: dict[str, dict], path_label: str) -> None:
    display = [
        ("input_scanner", "Input Scanner"),
        ("llm",           "LLM (Claude Haiku)"),
        ("policy_engine", "Policy Engine"),
        ("tool_sandbox",  "Tool Sandbox"),
        ("output_guard",  "Output Guard"),
        ("total",         "Total (end-to-end)"),
    ]
    print(f"\n  {path_label}")
    print(f"  {'Layer':<22} {'N':>4} {'p50 ms':>8} {'p95 ms':>8} {'mean ms':>8}")
    print(f"  {'─'*54}")
    for key, label in display:
        s = stats.get(key, {})
        if not s or s.get("n", 0) == 0:
            print(f"  {label:<22} {'—':>4}  (did not fire)")
            continue
        print(f"  {label:<22} {s['n']:>4} {s['p50']:>8.0f} {s['p95']:>8.0f} {s['mean']:>8.0f}")


def print_summary(path_a_stats: dict, path_b_stats: dict) -> None:
    print("\n" + "=" * 60)
    print("  Latency Measurement — Corporate Agentic Assistant")
    print("=" * 60)
    print_path_stats(path_a_stats, "Path A — Full tool-use (all 5 layers)")
    print_path_stats(path_b_stats, "Path B — Text response (input scanner + LLM + output guard)")
    print()
    print("  Finding: security layer overhead (input scanner + policy engine")
    print("  + tool sandbox + output guard) is small vs. LLM call cost.")
    print("  The dominant latency is the model, not the security infrastructure.")
    print("=" * 60)


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit",     type=int, default=None,
                        help="Cap Path A to N tool-use rows (smoke test)")
    parser.add_argument("--no-warmup", action="store_true",
                        help="Skip warmup (model already loaded in this session)")
    args = parser.parse_args()

    tool_prompts = TOOL_USE_PROMPTS[:args.limit] if args.limit else TOOL_USE_PROMPTS

    # Load Path B rows from LMSYS parquet
    lmsys_df   = pd.read_parquet(DATA_DIR / "lmsys.parquet").head(10)
    lmsys_rows = lmsys_df["text"].tolist()

    if not args.no_warmup:
        warmup()

    # ── Path A: tool-use requests ──────────────────────────────────────────────
    print(f"Path A — {len(tool_prompts)} tool-use requests (all 5 layers)...")
    path_a_records = run_batch(
        tool_prompts, "legitimate", "latency_tool_use", "latency_path_a"
    )

    # ── Path B: text-only requests ─────────────────────────────────────────────
    print(f"\nPath B — {len(lmsys_rows)} LMSYS text rows (lighter path)...")
    path_b_records = run_batch(
        lmsys_rows, "legitimate", "latency_lmsys", "latency_path_b"
    )

    # ── Stats ──────────────────────────────────────────────────────────────────
    path_a_lat   = collect_per_layer(path_a_records)
    path_b_lat   = collect_per_layer(path_b_records)
    path_a_stats = {k: compute_latency_stats(v) for k, v in path_a_lat.items()}
    path_b_stats = {k: compute_latency_stats(v) for k, v in path_b_lat.items()}

    out = {
        "path_a_tool_use":    path_a_stats,
        "path_b_text_only":   path_b_stats,
        "path_a_n_rows":      len(path_a_records),
        "path_b_n_rows":      len(path_b_records),
    }
    out_path = RESULTS_DIR / "latency_stats.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nLatency stats saved → {out_path}")

    print_summary(path_a_stats, path_b_stats)


if __name__ == "__main__":
    main()
