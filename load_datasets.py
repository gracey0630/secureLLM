"""
load_datasets.py — Action 2: Load and preprocess all four datasets.

Deliverable: four clean parquet files in data/ with columns:
  text, label (0=legitimate / 1=attack), source, difficulty (where available)

Run:
    python load_datasets.py

Requires:
    pip install datasets pandas pyarrow
    HuggingFace account + granted access for LMSYS-Chat-1M
    (set HF_TOKEN env var if datasets are gated)
"""

import os
import sys
import logging
from pathlib import Path

from dotenv import load_dotenv
import pandas as pd
from datasets import load_dataset, Dataset

# Load .env file if it exists
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)

HF_TOKEN = os.getenv("HF_TOKEN")  # needed only for LMSYS gated dataset


# ── 1. HackAPrompt ───────────────────────────────────────────────────────────
def load_hackaprompt() -> pd.DataFrame:
    """
    Source: hackaprompt/hackaprompt-dataset
    Filter: correct=True (attack succeeded against target model)
    Label:  1 (all rows are attacks)
    Difficulty: mapped from 'level' column (0-9 scale)
    """
    log.info("Loading HackAPrompt...")
    ds = load_dataset("hackaprompt/hackaprompt-dataset", split="train")
    df = ds.to_pandas()

    log.info(f"  Raw rows: {len(df)}  |  columns: {list(df.columns)}")

    # Keep only successful attacks (correct=True means the injection worked)
    df = df[df["correct"] == True].copy()
    log.info(f"  After correct=True filter: {len(df)} rows")

    # Normalise to canonical schema
    text_col = "prompt" if "prompt" in df.columns else df.columns[0]
    level_col = "level" if "level" in df.columns else None

    out = pd.DataFrame({
        "text": df[text_col].astype(str),
        "label": 1,                                        # all are attacks
        "source": "hackaprompt",
        "difficulty": df[level_col].astype(int) if level_col else pd.Series([None] * len(df), dtype=object),
    })

    # Stratify: keep up to 200 per level so no level dominates
    if level_col:
        out = (
            out.groupby("difficulty", group_keys=False)
               .apply(lambda g: g.sample(min(len(g), 200), random_state=42))
               .reset_index(drop=True)
        )
        log.info(f"  After stratified cap (200/level): {len(out)} rows")

    out = out.dropna(subset=["text"]).drop_duplicates(subset=["text"])
    log.info(f"  Final HackAPrompt rows: {len(out)}")
    return out


# ── 2. Deepset Prompt Injections ─────────────────────────────────────────────
def load_deepset() -> pd.DataFrame:
    """
    Source: deepset/prompt-injections
    Label:  'label' column (1=injection, 0=legitimate)
    """
    log.info("Loading Deepset prompt-injections...")
    ds = load_dataset("deepset/prompt-injections", split="train")
    df = ds.to_pandas()
    log.info(f"  Raw rows: {len(df)}  |  columns: {list(df.columns)}")

    # Dataset has 'text' and 'label' already
    text_col = "text" if "text" in df.columns else df.columns[0]
    label_col = "label" if "label" in df.columns else None

    out = pd.DataFrame({
        "text": df[text_col].astype(str),
        "label": df[label_col].astype(int) if label_col else None,
        "source": "deepset",
        "difficulty": None,
    })

    out = out.dropna(subset=["text", "label"]).drop_duplicates(subset=["text"])
    log.info(f"  Final Deepset rows: {len(out)}  "
             f"(attacks: {(out.label==1).sum()}, legitimate: {(out.label==0).sum()})")
    return out


# ── 3. LMSYS-Chat-1M (legitimate only) ──────────────────────────────────────
def load_lmsys(n_samples: int = 750) -> pd.DataFrame:
    """
    Source: lmsys/lmsys-chat-1m  (GATED — requires HF access request)
    Filter: English, no injection keywords, sample n_samples rows
    Label:  0 (legitimate)

    If access is not yet granted, this function writes a placeholder parquet
    and logs a warning instead of crashing the whole pipeline.
    """
    log.info("Loading LMSYS-Chat-1M...")

    INJECTION_KEYWORDS = [
        "ignore previous", "disregard", "you are now", "act as",
        "###system", "----", "jailbreak", "dan mode",
    ]

    try:
        ds = load_dataset(
            "lmsys/lmsys-chat-1m",
            split="train",
            token=HF_TOKEN,
            streaming=True,          # stream so we don't download 30 GB
        )

        rows = []
        for example in ds:
            if len(rows) >= n_samples * 5:   # oversample then filter
                break
            # Keep English conversations
            if example.get("language", "English").lower() != "english":
                continue
            # Extract first user turn
            convos = example.get("conversation", [])
            user_turns = [c["content"] for c in convos if c.get("role") == "user"]
            if not user_turns:
                continue
            text = user_turns[0]
            # Drop anything that looks injection-like
            low = text.lower()
            if any(kw in low for kw in INJECTION_KEYWORDS):
                continue
            rows.append(text)

        rows = rows[:n_samples]
        log.info(f"  Collected {len(rows)} legitimate LMSYS turns")

        out = pd.DataFrame({
            "text": rows,
            "label": 0,
            "source": "lmsys",
            "difficulty": None,
        })

    except Exception as e:
        log.warning(
            f"  Could not load LMSYS-Chat-1M: {e}\n"
            "  → Writing PLACEHOLDER parquet. Request access at "
            "huggingface.co/datasets/lmsys/lmsys-chat-1m then re-run."
        )
        out = pd.DataFrame({
            "text": pd.Series([], dtype=str),
            "label": pd.Series([], dtype=int),
            "source": "lmsys",
            "difficulty": pd.Series([], dtype=object),
        })

    out = out.dropna(subset=["text"]).drop_duplicates(subset=["text"])
    log.info(f"  Final LMSYS rows: {len(out)}")
    return out


# ── 4. ai4privacy/pii-masking-200k ──────────────────────────────────────────
def load_pii_masking() -> pd.DataFrame:
    """
    Source: ai4privacy/pii-masking-200k  (no access required)
    Label:  0 (legitimate — used to test false-positive rate of output guard)
    We pull the 'source_text' (unmasked) as our input text.
    """
    log.info("Loading ai4privacy/pii-masking-200k...")
    ds = load_dataset("ai4privacy/pii-masking-200k", split="train")
    df = ds.to_pandas()
    log.info(f"  Raw rows: {len(df)}  |  columns: {list(df.columns)}")

    # Column names vary by version; try common ones
    text_col = next(
        (c for c in ["source_text", "text", "unmasked_text", df.columns[0]] if c in df.columns),
        df.columns[0],
    )

    out = pd.DataFrame({
        "text": df[text_col].astype(str),
        "label": 0,       # legitimate (contains PII but not an injection attack)
        "source": "ai4privacy",
        "difficulty": None,
    })

    # Sample down to a manageable size for evaluation
    if len(out) > 2000:
        out = out.sample(2000, random_state=42).reset_index(drop=True)
        log.info("  Sampled down to 2000 rows")

    out = out.dropna(subset=["text"]).drop_duplicates(subset=["text"])
    log.info(f"  Final ai4privacy rows: {len(out)}")
    return out


# ── Save helpers ─────────────────────────────────────────────────────────────
def save(df: pd.DataFrame, name: str) -> Path:
    path = DATA_DIR / f"{name}.parquet"
    df.to_parquet(path, index=False)
    log.info(f"  → Saved {path}  ({len(df)} rows)")
    return path


def print_summary(datasets: dict[str, pd.DataFrame]) -> None:
    print("\n" + "=" * 60)
    print("DATASET SUMMARY")
    print("=" * 60)
    for name, df in datasets.items():
        attacks = (df["label"] == 1).sum()
        legit   = (df["label"] == 0).sum()
        print(f"  {name:<25} total={len(df):>5}  attacks={attacks:>4}  legit={legit:>4}")
    total = sum(len(d) for d in datasets.values())
    print(f"  {'TOTAL':<25} {total:>5}")
    print("=" * 60 + "\n")


# ── Safe loader wrapper ──────────────────────────────────────────────────────
def _safe_load(name: str, fn, *args, **kwargs) -> pd.DataFrame:
    """Run fn(*args, **kwargs); on any exception return an empty placeholder."""
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        log.warning(
            f"  [{name}] Failed to load: {e}\n"
            f"  → Returning empty placeholder. Re-run once network/access is available."
        )
        return pd.DataFrame({
            "text": pd.Series([], dtype=str),
            "label": pd.Series([], dtype=int),
            "source": name,
            "difficulty": pd.Series([], dtype=object),
        })


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    datasets = {
        "hackaprompt":  _safe_load("hackaprompt", load_hackaprompt),
        "deepset":      _safe_load("deepset",      load_deepset),
        "lmsys":        _safe_load("lmsys",        load_lmsys, n_samples=750),
        "ai4privacy":   _safe_load("ai4privacy",   load_pii_masking),
    }

    for name, df in datasets.items():
        save(df, name)

    print_summary(datasets)
    log.info("All datasets saved to data/. Parquet files are ready for the harness.")


if __name__ == "__main__":
    main()