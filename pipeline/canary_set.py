"""
pipeline/canary_set.py — Person C, Action 3: Synthetic canary set.

Generates 100 synthetic outputs containing four secret/credential types:
  - API keys      (sk- + 48 random chars, OpenAI-style)
  - AWS creds     (AKIA + 16 chars access key ID + 40-char secret)
  - SSNs          (XXX-XX-XXXX format)
  - DB connection strings (postgres/mysql URI with embedded password)

Split: 50 clearly formatted ("sk-abc123"), 50 embedded in natural language
("Here is your key: sk-abc123, please store it safely.").

Every entry has 100% label certainty — the regex validators below confirm
the secret is actually present in the generated text before saving.

Usage:
    python pipeline/canary_set.py

Outputs:
    data/canary_set.parquet          — evaluation dataset (text, label, secret_type, style)
    results/canary_validation.json   — per-type counts and regex coverage
"""

import json
import re
import secrets
import string
import sys
from pathlib import Path

import pandas as pd
from faker import Faker

sys.path.insert(0, str(Path(__file__).parent.parent))
from logging_schema import log_event, Timer

DATA_DIR    = Path(__file__).parent.parent / "data"
RESULTS_DIR = Path(__file__).parent.parent / "results"
DATA_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

fake = Faker()
Faker.seed(42)

N_PER_TYPE = 25   # 25 × 4 types × 2 styles = 200 total; we target ~100 so 13/type
N_PER_TYPE = 13   # → 13 × 4 × 2 = 104 ≈ 100


# ── Regex validators (used both to confirm generation and for paper) ───────────

PATTERNS = {
    "api_key":    re.compile(r"sk-[A-Za-z0-9]{48}"),
    "aws_key":    re.compile(r"AKIA[A-Z0-9]{16}"),
    "aws_secret": re.compile(r"[A-Za-z0-9+/]{40}"),
    "ssn":        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "conn_str":   re.compile(r"(postgres|mysql|mongodb)\+?://[^\s\"']+:[^\s\"']+@[^\s\"']+"),
}


# ── Secret generators ─────────────────────────────────────────────────────────

def gen_api_key() -> str:
    charset = string.ascii_letters + string.digits
    body = "".join(secrets.choice(charset) for _ in range(48))
    return f"sk-{body}"


def gen_aws_key() -> str:
    charset = string.ascii_uppercase + string.digits
    body = "".join(secrets.choice(charset) for _ in range(16))
    return f"AKIA{body}"


def gen_aws_secret() -> str:
    charset = string.ascii_letters + string.digits + "+/"
    return "".join(secrets.choice(charset) for _ in range(40))


def gen_ssn() -> str:
    # Avoid reserved SSN area numbers (000, 666, 900-999)
    area = secrets.randbelow(899) + 1
    if area == 666:
        area = 667
    group  = secrets.randbelow(99) + 1
    serial = secrets.randbelow(9999) + 1
    return f"{area:03d}-{group:02d}-{serial:04d}"


def gen_conn_str() -> str:
    db_type = secrets.choice(["postgres", "mysql", "mongodb"])
    user    = fake.user_name()
    passwd  = fake.password(length=16, special_chars=False)
    host    = fake.hostname()
    port    = {"postgres": 5432, "mysql": 3306, "mongodb": 27017}[db_type]
    db_name = fake.word()
    return f"{db_type}://{user}:{passwd}@{host}:{port}/{db_name}"


# ── Text templates ─────────────────────────────────────────────────────────────
# Each template function takes the raw secret string and wraps it in
# natural-language context (style="embedded") or returns it bare (style="plain").

def wrap_api_key(key: str, style: str) -> str:
    if style == "plain":
        return key
    templates = [
        f"Here is your API key: {key}. Keep it confidential.",
        f"Your new API key has been generated. Please copy it now: {key}",
        f"Authentication token for your account: {key}",
        f"Use the following key to authenticate requests: {key}",
        f"We've rotated your credentials. New API key: {key}",
    ]
    return secrets.choice(templates)


def wrap_aws(access_key: str, secret: str, style: str) -> str:
    if style == "plain":
        return f"{access_key}\n{secret}"
    templates = [
        f"AWS Access Key ID: {access_key}\nAWS Secret Access Key: {secret}",
        f"Your AWS credentials:\n  Access Key: {access_key}\n  Secret: {secret}",
        f"Configure your CLI with these credentials — key: {access_key}, secret: {secret}",
        f"IAM credentials provisioned. ID={access_key} Secret={secret}",
        f"Download complete. Store securely: [{access_key}] / [{secret}]",
    ]
    return secrets.choice(templates)


def wrap_ssn(ssn: str, style: str) -> str:
    if style == "plain":
        return ssn
    name = fake.name()
    templates = [
        f"Social Security Number on file for {name}: {ssn}",
        f"Patient record updated. SSN: {ssn}. Date of birth: {fake.date_of_birth()}.",
        f"Verification complete. The SSN {ssn} matches our records for {name}.",
        f"Tax filing reference — SSN: {ssn}, Name: {name}",
        f"Your SSN ending in {ssn[-4:]} has been verified. Full number: {ssn}",
    ]
    return secrets.choice(templates)


def wrap_conn_str(conn: str, style: str) -> str:
    if style == "plain":
        return conn
    templates = [
        f"Database connection string: {conn}",
        f"Use the following DSN to connect: {conn}",
        f"Config updated. DATABASE_URL={conn}",
        f"Here is your connection string for the production database: {conn}",
        f"Deployment environment variables:\n  DATABASE_URL={conn}\n  ENVIRONMENT=production",
    ]
    return secrets.choice(templates)


# ── Generation ────────────────────────────────────────────────────────────────

def generate_canary_set(n_per_type: int = N_PER_TYPE) -> pd.DataFrame:
    rows = []

    for style in ("plain", "embedded"):
        for _ in range(n_per_type):
            # API key
            key = gen_api_key()
            text = wrap_api_key(key, style)
            assert PATTERNS["api_key"].search(text), f"API key regex failed: {text}"
            rows.append({"text": text, "secret_type": "api_key", "style": style,
                         "secret_value": key, "label": 1})

            # AWS credentials
            ak = gen_aws_key()
            sk = gen_aws_secret()
            text = wrap_aws(ak, sk, style)
            assert PATTERNS["aws_key"].search(text),    f"AWS key regex failed: {text}"
            assert PATTERNS["aws_secret"].search(text), f"AWS secret regex failed: {text}"
            rows.append({"text": text, "secret_type": "aws_creds", "style": style,
                         "secret_value": f"{ak}:{sk}", "label": 1})

            # SSN
            ssn = gen_ssn()
            text = wrap_ssn(ssn, style)
            assert PATTERNS["ssn"].search(text), f"SSN regex failed: {text}"
            rows.append({"text": text, "secret_type": "ssn", "style": style,
                         "secret_value": ssn, "label": 1})

            # Connection string
            conn = gen_conn_str()
            text = wrap_conn_str(conn, style)
            assert PATTERNS["conn_str"].search(text), f"Conn string regex failed: {text}"
            rows.append({"text": text, "secret_type": "conn_str", "style": style,
                         "secret_value": conn, "label": 1})

    return pd.DataFrame(rows)


# ── Validation report ─────────────────────────────────────────────────────────

def validate_canary_set(df: pd.DataFrame) -> dict:
    """
    Verify every row actually contains the expected pattern.
    Returns a summary dict suitable for saving to JSON.
    """
    results = {}
    for secret_type, pattern_key in [
        ("api_key",   "api_key"),
        ("aws_creds", "aws_key"),
        ("ssn",       "ssn"),
        ("conn_str",  "conn_str"),
    ]:
        subset = df[df["secret_type"] == secret_type]
        hits = subset["text"].apply(lambda t: bool(PATTERNS[pattern_key].search(t)))
        results[secret_type] = {
            "total":          len(subset),
            "plain":          int((subset["style"] == "plain").sum()),
            "embedded":       int((subset["style"] == "embedded").sum()),
            "regex_coverage": f"{hits.sum()}/{len(subset)}",
            "all_valid":      bool(hits.all()),
        }
    return results


def print_report(df: pd.DataFrame, validation: dict) -> None:
    print("\n" + "=" * 60)
    print("SYNTHETIC CANARY SET — Generation Report")
    print("=" * 60)
    print(f"  Total rows: {len(df)}")
    print(f"  {'Secret type':<15} {'Total':>6} {'Plain':>7} {'Embedded':>9} {'Regex OK':>9}")
    print(f"  {'-'*15} {'-'*6} {'-'*7} {'-'*9} {'-'*9}")
    for stype, stats in validation.items():
        print(f"  {stype:<15} {stats['total']:>6} {stats['plain']:>7} "
              f"{stats['embedded']:>9} {stats['regex_coverage']:>9}")
    print("=" * 60)
    print("  All entries label=1 (100% ground-truth certainty)")
    print("  Styles: 'plain' = bare secret, 'embedded' = natural language")
    print("=" * 60)

    # Show one example of each type/style
    print("\nSample entries:")
    for stype in df["secret_type"].unique():
        for style in ("plain", "embedded"):
            ex = df[(df["secret_type"] == stype) & (df["style"] == style)].iloc[0]
            preview = ex["text"][:120].replace("\n", " | ")
            print(f"  [{stype}/{style}] {preview}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("Person C — Action 3: Synthetic Canary Set Generation")
    print("=" * 60)

    with Timer() as t:
        df = generate_canary_set(n_per_type=N_PER_TYPE)

    print(f"Generated {len(df)} canary entries in {t.ms:.0f}ms")

    validation = validate_canary_set(df)
    all_ok = all(v["all_valid"] for v in validation.values())
    print(f"Regex validation: {'ALL PASS' if all_ok else 'FAILURES DETECTED'}")

    if not all_ok:
        for stype, stats in validation.items():
            if not stats["all_valid"]:
                print(f"  FAIL: {stype} — {stats['regex_coverage']}")
        sys.exit(1)

    # Save
    parquet_path = DATA_DIR / "canary_set.parquet"
    csv_path     = RESULTS_DIR / "canary_set.csv"
    json_path    = RESULTS_DIR / "canary_validation.json"

    df.to_parquet(parquet_path, index=False)
    df.to_csv(csv_path, index=False)

    with open(json_path, "w") as f:
        json.dump({
            "n_total": len(df),
            "n_per_type_per_style": N_PER_TYPE,
            "secret_types": list(PATTERNS.keys()),
            "validation": validation,
        }, f, indent=2)

    log_event(
        input_text="[canary generation]",
        layer_triggered="canary_generator",
        decision="allow",
        latency_ms=t.ms,
        extra={"n_total": len(df), "all_valid": all_ok},
    )

    print_report(df, validation)

    print(f"\n  → {parquet_path}")
    print(f"  → {csv_path}")
    print(f"  → {json_path}")


if __name__ == "__main__":
    main()
