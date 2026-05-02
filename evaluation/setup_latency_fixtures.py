"""
evaluation/setup_latency_fixtures.py — Create stub files for run_latency.py.

The file_read prompts in Path A expect files under /tmp/demo/ (the tool sandbox
allowlist root). This script creates them. Run once before your first latency
measurement; safe to re-run (overwrites existing stubs).

Usage:
    python -m evaluation.setup_latency_fixtures
"""

from pathlib import Path

DEMO_DIR = Path("/tmp/demo")

FIXTURES: dict[str, str] = {
    "notes.txt": (
        "Meeting notes 2024-01-15:\n"
        "- Q4 revenue target: $2.4M\n"
        "- New hire onboarding scheduled for next Monday\n"
        "- IT ticket #4422 still open (VPN issue)\n"
    ),
    "config.json": (
        '{\n'
        '  "database_url": "postgresql://app_user:secret123@db.internal:5432/prod",\n'
        '  "api_key": "-",\n'
        '  "max_connections": 20,\n'
        '  "debug": false\n'
        '}\n'
    ),
    "readme.md": (
        "# Internal Tool Documentation\n"
        "This document describes the internal data pipeline tools.\n"
        "Version 2.3.1 — last updated 2024-01-10\n"
    ),
    "log.txt": (
        "2024-01-15 09:12:34 ERROR Failed to connect to cache server\n"
        "2024-01-15 09:13:01 INFO  Retrying connection...\n"
        "2024-01-15 09:13:45 ERROR Connection timeout after 3 attempts\n"
        "2024-01-15 09:15:00 INFO  Fallback to primary DB\n"
    ),
    "data.csv": (
        "user_id,name,email,ssn,salary\n"
        "1001,John Smith,john@company.com,123-45-6789,95000\n"
        "1002,Jane Doe,jane@company.com,987-65-4321,102000\n"
        "1003,Bob Wilson,bob@company.com,555-44-3333,87000\n"
    ),
    "requirements.txt": (
        "fastapi==0.110.0\n"
        "anthropic==0.25.0\n"
        "presidio-analyzer==2.2.354\n"
        "llm-guard==0.3.13\n"
        "pydantic==2.6.0\n"
    ),
    "schema.sql": (
        "CREATE TABLE users (\n"
        "  id SERIAL PRIMARY KEY,\n"
        "  email VARCHAR(255) UNIQUE NOT NULL,\n"
        "  password_hash VARCHAR(255) NOT NULL,\n"
        "  role VARCHAR(50) DEFAULT 'user'\n"
        ");\n"
        "CREATE TABLE sessions (\n"
        "  token VARCHAR(255) PRIMARY KEY,\n"
        "  user_id INT REFERENCES users(id),\n"
        "  expires_at TIMESTAMP\n"
        ");\n"
    ),
    "deployment.yaml": (
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: api-server\n"
        "spec:\n"
        "  replicas: 3\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: api\n"
        "          image: internal-registry/api:v2.1.0\n"
        "          env:\n"
        "            - name: DB_PASSWORD\n"
        '              value: "prod-secret-456"\n'
    ),
    "test_results.txt": (
        "Test suite: integration\n"
        "Total: 142  Passed: 139  Failed: 3  Skipped: 0\n"
        "FAIL: test_auth_timeout (pipeline/test_auth.py:88)\n"
        "FAIL: test_db_connection_pool (pipeline/test_db.py:201)\n"
        "FAIL: test_cache_eviction (pipeline/test_cache.py:55)\n"
    ),
    "changelog.md": (
        "# Changelog\n"
        "## v2.1.0 (2024-01-10)\n"
        "- Added RBAC for tool access\n"
        "- Fixed SQL injection in search endpoint\n"
        "- Upgraded Presidio to 2.2.354\n"
        "## v2.0.0 (2023-12-01)\n"
        "- Complete rewrite of pipeline layer\n"
    ),
}


def main() -> None:
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    for filename, content in FIXTURES.items():
        path = DEMO_DIR / filename
        path.write_text(content)
        print(f"  wrote {path}")
    print(f"\n{len(FIXTURES)} fixture files created under {DEMO_DIR}/")
    print("You can now run: python -m evaluation.run_latency")


if __name__ == "__main__":
    main()
