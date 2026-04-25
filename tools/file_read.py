"""tools/file_read.py — Stub file read tool, constrained to /tmp/demo/."""
from pathlib import Path

DEMO_DIR = Path("/tmp/demo")
DEMO_DIR.mkdir(exist_ok=True)


def execute(path: str) -> str:
    resolved = Path(path).resolve()
    if not str(resolved).startswith(str(DEMO_DIR)):
        raise PermissionError(f"file_read: access outside /tmp/demo/ is not permitted (got {path})")
    if not resolved.exists():
        return f"[file_read] file not found: {path}"
    return resolved.read_text()
