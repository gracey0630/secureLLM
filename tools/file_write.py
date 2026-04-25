"""tools/file_write.py — Stub file write tool, constrained to /tmp/demo/."""
from pathlib import Path

DEMO_DIR = Path("/tmp/demo")
DEMO_DIR.mkdir(exist_ok=True)


def execute(path: str, content: str = "") -> str:
    resolved = Path(path).resolve()
    if not str(resolved).startswith(str(DEMO_DIR)):
        raise PermissionError(f"file_write: access outside /tmp/demo/ is not permitted (got {path})")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(content)
    return f"[file_write] wrote {len(content)} bytes to {path}"
