"""
pipeline/sandbox_ast.py — AST-level bash command validator.

Parses the command string with bashlex and inspects the syntax tree rather
than raw string patterns. Runs after the regex pass in check_sandbox() and
catches structural attacks the regex layer misses:

  - Redirect-based reverse shells  bash -i >& /dev/tcp/...
  - Network tools absent from regex blocklist  ncat, scp, rsync, sftp
  - Privilege / persistence operations  chmod +s, crontab, useradd, sudo
  - Destructive tools not in regex list  truncate, pkill, killall
  - Python -c payloads using stdlib  shutil.rmtree, urllib, subprocess

Falls back silently if bashlex cannot parse the command (complex syntax,
here-docs, process substitution). In that case the command passes through
to any downstream check or is allowed if none is configured.

Public API:
  check_ast(command) -> (rule_violated | None, blocked_arg | None)
  Same (str | None, str | None) contract as _check_bash() in tool_sandbox.py.
"""

import re
from pathlib import Path

try:
    import bashlex
    _BASHLEX_AVAILABLE = True
except ImportError:
    _BASHLEX_AVAILABLE = False

_ALLOWED_REDIRECT_ROOT = Path("/tmp/demo")

# Exact command names that are unconditionally blocked.
# AST gives us the parsed command name as a string, so this is an exact
# set lookup — no word-boundary ambiguity, no partial-match false negatives.
_BLOCKED_COMMAND_NAMES: frozenset[str] = frozenset({
    # Network tools absent from regex external_exfiltration rule
    "ncat", "nmap", "socat", "scp", "rsync", "sftp", "ftp", "tftp",
    # Destructive tools absent from regex destructive_command rule
    "truncate", "wipefs", "wipe",
    # Process manipulation
    "pkill", "killall",
    # Privilege escalation
    "sudo", "su", "doas",
    # Persistence mechanisms
    "crontab", "at", "batch",
    # User / credential manipulation
    "useradd", "userdel", "usermod", "passwd", "chpasswd",
    # Service / firewall control
    "systemctl", "service", "iptables", "ip6tables", "ufw", "firewall-cmd",
})

# Applied only to the already-parsed payload of python3/python -c "...".
# Because we apply this to the extracted argument string (not the raw command),
# there is no quoting noise and the patterns are unambiguous.
_PYTHON_DANGEROUS_RE = re.compile(
    r"shutil\.(rmtree|move|copytree|rmdir)"
    r"|os\.(system|remove|rmdir|unlink|rename|popen)"
    r"|subprocess\.(run|call|Popen|check_output|check_call|getoutput)"
    r"|urllib\.request"
    r"|socket\.socket"
    r"|ftplib|paramiko|fabric"
    r"|__import__\s*\(",
    re.IGNORECASE,
)


def _words(parts: list) -> list:
    return [p for p in parts if getattr(p, "kind", None) == "word"]


def _redirects(parts: list) -> list:
    return [p for p in parts if getattr(p, "kind", None) == "redirect"]


def _check_command_node(node) -> tuple[str | None, str | None]:
    """Inspect one parsed command node. Return (rule, blocked_arg) or (None, None)."""
    parts = getattr(node, "parts", [])
    words = _words(parts)
    redirects = _redirects(parts)

    if not words:
        return None, None

    cmd_name = words[0].word

    # ── 1. Blocked command names ──────────────────────────────────────────
    if cmd_name in _BLOCKED_COMMAND_NAMES:
        return "ast_blocked_command", cmd_name

    # ── 2. chmod with SUID flag (+s / +S) ────────────────────────────────
    if cmd_name == "chmod":
        for w in words[1:]:
            if "+s" in w.word or "+S" in w.word:
                return "ast_suid_escalation", w.word

    # ── 3. Redirect target inspection ────────────────────────────────────
    for r in redirects:
        output = getattr(r, "output", None)
        if output is None or isinstance(output, int):
            continue
        target = getattr(output, "word", "")
        if not target:
            continue

        # Reverse shell via /dev/tcp or /dev/udp redirect
        if target.startswith("/dev/tcp/") or target.startswith("/dev/udp/"):
            return "ast_reverse_shell_redirect", target

        # Any other redirect to a path outside /tmp/demo
        if target.startswith("/") or target.startswith("~"):
            if not target.startswith(str(_ALLOWED_REDIRECT_ROOT)):
                return "ast_redirect_outside_allowed", target

    # ── 4. Python -c payload inspection ──────────────────────────────────
    if cmd_name in ("python3", "python", "python2", "python3.11", "python3.12"):
        word_strings = [w.word for w in words]
        if "-c" in word_strings:
            idx = word_strings.index("-c")
            if idx + 1 < len(word_strings):
                payload = word_strings[idx + 1]
                if _PYTHON_DANGEROUS_RE.search(payload):
                    return "ast_dangerous_python_payload", payload[:120]

    return None, None


def check_ast(command: str) -> tuple[str | None, str | None]:
    """
    Parse command with bashlex and inspect the AST for dangerous patterns.

    Returns (rule_violated, blocked_arg) or (None, None) if safe.
    Returns (None, None) silently on parse failure — the caller treats
    unparseable commands as needing further checks downstream.
    """
    if not _BASHLEX_AVAILABLE:
        return None, None

    try:
        nodes = bashlex.parse(command)
    except Exception:
        return None, None

    for node in nodes:
        rule, blocked = _check_command_node(node)
        if rule is not None:
            return rule, blocked

    return None, None
