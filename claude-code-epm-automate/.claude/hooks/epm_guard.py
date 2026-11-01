"""
PreToolUse guard for EPM Automate in Claude Code.

Claude Code runs this before every Bash, PowerShell, or Monitor call, and before any MCP tool call that
carries a command, such as a terminal tool (see ../settings.json). It reads the call as JSON on stdin and
decides:

    deny    the EPM Automate command is not on the policy, or the call is shaped so it cannot be checked
    ask     the command changes something in EPM, so a person approves it in the permission prompt
    (none)  the command is on the allow list, or has nothing to do with EPM Automate; the normal
            permission rules in settings.json still apply

It fails closed. A missing policy, an unreadable call, or any error inside this script denies the call
whenever the call mentions EPM Automate or a .epw file.

Every decision about an EPM Automate call is appended to an audit log as one JSON line. Anything that
could be a secret is redacted before it is written: a denied call keeps only its command name, and a call
the guard could not parse is logged as [unparsed].

The policy lives next to this script in epm_policy.json:

    program        optional: the full path EPM Automate is run by. Without it, only the bare name works
    login          the one user, password file, and environments the agent may log in with
    allow          commands that only read
    ask            commands that run or change something
    audit_log      path of the audit log, relative to the project folder

Any command in neither list is denied. Requires Python 3.9+, standard library only.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY_FILE = HERE / "epm_policy.json"

PROGRAM_NAMES = {"epmautomate"}
PROGRAM_SUFFIXES = (".bat", ".cmd", ".sh", ".exe")
# A call that mentions EPM Automate may use only these characters. Bash, PowerShell, and cmd.exe each
# read quotes, escapes, and operators differently, so instead of listing what is dangerous, this allows
# only what an EPM Automate command needs: no & | ; < > ( ) $ ` \ % ^ @ or non ASCII characters at all.
# The cost: substitution variables such as &CurYr must be resolved first, with getSubstVar.
SAFE = re.compile(r"""[A-Za-z0-9 _.,:/=+{}#"'-]*""")
SECRET_ARGS = re.compile(r"^(ProxyServerPassword|KeystorePassword|userPassword|key)=", re.IGNORECASE)
# Commands that take a password or auth token as a plain positional argument, and its position.
POSITIONAL_SECRETS = {"copytoobjectstorage": 4, "copyfromobjectstorage": 4}


def decide(decision: str, reason: str) -> None:
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                             "permissionDecision": decision,
                                             "permissionDecisionReason": reason}}))


def mentions_epm(command: str) -> bool:
    low = command.lower()
    return "epmautomate" in low or ".epw" in low


def same_path(a: str, b: str) -> bool:
    """Paths match exactly, ignoring case only on Windows, where the file system ignores it too."""
    if ".." in a.split("/"):
        return False
    norm = lambda p: p.rstrip("/").lower() if os.name == "nt" else p.rstrip("/")
    return norm(a) == norm(b)


def program_name(token: str) -> str:
    name = re.split(r"[\\/]", token.strip("\"'"))[-1].lower()
    for suffix in PROGRAM_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def is_program(token: str, policy: dict) -> bool:
    """EPM Automate by its bare name, found on PATH, or by the exact path in the policy. Any other path
    could be a script the agent wrote and named epmautomate."""
    t = token.strip("\"'").replace("\\", "/")
    configured = str(policy.get("program", "")).replace("\\", "/")
    if configured and same_path(t, configured):
        return True
    return "/" not in t and program_name(t) in PROGRAM_NAMES


def redact(tokens: list[str], decision: str) -> list[str]:
    if decision == "deny":  # a refused call can have any shape, so nothing after the command name is kept
        return tokens[:2] + (["[redacted]"] if len(tokens) > 2 else [])
    out = list(tokens)
    low = [t.lower() for t in tokens]
    secret_at = POSITIONAL_SECRETS.get(low[1] if len(low) > 1 else "")
    if secret_at and len(out) > secret_at:
        out[secret_at] = "[redacted]"
    if "encrypt" in low:  # everything after encrypt is a secret, a key, or a path to one
        i = low.index("encrypt")
        out[i + 1:] = ["[redacted]"] * (len(out) - i - 1)
    if len(out) > 1 and low[1] == "login":  # keep the user, the file, and the URL; anything else may be a password
        out[3:] = [t if t.lower().endswith(".epw") or t.lower().startswith("https://") else "[redacted]"
                   for t in out[3:]]
    return [t.split("=", 1)[0] + "=[redacted]" if SECRET_ARGS.match(t) else t for t in out]


def audit(policy: dict, payload: dict, decision: str, tokens: list[str] | None, reason: str) -> None:
    project = Path(os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or ".")
    log_path = project / policy.get("audit_log", ".claude/epm-audit.jsonl")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "session": payload.get("session_id", ""),
        "decision": decision,
        "command": redact(tokens, decision) if tokens else "[unparsed]",
        "reason": reason,
    }
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def check_login(tokens: list[str], login: dict) -> str | None:
    """Return a reason to deny, or None. Login must be exactly: epmautomate login USER FILE URL."""
    if len(tokens) != 5:
        return "Login must be exactly: epmautomate login USER PASSWORD_FILE URL, as set in epm_policy.json."
    _, _, user, pw_file, url = tokens
    # With an OAuth token in the file, EPM Automate ignores the user name, so the file is the identity.
    if user.lower() != str(login.get("user", "")).lower():
        return "Login is allowed only as the agent's own user in epm_policy.json."
    if not same_path(pw_file, str(login.get("password_file", ""))):
        return "Login is allowed only with the agent's own password file in epm_policy.json."
    urls = {u.lower().rstrip("/") for u in login.get("allowed_urls", [])}
    if url.lower().rstrip("/") not in urls:
        return "Login is allowed only to the environments in epm_policy.json."
    return None


def check(command: str, policy: dict) -> tuple[str, str, list[str] | None]:
    """Return (decision, reason, tokens). decision is deny, ask, or none."""
    text = command.strip()
    if text.startswith("& "):  # PowerShell call operator
        text = text[2:].lstrip()
    if not SAFE.fullmatch(text):
        return "deny", ("Run EPM Automate as one plain command, using only letters, digits, spaces, quotes, and "
                        ". , : / = + { } # _ -. No operators, variables, escapes, or parentheses."), None
    try:
        tokens = shlex.split(text, posix=False)
    except ValueError:
        return "deny", "The command could not be parsed.", None
    tokens = [t[1:-1] if len(t) > 1 and t[0] == t[-1] and t[0] in "\"'" else t for t in tokens]

    if not tokens or program_name(tokens[0]) not in PROGRAM_NAMES:
        # logged as [unparsed]: a wrapped command can carry a secret the redaction would not recognize
        return "deny", ("EPM Automate and .epw files may only appear as a direct EPM Automate call, "
                        "never inside another program, shell, or script."), None
    if not is_program(tokens[0], policy):
        return "deny", ("Run EPM Automate by its name, or by the exact path set as program in epm_policy.json. "
                        "Any other path could be a different program with the same name."), tokens
    if len(tokens) < 2:
        return "deny", "No EPM Automate command given.", tokens
    if any(t.lower() == "-p" for t in tokens):
        return "deny", "Parameter files (-p) hide the real arguments from this check and from you.", tokens

    sub = tokens[1].lower()
    allow = {c.lower() for c in policy.get("allow", [])}
    ask = {c.lower() for c in policy.get("ask", [])}

    if sub == "login":
        reason = check_login(tokens, policy.get("login", {}))
        if reason:
            return "deny", reason, tokens
    elif ".epw" in text.lower():
        return "deny", "Only the login command may name a .epw file.", tokens

    if sub in allow:
        return "none", "On the allow list.", tokens
    if sub in ask:
        return "ask", f"{tokens[1]} runs or changes something in EPM. Approve only if it is what you asked for.", tokens
    return "deny", f"{tokens[1]} is not on the EPM Automate policy for this project.", tokens


def main() -> int:
    raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")  # Claude Code sends UTF-8, whatever the console code page
    try:
        payload = json.loads(raw)
        command = payload.get("tool_input", {}).get("command", "")
        if not isinstance(command, str):
            command = json.dumps(command)
    except (ValueError, AttributeError):
        if "epmautomate" in raw.lower() or ".epw" in raw.lower():
            print("epm_guard: unreadable tool call that mentions EPM Automate, blocked.", file=sys.stderr)
            return 2
        return 0

    tool = str(payload.get("tool_name", ""))
    if not (tool in ("Bash", "PowerShell", "Monitor") or tool.startswith("mcp__")) or not mentions_epm(command):
        return 0

    try:
        policy = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        decide("deny", "epm_policy.json is missing or invalid, so every EPM Automate call is blocked.")
        return 0

    decision, reason, tokens = check(command, policy)
    audit(policy, payload, decision, tokens, reason)
    if decision != "none":
        decide(decision, reason)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # fail closed: an error in the guard must never let a call through
        print(f"epm_guard: internal error, call blocked ({type(exc).__name__}).", file=sys.stderr)
        sys.exit(2)
