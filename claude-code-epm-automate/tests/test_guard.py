"""
Offline checks for .claude/hooks/epm_guard.py.

Runs the hook the way Claude Code does: a fresh process per call, the tool call as JSON on stdin.
Uses a temporary project folder, so the real audit log is never touched. Run from this post's code
folder:  python tests/test_guard.py
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CODE = Path(__file__).resolve().parent.parent
HOOK = CODE / ".claude" / "hooks" / "epm_guard.py"
TEST_URL = "https://example-test.epm.us-phoenix-1.ocs.oraclecloud.com"
PROD_URL = "https://example.epm.us-phoenix-1.ocs.oraclecloud.com"

ok = 0
project = Path(tempfile.mkdtemp(prefix="epm_guard_test_"))
hooks_dir = project / ".claude" / "hooks"
hooks_dir.mkdir(parents=True)
shutil.copy(HOOK, hooks_dir)
shutil.copy(HOOK.parent / "epm_policy.json", hooks_dir)
audit_log = project / ".claude" / "epm-audit.jsonl"


def check(cond, msg):
    global ok
    assert cond, msg
    ok += 1
    print("PASS", msg)


def run(command, tool="Bash", raw=None, env_extra=None):
    payload = raw if raw is not None else json.dumps(
        {"session_id": "test", "cwd": str(project), "hook_event_name": "PreToolUse",
         "tool_name": tool, "tool_input": {"command": command}})
    env = dict(os.environ, CLAUDE_PROJECT_DIR=str(project), **(env_extra or {}))
    p = subprocess.run([sys.executable, str(hooks_dir / "epm_guard.py")], input=payload,
                       capture_output=True, text=True, env=env)
    decision = None
    if p.stdout.strip():
        decision = json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"]
    return p.returncode, decision, p.stderr


def decision(command, **kw):
    code, d, _ = run(command, **kw)
    assert code == 0, f"unexpected exit {code} for {command}"
    return d


# commands with nothing to do with EPM pass through untouched and are not logged
check(decision("git status") is None, "unrelated command: no decision")
check(not audit_log.exists(), "unrelated command: nothing written to the audit log")

# the allow list defers to the normal permission rules
check(decision("epmautomate listFiles") is None, "listFiles: allowed, normal rules apply")
check(decision("epmautomate.bat exportJobConsole jobs.zip nDays=1 jobStatusCodes=3,8 exportErrorDetails=true") is None,
      "exportJobConsole through epmautomate.bat: allowed")
check(decision("& epmautomate downloadFile jobs.zip", tool="PowerShell") is None,
      "PowerShell call operator: allowed")
check(decision(f"epmautomate login svc_epm_agent C:/secure/svc_epm_agent.epw {TEST_URL}") is None,
      "login as the agent, with its own file, to the test environment: allowed")
check(decision(f"epmautomate login svc_epm_agent C:/secure/svc_epm_agent.epw {TEST_URL}/") is None,
      "login URL with a trailing slash still matches")
check(decision(f"epmautomate login svc_epm_agent C:\\secure\\svc_epm_agent.epw {TEST_URL}") == "deny",
      "login with backslashes: denied, because Git Bash would read a different path")
check(decision("epmautomate login svc_epm_agent C:/secure/svc_epm_agent.epw $EPM_URL",
               env_extra={"EPM_URL": TEST_URL}) == "deny", "login URL from a variable: denied, URLs must be literal")
check(decision(f"epmautomate login svc_epm_agent C:/secure/../secure/svc_epm_agent.epw {TEST_URL}") == "deny",
      "a password file path with .. in it: denied")

# commands that run or change something ask a person
check(decision('epmautomate runBusinessRule "FIN.REV.210 Calculate Revenue" Period=Oct Entity=E-4410') == "ask",
      "runBusinessRule: asks")
check(decision('epmautomate runIntegration GL_Actuals importMode=Replace exportMode=Merge periodName="{Oct-26}"') == "ask",
      "runIntegration: asks")
check(decision("EPMAutomate RunBusinessRule X") == "ask", "mixed case is normalized before the policy check")
check(decision('epmautomate runIntegration GL_Actuals importMode=Replace exportMode=Merge periodName="{Jan#&CurYr}"') == "deny",
      "a substitution variable, even quoted: denied, because cmd.exe runs what follows the &")
check(decision('epmautomate downloadFile "x&whoami"', tool="PowerShell") == "deny", "& inside quotes: denied")
check(decision('epmautomate runBusinessRule "X;Y"') == "deny", "a semicolon inside quotes: denied")
check(decision("epmautomate runBusinessRule X Period=&CurMonth") == "deny", "an unquoted & is denied")

# quoting and escaping tricks that make the shell read the line differently from the hook
check(decision("epmautomate listFiles \\' ; epmautomate recreate -f \\'") == "deny", "escaped quote trick in Bash: denied")
check(decision('epmautomate listFiles \\" ; epmautomate recreate -f \\"') == "deny", "escaped double quote trick: denied")
check(decision("epmautomate listFiles ‘a\"b’ ; Write-Output SECOND ; ‘c\"d’", tool="PowerShell") == "deny",
      "curly quotes, which PowerShell treats as quotes: denied")
check(decision("epmautomate downloadFile (Write-Output INJECTED)", tool="PowerShell") == "deny", "a PowerShell subexpression in parentheses: denied")
check(decision("epmautomate downloadFile @(Write-Output INJECTED)", tool="PowerShell") == "deny", "a PowerShell array expression: denied")
check(decision("epmautomate downloadFile %USERPROFILE%") == "deny", "a cmd.exe variable: denied")
check(decision("epmautomate downloadFile x^&whoami") == "deny", "a cmd.exe escape: denied")
check(decision("epmautomate recreate -f", tool="Monitor") == "deny", "the Monitor tool is inspected too")

# everything else is denied, fail closed
check(decision("epmautomate recreate -f") == "deny", "recreate: denied")
check(decision("epmautomate RECREATE -f removeAll=true") == "deny", "RECREATE in capitals: denied")
check(decision("/opt/epmautomate/bin/epmautomate.sh recreate -f") == "deny", "recreate through a full path to epmautomate.sh: denied")
check(decision('epmautomate resetService "slow" -f') == "deny", "resetService: denied")
check(decision("epmautomate importSnapshot Artifact_Snapshot") == "deny", "importSnapshot, not on the policy: denied")
check(decision("epmautomate deleteFile data.csv") == "deny", "deleteFile: denied")
check(decision("epmautomate") == "deny", "no command: denied")

# shapes the hook cannot vouch for
check(decision('sh -c "epmautomate recreate -f"') == "deny", "wrapped in sh -c: denied")
check(decision('cmd /c epmautomate resetService "x" -f') == "deny", "wrapped in cmd /c: denied")
check(decision('sh -c "epmautomate encrypt S3cretA key f.epw"') == "deny", "encrypt wrapped in sh -c: denied")
check(decision("cmd /c epmautomate encrypt S3cretB key f.epw") == "deny", "encrypt wrapped in cmd /c: denied")
check(decision("epmautomate listFiles && epmautomate deleteFile x.csv") == "deny", "chained with &&: denied")
check(decision("epmautomate listFiles & epmautomate recreate -f") == "deny", "chained with a single & (cmd.exe): denied")
check(decision("epmautomate listFiles; epmautomate recreate -f", tool="PowerShell") == "deny", "chained with ;: denied")
check(decision("epmautomate listFiles | findstr snapshot") == "deny", "piped: denied")
check(decision("epmautomate listFiles > files.txt") == "deny", "redirected: denied")
check(decision("epmautomate downloadFile $(cat name.txt)") == "deny", "command substitution: denied")
check(decision("epmautomate listFiles\nepmautomate recreate -f") == "deny", "second command on a new line: denied")
check(decision('epmautomate runBusinessRule "unbalanced') == "deny", "unbalanced quotes: denied")

# the credential file
check(decision("cat C:\\secure\\svc_epm_agent.epw") == "deny", "reading the .epw with cat: denied")
check(decision("type svc_epm_agent.epw", tool="PowerShell") == "deny", "reading the .epw with type: denied")
check(decision("epmautomate downloadFile svc_epm_agent.epw") == "deny", "a .epw named outside login: denied")
check(decision(f"epmautomate login svc_epm_agent C:/secure/svc_epm_agent.epw {PROD_URL}") == "deny",
      "login to an environment not on the policy (production): denied")
check(decision(f"epmautomate login svc_admin C:/Users/admin/admin.epw {TEST_URL}") == "deny",
      "login as another user, with that user's file: denied")
check(decision(f'epmautomate login svc_epm_agent "C:/ProgramData/Oracle/EPM Automate/password.epw" {TEST_URL}') == "deny",
      "login with another password file: denied")
check(decision(f"epmautomate login svc_epm_agent Plain#Passw0rd {TEST_URL}") == "deny",
      "login with a password typed in place of the file: denied")
check(decision(f"epmautomate login -p prod_login.txt {TEST_URL}") == "deny", "login through a parameter file: denied")
check(decision(f"epmautomate login svc_epm_agent C:/secure/svc_epm_agent.epw {TEST_URL} MyDomain") == "deny",
      "login with an extra argument: denied")
check(decision("epmautomate runBusinessRule -p rb.txt") == "deny", "a parameter file on any command: denied")
check(decision("epmautomate encrypt S3cretPass myKey C:/secure/svc_epm_agent.epw") == "deny", "encrypt: denied")
check(decision(f"epmautomate login svc_epm_agent {TEST_URL} Hunter2Pass") == "deny", "a misordered login: denied")

# the audit log
lines = [json.loads(l) for l in audit_log.read_text(encoding="utf-8").splitlines()]
check(all(set(l) == {"ts", "session", "decision", "command", "reason"} for l in lines), "every audit line has the same five fields")
check(any(l["decision"] == "deny" and l["command"][:2] == ["epmautomate", "recreate"] for l in lines), "a denied recreate is logged")
log_text = audit_log.read_text(encoding="utf-8")
check("S3cretPass" not in log_text, "the password given to encrypt never reaches the log")
check("Hunter2Pass" not in log_text, "a password in a misordered login never reaches the log")
check("S3cretA" not in log_text and "S3cretB" not in log_text, "secrets inside a wrapped, denied command never reach the log")
check("Plain#Passw0rd" not in log_text, "a password typed into login never reaches the log")
check(any(l["command"] == ["epmautomate", "encrypt", "[redacted]", "[redacted]", "[redacted]"] for l in lines),
      "encrypt is logged with every argument redacted")
check(sum(1 for l in lines if l["decision"] == "ask") == 3, "each ask is logged once")

# fail closed
code, d, err = run("", raw='{"tool_name": "Bash", "tool_input": {"command": "epmautomate recreate -f"')
check(code == 2 and "blocked" in err, "malformed input that mentions EPM Automate: blocked with exit 2")
code, d, _ = run("", raw="not json at all")
check(code == 0 and d is None, "malformed input with no EPM content: left to the normal rules")
(hooks_dir / "epm_policy.json").rename(hooks_dir / "policy.bak")
check(decision("epmautomate listFiles") == "deny", "missing policy file: every EPM Automate call denied")
check(decision("git status") is None, "missing policy file: unrelated commands unaffected")
(hooks_dir / "policy.bak").rename(hooks_dir / "epm_policy.json")
check(decision("epmautomate listFiles", tool="Read") is None, "tools other than Bash and PowerShell are not inspected")

shutil.rmtree(project, ignore_errors=True)
print(f"\n{ok} checks passed")
