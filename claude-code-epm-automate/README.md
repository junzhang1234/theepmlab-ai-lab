# Code for the Claude Code and EPM Automate post

Copy the `.claude` folder into an empty project folder, then set the agent's user, password file, and
test environment URL in `hooks/epm_policy.json`, the login allow rules in `settings.json` (Bash and
PowerShell), and the login line in `skills/epm-automate/SKILL.md`. Put your production host in the
sandbox's `deniedDomains`.

```
.claude/
  settings.json                  permission rules, the hook registration, the sandbox
  hooks/epm_guard.py             PreToolUse guard for EPM Automate, fails closed
  hooks/epm_policy.json          environments and commands the agent may use
  skills/epm-automate/SKILL.md   the runbook
  skills/epm-automate/reference.md   exit codes and command syntax
tests/test_guard.py              69 offline checks: python tests/test_guard.py
```

The hook needs Python 3.9 or later and nothing outside the standard library.
