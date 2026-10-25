# EPM Automate reference for the runbook

From Oracle's EPM Automate documentation, read 2026-10-24.

## Exit codes

| Code | Meaning | What to do |
|------|---------|-----------|
| 0 | Success | Report it |
| 1 | Command failed to execute: insufficient privileges, a missing file or snapshot, an invalid snapshot, and other errors the REST API returns | Read the message; check names with `listFiles` |
| 6 | Service unavailable, invalid URL, or a read or write timeout | Stop. Tell the administrator; the environment may be in maintenance |
| 7 | EPM Automate could not run the command: invalid parameter, unable to connect, unable to open the password file | Check the syntax against this file. If the password file cannot be opened, stop and tell the administrator |
| 9 | Invalid credentials, or authentication failed | Stop. The administrator renews the credential |
| 11 | Internal server error, including an environment unavailable after a reset | Stop and report |
| 13 | Access denied by Oracle's web access firewall | Stop and report |

For each failed command, EPM Automate writes `COMMANDNAME_TIMESTAMP.log` on this machine.

https://docs.oracle.com/en/cloud/saas/enterprise-performance-management-common/cepma/epm_automate_status_codes.html

## The commands this runbook uses

| Command | Usage |
|---------|-------|
| `login` | `epmautomate login USERNAME PASSWORD_FILE URL` |
| `exportJobConsole` | `epmautomate exportJobConsole FILE_NAME.zip [nDays=1|2|7|30|60|all] [jobTypes=...] [jobStatusCodes=...] [exportErrorDetails=true]` |
| `downloadFile` | `epmautomate downloadFile "FILE_NAME"` |
| `listFiles` | `epmautomate listFiles` |
| `runBusinessRule` | `epmautomate runBusinessRule RULE_NAME [PARAMETER=VALUE]` runs one rule against the cube it is deployed to. Runtime prompts that do not match exactly are ignored, and defaults are used |
| `runIntegration` | `epmautomate runIntegration JOB_NAME importMode=... exportMode=... periodName={...}` |
| `exportSnapshot` | `epmautomate exportSnapshot SNAPSHOT_NAME` replaces an existing snapshot of that name |
| `logout` | `epmautomate logout` |

Job status codes for `exportJobConsole`: 1 processing, 2 completed successfully, 3 failed with errors,
4 completed with unknown status, 5 completed with threshold violation, 6 pending cancellation,
7 canceled, 8 completed with errors, 9 completed with warnings. Error details are exported for 3, 4,
5, 8, and 9.
