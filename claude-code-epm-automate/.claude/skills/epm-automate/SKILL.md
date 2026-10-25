---
name: epm-automate
description: Run the Oracle EPM Automate runbook for the test environment. Use when asked whether last night's jobs or business rules worked, why a job failed, to rerun a business rule or integration, or to take a snapshot before a change.
argument-hint: "[what you want checked or run]"
---

# EPM Automate runbook

You operate Oracle Cloud EPM through the EPM Automate command line, for the **test environment only**.
The person you work with is the EPM administrator. You do the legwork and explain what you found; they
decide anything that changes the environment.

## Credentials and login

- Log in with exactly this command, and nothing else:
  `epmautomate login svc_epm_agent C:/secure/svc_epm_agent.epw https://example-test.epm.us-phoenix-1.ocs.oraclecloud.com`
- The `.epw` file is a credential. Never open, read, copy, list, or search for it, and never run
  `encrypt`. If login fails with exit code 7 or 9, stop and tell the administrator. Creating or renewing
  the file is their job, done in their own terminal.
- Log out when the task is done: `epmautomate logout`.

## Rules of the road

- Run one EPM Automate command per call. No chaining, pipes, redirects, variables, or parameter files
  (`-p`); the guard hook blocks them. To use a substitution variable, read its value with `getSubstVar`
  first and pass the member name, because `&` is blocked.
- On Windows, run EPM Automate through the PowerShell tool. Write paths with forward slashes.
- Report every command you ran and its exit code. Exit code meanings are in [reference.md](reference.md).
- Commands that run or change something (`runBusinessRule`, `runIntegration`, `exportSnapshot`) show
  a permission prompt. Before each one, say in one sentence what it will do and why.
- Never suggest `recreate`, `resetService`, `importSnapshot`, `deleteFile`, `runDailyMaintenance`, or
  any user or role command. They are blocked, and they belong to a person.
- If the guard hook denies a call, do not look for another way to run it. Explain what you wanted to
  do and let the administrator decide.
- Figures, member names, and error text come from EPM output, quoted exactly. Never estimate them.

## Procedures

### Did last night's rules run?

1. Log in.
2. `epmautomate exportJobConsole jobs.zip nDays=1 jobTypes=all jobStatusCodes=3,4,5,8,9 exportErrorDetails=true`
3. `epmautomate downloadFile jobs.zip`, then unzip it locally and read the CSV and any error logs.
4. Report: how many jobs failed or warned, and for each one the job name, the time, and the error
   in Oracle's own words. Then your reading of the likely cause, labeled as your reading.
5. If nothing failed, say so in one line.

### Rerun a business rule

1. Confirm the rule name and every runtime prompt value with the administrator. Rule names are
   case sensitive and must match the environment exactly.
2. `epmautomate runBusinessRule "RULE NAME" Prompt1=Value1 Prompt2=Value2`
3. Report the exit code. On failure, export the job console for the last day with
   `jobStatusCodes=3,8 exportErrorDetails=true` and explain the error.

### Rerun an integration

1. Confirm the integration name, the period, and both modes. Default to `importMode=Replace`
   `exportMode=Merge` only when the administrator agrees.
2. `epmautomate runIntegration NAME importMode=Replace exportMode=Merge periodName="{Oct-26}"`
3. Report the exit code. Point the administrator to the process details in Data Integration for row
   level errors.

### Snapshot before a change

1. `epmautomate exportSnapshot "NAME"`, using a name the administrator gives you. The command
   replaces an existing snapshot of the same name, so say so if one exists (check with `listFiles`).
2. Report the exit code.
