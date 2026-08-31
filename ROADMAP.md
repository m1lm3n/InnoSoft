# AD Audit — Roadmap

One-shot PowerShell toolkit: run a script, it connects to each domain over
WinRM, deploys and runs the collectors on the DC, brings the results home,
and builds one self-contained HTML report. No database, no persistent
service, nothing installed anywhere but this folder.

**2026-08-24: reverted the SQL Server + ASP.NET Core/Blazor web app
direction.** That stack (see git history 2026-08-19 through 2026-08-24, and
the `project_web_architecture_plan`/`project_web_implementation_progress`
assistant-memory entries for the full "why" and the real bugs hit along the
way) was built out through a working credential-management UI with cookie
login, but turned out to be the wrong shape for what this actually is: a
tool run occasionally by one person, not a service that needs its own auth
system, TLS story, and a database to babysit. Rolled back to the
pre-migration shape - `dc_actions/*.ps1` only - with two changes from how
it worked before the SQL detour: targets now come from `$env:ADAUDIT_TARGETS`
(a JSON env var, see `AuditTargets.psm1`'s header) instead of a
`targets.psd1` file, and no credential is ever stored on disk - `run-remote.ps1`/
`deploy.ps1`/`Fix-NlaDependency.ps1` prompt for a password interactively,
every run. Everything from `src/` (the .NET solution) and the SQL
provisioning scripts is gone from the working tree but recoverable from git
history if ever needed again.

## Current state

- [x] Collectors (`Export-GpoMap.ps1`, `Export-AdHealth.ps1`,
      `Export-AdSecurity.ps1`, `Export-GpoReport.ps1`) + their `run-*.ps1`
      wrappers, deployed to and run on the DC itself over WinRM
- [x] Analyzers (`Analyze-GpoMap.ps1`, `Analyze-AdHealth.ps1`,
      `Analyze-AdSecurity.ps1`) run on the workstation, comparing the fresh
      CSVs against the previous dated folder
- [x] `AuditHtml.psm1` - single self-contained HTML report, one tab per
      domain, no external files or CDN
- [x] `deploy.ps1` - robocopy the toolkit onto each DC
- [x] `run-remote.ps1` - orchestrates deploy+collect+analyze+report across
      every domain in one run
- [x] `Fix-NlaDependency.ps1` - one-off maintenance fix for a DC's network
      profile flapping to Public at boot
- [x] Targets + usernames from `$env:ADAUDIT_TARGETS` (JSON array: Domain,
      Server, Username, Trusted, Extra, Note per entry) - see
      `AuditTargets.psm1`
- [x] Passwords never stored anywhere - `Get-Credential` prompt per domain,
      every run, prefilled with the Username from `$env:ADAUDIT_TARGETS` if
      given
- [x] CSV folders under `-LocalRoot` (`C:\audit\<domain>\<date>\` by
      default) kept on disk permanently - each one is the baseline the next
      run compares against

## Usage

```powershell
$env:ADAUDIT_TARGETS = '[
  {"Domain":"a.lo","Server":"dc.a.lo","Username":"a\olvin","Trusted":true},
  {"Domain":"nnn.lo","Server":"dc-nnn.nnn.lo","Username":"nnn\adm","Trusted":false,"Note":"no trust"}
]'

.\deploy.ps1 -all          # ship the toolkit to every DC
.\run-remote.ps1 -all      # collect, analyze, build the report
```

---

*Background/decisions live in the assistant's project memory
(architecture, implementation history, real bugs found) - this file is the
current-state checklist, not the reasoning.*
