# AD Audit — Roadmap

Working checklist for turning this from a PowerShell+SQL toolkit into the
full self-hosted stack: SQL Server (storage) → PowerShell/Task Scheduler
(collectors) → ASP.NET Core/Blazor (backend+UI) → Nginx (gateway).

Status legend: `[x]` done and verified for real, `[~]` in progress,
`[ ]` not started.

---

## Phase 0 — Foundations

- [x] MS SQL Server as system of record, replacing dated CSV folders
      (`dc_actions/AuditDb.psm1`: 25 fact tables + `Runs`/`RunMeta`/`Findings`,
      byte-faithful CSV rehydration for baseline comparison so
      `Analyze-*.ps1` stayed untouched)
- [x] SQL provisioning scripts (`New-AuditDatabaseLogin.ps1`,
      `Initialize-AuditDatabase.ps1`) — `ad_audit_svc` login,
      `db_datareader`/`db_datawriter`/`db_ddladmin` on `AdAudit`
- [x] Piloted on `a.lo`, then rolled out to all 6 domains — clean runs,
      SQL-sourced baseline comparison confirmed working
- [x] `.NET 10` SDK installed, `src/` solution scaffolded
      (`AdAudit.Shared`, `AdAudit.Web`, `AdAudit.Cli`)
- [x] `svc_adaudit` local account created for real — not a local admin,
      `Log on as a service` + `Log on as a batch job` granted
- [x] First vertical slice, verified end to end including a real browser:
      Blazor page → `CollectionJobRunner`/`CollectionJob` (`Process.Start`,
      streamed stdout/stderr) → `CollectionHub` (SignalR) → live log in the
      UI. `ApplicationStopping` → `KillAll()` as the first-pass answer to
      orphaned processes on backend restart (deliberately shallow, see
      Phase 4)
- [x] Found and fixed a real bug: `$PSScriptRoot` empty in `param()`
      defaults under `[CmdletBinding()]` when invoked via `-File` from an
      external process — fixed in `run-remote.ps1`,
      `Initialize-AuditDatabase.ps1`, `New-AuditDatabaseLogin.ps1`,
      `Fix-NlaDependency.ps1`

## Phase 1 — Credential & config store *(current)*

Goal: `targets.psd1` + per-domain DPAPI `.cred.xml` files retired; domains
and their credentials live in the database, managed through the app.

- [x] `ad_audit_web` SQL login (`New-AuditWebLogin.ps1`) — `db_datareader`
      on the whole database + `SELECT/INSERT/UPDATE/DELETE` scoped to the
      `cfg` schema only, no `db_datawriter`/`db_ddladmin`. Verified for
      real: can read `dbo.Runs`, can INSERT/SELECT/DELETE `cfg.Targets`,
      an `UPDATE` on `dbo.Runs` is correctly denied by SQL Server itself.
- [x] EF Core in a new `AdAudit.Data` project + **EF Core Migrations**
      (`InitialCreate`, applied via a trusted/Windows-auth connection, never
      via `ad_audit_web` — that login intentionally has no DDL rights),
      scoped to the tables the backend owns:
  - [x] `Targets` + `TargetExtraServers` (domain → DC address(es), replaces `targets.psd1`)
  - [x] `DomainCredentials` (encrypted blob per domain, see below)
  - [x] `AuditLogEntries` (who changed which domain's credential, when)
  - Existing `Findings`/`Runs`/fact tables stay **Dapper/raw ADO.NET**
    (not built yet), not EF — PowerShell owns that schema
- [x] ASP.NET Core Data Protection API wired up in `AdAudit.Web`
      (`AddDataProtection()`, `PersistKeysToFileSystem` at
      `C:\ProgramData\AdAudit\keys`, `SetApplicationName("AdAudit")`) —
      supersedes the earlier hand-rolled HKDF/AES-GCM plan
- [x] Shared encrypt/decrypt logic for PowerShell — **not** `Add-Type`
      loading `AdAudit.Shared` directly as originally planned: confirmed
      empirically that Windows PowerShell 5.1 (.NET Framework) cannot load
      a net10.0 assembly at all (loader exception, not a theoretical
      concern). Built `AdAudit.CredentialHelper`, a small standalone
      console exe (same "PowerShell launches it as a child process"
      pattern already proven for `run-remote.ps1`) that wraps
      `AdAudit.Shared`'s `DomainCredentialProtector`. Verified end to end:
      cross-process encrypt→decrypt round-trip, wrong-target-id correctly
      fails to decrypt (purpose-chain binding works), and the real
      PowerShell pipe invocation (`$plain | & $exe encrypt ...`) works
      after fixing a real bug (Windows PowerShell 5.1 prepends a UTF-8 BOM
      to piped stdin; `Console.In` didn't reliably strip it — fixed by
      reading raw stdin bytes and stripping it by hand).
- [x] The 6 real domains migrated from `targets.psd1` + their existing
      per-domain DPAPI `.cred.xml` files into `cfg.Targets`/
      `cfg.TargetExtraServers`/`cfg.DomainCredentials`
      (`dc_actions/Import-TargetsToDb.ps1`, idempotent - re-running skips
      domains already present). Verified for real, not just by row count:
      decrypted `a.lo`'s credential back out of the DB via
      `AdAudit.CredentialHelper` and confirmed it matches the original
      DPAPI-stored password byte-for-byte, username too. Found and fixed a
      third real bug along the way (see project_web_implementation_progress
      memory): a PowerShell function returning `[Convert]::FromBase64String(...)`
      via plain `return` got unrolled into a `System.Object[]` of boxed
      bytes instead of staying a `byte[]`, which `SqlParameter.AddWithValue`
      couldn't bind to a `varbinary` column - same class of bug as the
      earlier `AuditHtml.psm1` array-wrapping issue, opposite direction;
      fixed with `return ,` .
- [ ] Re-running the credential-setting commands under an interactive
      `runas /user:svc_adaudit powershell.exe` session so the whole chain
      (DPAPI `_db.cred.xml`, the Data Protection keyring) is consistent
      under one account - relevant once this actually gets deployed to run
      as `svc_adaudit` (Phase 4, Task Scheduler), not blocking this phase's
      goal below. Can't be driven by the assistant, which can't operate an
      interactive session as another Windows identity.
- [x] `run-remote.ps1`/`deploy.ps1` read domain list + credentials from
      `cfg.Targets`/`cfg.DomainCredentials` when SQL is reachable, falling
      back to `targets.psd1` + the DPAPI `.cred.xml` store otherwise (same
      graceful-degradation shape as the earlier `CanUseDb` pattern) - new
      `Get-AuditTargetsFromDb`/`Get-DomainCredentialFromDb` in
      `AuditDb.psm1`, decrypting via `AdAudit.CredentialHelper` as a child
      process. **Verified for real on the full fleet, not just `a.lo`**:
      `deploy.ps1 -all` and `run-remote.ps1 -all` both ran clean against
      all 6 real domains using DB-sourced targets/credentials end to end -
      every domain logged "using DB-stored credential", every collection
      succeeded, findings totals matched the expected ballpark from the
      last known-good run (380/374/436 vs. 380/374/439, normal real-world
      drift), all 6 saved to SQL, all local CSVs removed. Also found and
      fixed two more real issues along the way: `Protect-Password` in the
      migration script leaked a `byte[]` as an unrolled `Object[]` through
      a bare `return` (same comma-return bug as `AuditHtml.psm1`, see
      below); `deploy.ps1` had no explicit `exit 0` on its success path,
      so a run that actually copied files inherited robocopy's own exit
      code 1 ("files copied") and looked like a failure to anything
      scripting around it.
- [ ] Retire `targets.psd1`, `AuditTargets.psm1`'s file-reading path, and
      the per-domain `.cred.xml` store - the DB path is now proven end to
      end (see above), so this is safe to do, but deleting the fallback
      files/mechanism is a deliberate, hard-to-reverse step the assistant
      is holding off on without an explicit go-ahead rather than doing
      speculatively.

## Phase 2 — Credential management UI

- [ ] Blazor page: add/edit a domain + its DC credential
  - [ ] Password field is **write-only** — never redisplay a saved
        password, replace-only on edit
  - [ ] "Test connection" action against a live DC, with an explicit
        rate-limit/cooldown specific to that action (real AD lockout risk,
        not generic API throttling)
- [ ] Every add/change writes to `AuditLog` (Phase 1 table)

## Phase 3 — Auth & network exposure

Nothing in front of this app yet — currently wide open on whatever port
it's bound to. Must land before this ever leaves a dev machine.

- [ ] OIDC via a real IdP (Entra ID / Keycloak / Okta / whatever the
      self-hosting org already has) — `Microsoft.AspNetCore.Authentication.OpenIdConnect`
      or `oauth2-proxy` in front of nginx
- [ ] (optional, additional) Kestrel `Negotiate` handler for orgs that
      want native Windows Integrated Auth — not a replacement for OIDC
- [ ] Nginx reverse proxy in front of Kestrel, configured for WebSocket
      proxying (`Upgrade`/`Connection: upgrade`, sane timeouts) — required
      for the SignalR/Interactive-Server circuit to survive behind it
- [ ] Explicit decision + firewall/binding: who can actually reach this
      (localhost only vs internal VLAN vs further) — see the
      credential-vault-paranoia stance already agreed for this project

## Phase 4 — Production deployment

- [ ] `UseWindowsService()` for the backend — likely no NSSM needed for it
      (native .NET Windows Service hosting); NSSM only for Nginx
- [ ] Serilog (rolling file sink) + `Microsoft.Extensions.Logging.EventLog`
      for the backend, replacing default console logging
- [ ] Task Scheduler job for the collector running under `svc_adaudit`,
      matching the account the backend runs as (DPAPI/keyring access
      depends on this being consistent)
- [ ] Revisit the orphaned-process problem properly (Phase 0's `KillAll()`
      was explicitly a first pass): what happens to an in-flight
      `Process.Start`-launched collection job across a backend restart —
      detect a leftover process from a previous crash on startup, and/or
      make jobs resumable instead of just killed

## Phase 5 — Dashboards & polish

- [ ] Findings browsing/filtering UI beyond the single `/collect` page
- [ ] Trend/history views the SQL `RunId` history newly enables (findings
      over time per domain/severity, cross-domain rollups) — the actual
      payoff of the SQL migration, not just a prettier version of the
      existing static report
- [ ] Keep `AuditHtml.psm1`'s self-contained HTML report as an offline
      export/fallback option — don't retire it, it needs zero
      infrastructure and is mailable

## Phase 6 — Scale & OSS readiness *(later, not urgent)*

- [ ] Retention/purge policy + partitioning by `RunDate` for
      `Findings`/fact tables (currently indexed only by `RunId`)
- [ ] Parallelize `run-remote.ps1`'s currently-sequential domain
      collection (runspaces/`-Parallel`)
- [ ] License file, README/install docs, `.gitignore` audit for anything
      org-identifying, before any public push

---

*Background/decisions behind each item live in the assistant's project
memory (architecture plan, implementation progress, real bugs found) —
this file is the sequenced checklist, not the reasoning. Update status
markers as items land; add new items under the phase they belong to
rather than tacking everything onto the end.*
