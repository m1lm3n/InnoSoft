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

- [ ] `ad_audit_web` SQL login — **not created yet**. `db_datareader` only
      on the audit-history schema (`Runs`/`RunMeta`/`Findings`/fact
      tables); full read/write on a separate config schema (e.g. `cfg.*`)
      for the new tables below. Never write access to audit history — that
      stays the collector's job alone.
- [ ] EF Core wired into `AdAudit.Web` (or a new `AdAudit.Data` project) +
      **EF Core Migrations**, scoped to the tables the backend actually
      owns:
  - [ ] `Targets` (domain → DC address, replaces `targets.psd1`)
  - [ ] `DomainCredentials` (encrypted blob per domain, see below)
  - [ ] `AuditLog` (who changed which domain's credential, when — the
        tool auditing itself, separate from the AD-findings audit trail)
  - Existing `Findings`/`Runs`/fact tables stay **Dapper/raw ADO.NET**,
    not EF — PowerShell owns that schema, EF Migrations must never touch it
- [ ] ASP.NET Core Data Protection API wired up (`AddDataProtection()`,
      `PersistKeysToFileSystem`, DPAPI-protected keyring under
      `svc_adaudit`) — supersedes the earlier hand-rolled HKDF/AES-GCM plan
- [ ] Shared `AdAudit.Shared` wrapper around `IDataProtector` so PowerShell
      can decrypt the same way (`Add-Type -Path` against the compiled DLL,
      same keyring folder + `ApplicationName`, same `svc_adaudit` account —
      this is *why* the account had to exist for real before this step)
- [ ] Migrate what already exists under DPAPI today (domain credentials,
      `_db.cred.xml` — currently created under the interactive dev account,
      not `svc_adaudit`) so the whole chain is consistent under one account
      before anything in this phase depends on it
- [ ] `run-remote.ps1`/`deploy.ps1` read domain list + credentials from the
      DB instead of `targets.psd1` + `.cred.xml` (via the shared
      decrypt library above)
- [ ] Retire `targets.psd1`, `AuditTargets.psm1`'s file-reading path, and
      the per-domain `.cred.xml` store once the DB path is proven

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
