# AD Audit — Roadmap

Working checklist for turning this from a PowerShell+SQL toolkit into the
full self-hosted stack: SQL Server (storage) → PowerShell/Task Scheduler
(collectors) → ASP.NET Core/Blazor (backend+UI), exposed directly via
Kestrel + Windows Firewall - no reverse proxy in front of it (decided
2026-08-21, see Phase 3: Kestrel's modern TLS/limits support plus the
localhost/internal-only exposure model make nginx unnecessary complexity
for a self-hosted tool).

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

## Phase 1 — Credential & config store *(complete 2026-08-21)*

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
      supersedes the earlier hand-rolled HKDF/AES-GCM plan. Found and fixed
      a real bug during the `svc_adaudit` rotation below: `.ProtectKeysWithDpapi()`
      was never actually called (in both `Program.cs` and
      `DomainCredentialProtector`'s standalone constructor), so the keyring
      was sitting on disk as **plaintext** the whole time — the key file
      literally carried Data Protection's own
      `<!-- Warning: the key below is in an unencrypted form -->` comment.
      Confirmed by reading the file directly, not by inspecting the code.
      Now fixed in both places and verified the newly-generated key uses
      `DpapiXmlDecryptor` (proper DPAPI wrapper), not the plaintext fallback.
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
- [x] `_db.cred.xml` and the Data Protection keyring rotated to be
      genuinely consistent under `svc_adaudit`, not just `adm`. Confirmed
      the assistant cannot drive this directly: `Start-Process -Credential`
      to launch cross-account fails with `Access is denied` from a
      non-interactive tool session (no WinSta0/desktop access) — the user
      ran it themselves, which also surfaced that it needs an **elevated**
      PowerShell window on this machine (non-elevated failed the same way
      for the user too, not just the assistant). Sequence run as
      `svc_adaudit` via `Start-Process -Credential -LoadUserProfile`:
      wrote a fresh `_db.cred.xml` under svc_adaudit's own profile,
      decrypted all 6 domains' credentials under the old (plaintext) key,
      retired that key, re-encrypted all 6 under a brand new
      DPAPI-protected/svc_adaudit-scoped key, updated
      `cfg.DomainCredentials`, and verified every domain round-trips —
      `VERIFY: <domain> -> True` for all 6, `ALL_OK`. Automatic rollback
      (un-retire the old key) built in and tested by hitting it for real:
      first run failed on a private, non-exported `AuditDb.psm1` function
      (`New-AuditDbConnection`) and rolled back cleanly with zero data
      touched, confirming the safety net actually works before the second,
      successful run. Also had to grant `svc_adaudit` NTFS read+execute on
      the repo folder (`icacls ... /grant ... RX /T`) - it had zero access
      to `adm`'s Documents tree by default, needed to even read
      `AuditDb.psm1`. Old key kept on disk as `*.xml.retired` (not
      deleted) as a backup.
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
- [x] `targets.psd1` and the 6 per-domain `.cred.xml` files deleted for
      real (`_db.cred.xml` - the unrelated SQL login credential - left
      alone). The 6 credential files were backed up to a local scratch
      location first, since unlike `targets.psd1` they were never
      git-tracked and would have been unrecoverable otherwise.
      `AuditTargets.psm1`/`Get-AuditTargets` are kept as the fallback code
      path (not deleted) - now correctly only a safety net if SQL is ever
      unreachable, not the primary source. Also wired the same SQL-first/
      file-fallback pattern into `Fix-NlaDependency.ps1`, which had the
      same hard dependency on `targets.psd1` existing and would otherwise
      have broken outright once the file was gone.

      **Two more real bugs found by actually deleting the files and
      re-testing, not just by reasoning about the code** (sixth and
      seventh of this integration work - see
      project_web_implementation_progress memory for the full list):
      `run-remote.ps1`/`deploy.ps1` both called
      `$Targets = Get-AuditTargets -Path $TargetsFile` *unconditionally,
      before* checking whether SQL was reachable - harmless while
      `targets.psd1` still existed (redundant read, silently overwritten
      by SQL data moments later), but `Get-AuditTargets` throws when the
      file is missing, so once it was actually deleted this crashed both
      scripts before the SQL path was ever reached. Separately, `-List` in
      both scripts called `Show-AuditTargets -Path $TargetsFile`, which
      re-reads the file **itself**, independently of whatever `$Targets`
      the main script body had already resolved (from SQL or otherwise) -
      same crash, different call site. Fixed by re-ordering both scripts
      to resolve SQL first and only call the file-reading path in the
      `else` branch of a conditional (matching the pattern
      `Fix-NlaDependency.ps1` happened to already use correctly), and by
      giving `Show-AuditTargets` a `-Targets` parameter to print an
      already-resolved dictionary instead of always re-deriving one from
      a path. Verified after the fix: `-list` and a real end-to-end
      collection run both work cleanly with `targets.psd1` and the old
      `.cred.xml` files completely gone from disk.

## Phase 2 — Credential management UI *(complete 2026-08-21)*

- [x] Blazor page: add/edit a domain + its DC credential (`/domains`,
      `Domains.razor` + `DomainAdminService`) — verified for real via a
      direct SQL round-trip (create → row appears in `cfg.Targets` →
      delete via UI → row gone → create again), not just by reading the
      code.
  - [x] Password field is **write-only** — `EditModel.Password` is never
        populated from the saved credential on edit (only `Username` is),
        field starts blank with a "leave blank to keep the existing
        password" placeholder.
  - [x] "Test connection" action against a live DC
        (`DomainConnectionTester`, 30s cooldown keyed by target id) —
        clicked for real in the browser against a saved credential:
        `OK: connected to dc.a.lo (remote host: DC)`.
- [x] Every add/change writes to `AuditLog` (Phase 1 table) — confirmed in
      SQL: `target.create`/`target.delete`/`credential.set` all present
      with the correct `Actor`, `credential.set`'s `Detail` carries the
      username only, never the password.

## Phase 3 — Auth & network exposure

Nothing in front of this app yet — currently wide open on whatever port
it's bound to. Must land before this ever leaves a dev machine.

**No reverse proxy — decided 2026-08-21.** Kestrel is exposed directly:
modern Kestrel (.NET 5+) has its own HTTPS/TLS, request/connection limits
and timeouts, which used to be the reason nginx/IIS sat in front of it;
combined with this app never being meant to reach past localhost/an
internal VLAN, nginx would just be one more service to install, patch, and
(as already flagged once) get its WebSocket proxying subtly wrong for the
SignalR/Interactive-Server circuit. One less moving part for a
self-hosted tool aimed at admins who aren't necessarily nginx experts.

- [x] **Decided 2026-08-21: `Negotiate` (Kerberos/NTLM against this box's
      own AD) instead of OIDC.** This machine is already domain-joined with
      real AD domains to authenticate against - no separate IdP to stand up
      or maintain for a single-user home deployment. OIDC via a real IdP
      (Entra ID / Keycloak / Okta) stays a future option for a
      multi-tenant/org deployment, not needed here.
- [~] `Microsoft.AspNetCore.Authentication.Negotiate` wired up in
      `Program.cs`, but **enforcement is currently OFF** (`AddAuthorization()`
      with no fallback policy) - 2026-08-24, hit two stacked real problems
      trying to verify it live and backed out rather than debug three
      things at once under pressure:
      1. Chrome doesn't attempt transparent Kerberos/NTLM SSO against an
         arbitrary host by default - needs an `AuthServerAllowlist` browser
         policy (`HKCU\SOFTWARE\Policies\Google\Chrome`) naming
         `127.0.0.1`/`localhost`, or it falls back to a manual
         username/password prompt (which defeats the point).
      2. Separately, the HTTPS dev-cert story broke: `dotnet dev-certs
         https --trust` is per-Windows-account. `adm` trusted one cert,
         but Kestrel runs as `svc_adaudit` and presents a *different* one
         from its own cert store once it also ran the same command -
         browser shows "Not secure" because the two accounts don't share a
         trust chain. Fixing this properly means moving off the ephemeral
         per-account dev cert entirely (one real cert file, ACL'd for
         `svc_adaudit` to read, referenced explicitly via
         `Kestrel:Certificates:Default:Path`, its public half imported into
         every browsing account's trusted root - same shape as the DPAPI
         keyring precedent) rather than fighting the per-account mismatch.

      `Domains.razor`'s `AuditLog` `Actor` now correctly comes from the
      authenticated identity (`AuthenticationState`) instead of
      `Environment.UserName` (which reported the *process's* account,
      svc_adaudit/adm, not whoever was actually in the browser - a real gap
      the audit log had this whole time, closed while wiring this up) -
      this part is done and doesn't depend on enforcement being back on.
      **Both SSO and the cert fix are deliberately deferred as a separate
      follow-up item, not urgent** - the app is reachable at
      `http://127.0.0.1:5034` with no login prompt in the meantime, which
      is fine given it's already localhost-only + firewalled (see below).
- [x] Rate limiting via ASP.NET Core's native middleware
      (`Microsoft.AspNetCore.RateLimiting`, no extra package needed) - a
      global fixed-window limiter as a backstop against a runaway client,
      partitioned by the **authenticated Windows account**, not remote IP
      (every request on this box arrives from 127.0.0.1 regardless of who
      it's actually from, so IP-based partitioning would be meaningless
      here). Separate from and does not replace the Phase 2 "test
      connection" cooldown, which exists specifically for AD-lockout risk,
      not general request volume.
- [x] Explicit exposure scope decision: **localhost only.** Enforced twice:
      `appsettings.json` now pins Kestrel to `http://127.0.0.1:5034`
      explicitly (previously only `launchSettings.json` bound to
      `localhost`, which is dev-only and won't apply once this runs as a
      Windows Service in Phase 4 - an unconfigured Kestrel defaults to
      `http://+:5000`, all interfaces).
- [x] Windows Firewall rule blocking inbound to the port from any
      non-loopback address, as defense-in-depth against a future
      accidental rebind (loopback traffic bypasses the firewall entirely,
      so this doesn't close a gap that exists today - it guards against
      one being introduced later). Applied for real by the user in an
      elevated window (`New-NetFirewallRule -DisplayName "AdAudit Web -
      block non-loopback" -Direction Inbound -LocalPort 5034 -Protocol TCP
      -Action Block -RemoteAddress Any`) - the assistant's own tool session
      cannot open an elevated window itself (see the "no attached window
      station" finding in Phase 1).

**Open follow-up, not blocking anything**: turn `Negotiate` enforcement
back on. Needs, in order: (1) the Chrome `AuthServerAllowlist` policy, (2)
a real file-based cert replacing the per-account dev cert, (3) re-add the
`FallbackPolicy` in `Program.cs` (currently commented out with a note
pointing back here), (4) actually click through it live in a browser
before calling it done - same "verify for real" standard as everything
else in this project.

## Phase 4 — Production deployment

- [ ] `UseWindowsService()` for the backend — native .NET Windows Service
      hosting, no NSSM needed anywhere now that nginx is out of the picture
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
