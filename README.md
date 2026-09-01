# AD Audit

A one-shot PowerShell toolkit for auditing multiple Active Directory
domains: deploys collectors to each domain's DC over WinRM, runs them
there, brings the results home, and builds one self-contained HTML report.
No database, no service, no web UI - just this folder and a `.env` file.

## What it collects

Three toolkits, each collection-only (writes CSVs) with a matching
analyzer (reads them, flags findings, diffs against the previous run):

| Toolkit    | Collector               | Analyzer               | Covers |
|------------|--------------------------|--------------------------|--------|
| `gpo`      | `Export-GpoMap.ps1`      | `Analyze-GpoMap.ps1`     | OU structure, GPO links, WMI filters, GPO permissions/ACLs (including raw Apply-Group-Policy Allow/Deny ACEs), group membership behind exclusion groups |
| `adhealth` | `Export-AdHealth.ps1`    | `Analyze-AdHealth.ps1`   | Domain controllers, FSMO roles, replication health, sites/subnets/site links, privileged group membership, domain-wide settings (functional levels, password policy, krbtgt age) |
| `adsecurity` | `Export-AdSecurity.ps1` | `Analyze-AdSecurity.ps1` | Certification authorities and templates, LAPS coverage, `AdminSDHolder`/Protected Users status, computer inventory, DC hardening (SMB/LDAP signing, NTLM level, spooler) |

`Export-GpoReport.ps1` is a separate, standalone utility (not part of the
three toolkits above) that dumps full GPO XML/HTML reports - run it by hand
when you need the raw policy content, not just the audit findings.

Everything is read-only against the directory. DC hardening checks need
the remote registry service (or running directly on the DC); certificate
**private keys** are never touched, only template definitions.

## Requirements

- A Windows workstation with WinRM's client side available (built in) and
  network reach to each domain's DC on TCP 5985 and TCP 445 (admin share,
  for `deploy.ps1`).
- An account with administrative rights on each target domain - used to
  open a WinRM session and read AD/registry data. Nothing is installed on
  the DC permanently; `deploy.ps1` copies the scripts, `run-remote.ps1`
  cleans up its working folder after each run.
- Domains with no trust to your workstation's domain need NTLM, which
  WinRM only allows for hosts listed in `TrustedHosts` - see
  `run-remote.ps1 -?` (its comment-based help covers this in detail).

## Setup

```powershell
cd dc_actions
copy .env.example .env
notepad .env
```

`.env` is a JSON array, one object per domain:

```json
[
  {"Domain":"a.lo",   "Server":"dc.a.lo",       "Username":"a\olvin",   "Trusted":true},
  {"Domain":"nnn.lo", "Server":"dc-nnn.nnn.lo",  "Username":"nnn\adm",   "Trusted":false, "Note":"no trust"}
]
```

`Domain`/`Server` are required; `Username` prefills the credential prompt
(never a password - see [Credentials](#credentials) below); `Trusted`
defaults to `true`; `Extra` (array of additional DC names) and `Note`
default to empty. Full field list: `AuditTargets.psm1`'s header comment.

`.env` is gitignored. If `$env:ADAUDIT_TARGETS` is set for the session, it
takes precedence over the file - useful for a one-off run without editing
the file, or for CI-style invocation.

## Usage

```powershell
.\deploy.ps1 -all               # ship the toolkit to every DC
.\run-remote.ps1 -all           # collect + analyze + build the report

.\run-remote.ps1 -domain a.lo   # just one domain
.\run-remote.ps1 -all -only gpo # one toolkit across every domain
.\run-remote.ps1 -list          # print the target table, do nothing else
.\run-remote.ps1 -all -promptondenied        # retry interactively if a credential is refused
```

Untrusted domains (`Trusted: false`) need NTLM, which WinRM only permits
for hosts listed in `TrustedHosts` - handled automatically, no flag needed:
missing entries are added before the run starts, prompting once for UAC if
the console isn't already elevated.

`Get-Help .\run-remote.ps1` shows the parameter list; the fuller
explanation (trusts, TrustedHosts, authentication fallback, output layout)
is in the comment block at the top of `run-remote.ps1` and `deploy.ps1`
themselves - open the file.

## Credentials

Never stored, anywhere. `Get-Credential` prompts once per domain, every
run, prefilled with the `Username` from `.env`/`$env:ADAUDIT_TARGETS` if
one was given. No DPAPI cache, no credential file, no database row.

## Output

```
C:\audit\
  <domain>\<yyyy-MM-dd>\*.csv     one dated folder per domain per run
  audit-report-<yyyy-MM-dd>.html  single self-contained report, no CDN/external files
```

Dated folders are **kept forever** - each one is the baseline the next
run's analyzers diff against. Nothing is deleted automatically.

This output holds real AD security findings (kerberoastable accounts,
delegation misconfigurations, LAPS coverage, privileged group membership)
across production domains - treat the `-LocalRoot` folder with the same
care as the domain credentials themselves.

## Repo layout

```
dc_actions/
  deploy.ps1              ship the toolkit to every DC (robocopy over an admin share)
  run-remote.ps1           orchestrates deploy+collect+analyze+report across domains
  Export-*.ps1             collectors (run on the DC)
  Analyze-*.ps1             analyzers (run on the workstation)
  run-gpo.ps1, run-adhealth.ps1, run-adsecurity.ps1   thin wrappers run-remote.ps1 invokes on the DC
  AuditTargets.psm1        reads the target table (.env / $env:ADAUDIT_TARGETS)
  AuditCapture.psm1        captures an analyzer's console output for the HTML report
  AuditHtml.psm1           builds the HTML report
  Fix-NlaDependency.ps1    one-off fix for a DC's network profile flapping to Public at boot
  .env.example             copy to .env and fill in your domains
ROADMAP.md                 current-state checklist
```

See `ROADMAP.md` for what's done, and the assistant's project memory
(referenced there) for the reasoning behind past architecture decisions,
including why this ended up as a plain script instead of a web app.
