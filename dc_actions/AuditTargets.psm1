<#
    AuditTargets.psm1

    Reads the target table - a JSON array, one object per domain - and
    hands back an ordered dictionary keyed by domain name. No database:
    this is a one-shot tool.

    Source, in order:
        1. $env:ADAUDIT_TARGETS, if already set for the session
        2. a .env file next to this module (dc_actions\.env) - read once
           per call, not cached, so editing it takes effect on the next run

    .env may hold the JSON directly, or prefixed with `ADAUDIT_TARGETS=`
    (either is fine, the prefix is just stripped if present). Being a real
    file means no PowerShell string-quoting to fight - write the JSON as
    plain, multi-line, pretty-printed text.

    Shape:
        [
          {"Domain":"a.lo","Server":"dc.a.lo","Username":"a\olvin","Trusted":true},
          {"Domain":"nnn.lo","Server":"dc-nnn.nnn.lo","Username":"nnn\adm","Trusted":false,"Extra":["dc2.nnn.lo"],"Note":"no trust"}
        ]

    Fields per entry:
        Domain    required, the key
        Server    required, primary DC to connect to
        Username  optional - prefills the Get-Credential prompt so the
                  account never has to be retyped; the password is always
                  asked for interactively, never stored here or anywhere
                  else
        Trusted   optional, defaults to $true - $false marks a domain with
                  no trust to the management domain (needs NTLM +
                  TrustedHosts, see run-remote.ps1's header)
        Extra     optional, defaults to [] - additional DC names for the
                  same domain
        Note      optional, defaults to '' - shown in -list

    .env is gitignored - see .env.example for a template to copy.

    Usage
        Import-Module .\AuditTargets.psm1
        $Targets = Get-AuditTargets
        $Targets['nnn.lo'].Server
#>

function Get-TargetsRawJson {
    if (-not [string]::IsNullOrWhiteSpace($env:ADAUDIT_TARGETS)) {
        return $env:ADAUDIT_TARGETS
    }

    $envFile = Join-Path $PSScriptRoot '.env'
    if (Test-Path $envFile) {
        $text = (Get-Content $envFile -Raw).Trim()
        # Accept either a bare JSON array or an `ADAUDIT_TARGETS=...` line.
        $text = $text -replace '(?i)^ADAUDIT_TARGETS\s*=\s*', ''
        if (-not [string]::IsNullOrWhiteSpace($text)) { return $text }
    }

    return $null
}

function Get-AuditTargets {
    <#
        .SYNOPSIS
        Reads the target table - $env:ADAUDIT_TARGETS if set, else .env
        next to this module.

        .PARAMETER Domain
        Return only these domains, in the order given.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Domain
    )

    $raw = Get-TargetsRawJson
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "No targets found. Either set `$env:ADAUDIT_TARGETS to a JSON array, or create a .env file next to this module (copy .env.example). See this module's header for the shape."
    }

    try { $parsed = $raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Targets could not be parsed as JSON: $($_.Exception.Message)" }

    $entries = @($parsed)
    if (-not $entries.Count) { throw "Targets parsed to an empty list" }

    $ordered = [ordered]@{}
    foreach ($e in $entries) {
        if (-not $e.Domain) { throw "An entry is missing 'Domain'" }
        if (-not $e.Server) { throw "'$($e.Domain)' has no Server" }
        if ($ordered.Contains($e.Domain)) { throw "Duplicate domain '$($e.Domain)'" }

        $ordered[$e.Domain] = @{
            Server   = $e.Server
            Username = if ($e.PSObject.Properties.Name -contains 'Username') { $e.Username } else { '' }
            Trusted  = if ($e.PSObject.Properties.Name -contains 'Trusted') { [bool]$e.Trusted } else { $true }
            Extra    = if ($e.PSObject.Properties.Name -contains 'Extra') { @($e.Extra) } else { @() }
            Note     = if ($e.PSObject.Properties.Name -contains 'Note') { "$($e.Note)" } else { '' }
        }
    }

    if ($Domain) {
        $subset = [ordered]@{}
        foreach ($d in $Domain) {
            if (-not $ordered.Contains($d)) {
                throw "Unknown domain '$d'. Known: $(($ordered.Keys) -join ', ')"
            }
            $subset[$d] = $ordered[$d]
        }
        return $subset
    }

    return $ordered
}

function Show-AuditTargets {
    <#
        .SYNOPSIS
        Prints the target table.

        .PARAMETER Targets
        An already-loaded ordered dictionary to print, instead of reloading.
    #>
    [CmdletBinding()]
    param($Targets)

    $t = if ($PSBoundParameters.ContainsKey('Targets')) { $Targets } else { Get-AuditTargets }
    Write-Host ''
    Write-Host 'Targets:' -ForegroundColor Cyan
    foreach ($k in $t.Keys) {
        $trust = if ($t[$k].Trusted) { 'trusted' } else { 'no trust' }
        $colour = if ($t[$k].Trusted) { 'Gray' } else { 'DarkYellow' }
        Write-Host ("  {0,-12} {1,-24} {2,-9} {3}" -f $k, $t[$k].Server, $trust, $t[$k].Note) -ForegroundColor $colour
        if (@($t[$k].Extra).Count) {
            Write-Host ("  {0,-12} {1}" -f '', ('also: ' + (@($t[$k].Extra) -join ', '))) -ForegroundColor DarkGray
        }
    }
    Write-Host ''
}

Export-ModuleMember -Function Get-AuditTargets, Show-AuditTargets
