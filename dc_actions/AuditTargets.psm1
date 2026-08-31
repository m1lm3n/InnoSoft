<#
    AuditTargets.psm1

    Reads the target table from the ADAUDIT_TARGETS environment variable -
    a JSON array, one object per domain - and hands back an ordered
    dictionary keyed by domain name. No file, no database: this is a
    one-shot tool, the caller sets ADAUDIT_TARGETS for the session and runs
    the script.

    Shape:
        $env:ADAUDIT_TARGETS = '[
          {"Domain":"a.lo","Server":"dc.a.lo","Username":"a\\olvin","Trusted":true},
          {"Domain":"nnn.lo","Server":"dc-nnn.nnn.lo","Username":"nnn\\adm","Trusted":false,"Extra":["dc2.nnn.lo"],"Note":"no trust"}
        ]'

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

    Usage
        Import-Module .\AuditTargets.psm1
        $Targets = Get-AuditTargets
        $Targets['nnn.lo'].Server
#>

function Get-AuditTargets {
    <#
        .SYNOPSIS
        Reads the target table from $env:ADAUDIT_TARGETS.

        .PARAMETER Domain
        Return only these domains, in the order given.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Domain
    )

    $raw = $env:ADAUDIT_TARGETS
    if ([string]::IsNullOrWhiteSpace($raw)) {
        $example = '$env:ADAUDIT_TARGETS = ''[{"Domain":"a.lo","Server":"dc.a.lo","Username":"a\olvin"}]'''
        throw "ADAUDIT_TARGETS is not set. Example: $example"
    }

    try { $parsed = $raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "ADAUDIT_TARGETS could not be parsed as JSON: $($_.Exception.Message)" }

    $entries = @($parsed)
    if (-not $entries.Count) { throw "ADAUDIT_TARGETS parsed to an empty list" }

    $ordered = [ordered]@{}
    foreach ($e in $entries) {
        if (-not $e.Domain) { throw "ADAUDIT_TARGETS: an entry is missing 'Domain'" }
        if (-not $e.Server) { throw "ADAUDIT_TARGETS: '$($e.Domain)' has no Server" }
        if ($ordered.Contains($e.Domain)) { throw "ADAUDIT_TARGETS: duplicate domain '$($e.Domain)'" }

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
        An already-loaded ordered dictionary to print, instead of reloading
        from ADAUDIT_TARGETS.
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
