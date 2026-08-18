<#
    AuditTargets.psm1

    Loads targets.psd1 and hands back an ordered dictionary.

    Why a module rather than one line in each script
        Import-PowerShellDataFile returns a plain hash table, whose key
        order is not the order they were written in. Domains would then be
        processed in an arbitrary sequence, which makes two runs awkward to
        compare. This restores the file order by reading the keys back out
        of the text.

    Usage
        Import-Module .\AuditTargets.psm1
        $Targets = Get-AuditTargets
        $Targets['nnn.lo'].Server
#>

function Get-AuditTargets {
    <#
        .SYNOPSIS
        Reads the shared target table.

        .PARAMETER Path
        Location of targets.psd1. Defaults to the folder holding this module.

        .PARAMETER Domain
        Return only these domains, in the order given.
    #>
    [CmdletBinding()]
    param(
        [string]$Path,
        [string[]]$Domain
    )

    if (-not $Path) { $Path = Join-Path $PSScriptRoot 'targets.psd1' }

    if (-not (Test-Path $Path)) {
        throw "targets.psd1 not found at $Path. It must sit next to the scripts."
    }

    try { $raw = Import-PowerShellDataFile -Path $Path -ErrorAction Stop }
    catch { throw "targets.psd1 could not be parsed: $($_.Exception.Message)" }

    if (-not $raw -or $raw.Count -eq 0) { throw "targets.psd1 is empty" }

    # recover the order the domains were written in
    $text = Get-Content $Path -Raw
    $ordered = [ordered]@{}
    foreach ($m in [regex]::Matches($text, "(?m)^\s*'([^']+)'\s*=\s*@\{")) {
        $key = $m.Groups[1].Value
        if ($raw.Contains($key) -and -not $ordered.Contains($key)) { $ordered[$key] = $raw[$key] }
    }
    # anything the regex missed still goes in, so nothing is silently lost
    foreach ($k in $raw.Keys) {
        if (-not $ordered.Contains($k)) { $ordered[$k] = $raw[$k] }
    }

    # fill in defaults so callers never have to test for a missing field
    foreach ($k in @($ordered.Keys)) {
        $entry = $ordered[$k]
        if (-not $entry.Contains('Server')) { throw "targets.psd1: '$k' has no Server" }
        if (-not $entry.Contains('Trusted')) { $entry['Trusted'] = $true }
        if (-not $entry.Contains('Extra')) { $entry['Extra'] = @() }
        if (-not $entry.Contains('Note')) { $entry['Note'] = '' }
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
    #>
    [CmdletBinding()]
    param([string]$Path)

    $t = Get-AuditTargets -Path $Path
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