<#
    run-adhealth.ps1

    Convenience wrapper: collect, then analyse, then compare with the
    previous dated run if one exists.

    Everything can be typed in lowercase.

    Usage:
        .\run-adhealth.ps1
        .\run-adhealth.ps1 -domain kkk.lo -server dc-iiii.kkk.lo
        .\run-adhealth.ps1 -root d:\ad
#>

[CmdletBinding()]
param(
    [string]$Domain = 'nnn.lo',
    [string]$Server = 'dc-nnn.nnn.lo',
    [string]$Root = 'C:\ad-export',
    [switch]$SkipAnalyze
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$today = (Get-Date).ToString('yyyy-MM-dd')
$outDir = Join-Path $Root $today

# find the newest previous dated folder, if any
$previous = $null
if (Test-Path $Root) {
    $previous = Get-ChildItem $Root -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^\d{4}-\d{2}-\d{2}$' -and $_.Name -ne $today } |
    Sort-Object Name -Descending |
    Select-Object -First 1
}

Write-Host ""
Write-Host "Domain:   $Domain" -ForegroundColor Cyan
Write-Host "Output:   $outDir" -ForegroundColor Cyan
if ($previous) { Write-Host "Baseline: $($previous.FullName)" -ForegroundColor Cyan }
else { Write-Host "Baseline: none yet, this run becomes the first" -ForegroundColor DarkGray }

# repadmin only exists on a DC or with RSAT AD DS tools installed
if (-not (Get-Command repadmin.exe -ErrorAction SilentlyContinue)) {
    Write-Host "Note:     repadmin not found - replication and backup age will be skipped." -ForegroundColor DarkYellow
    Write-Host "          Run this on a domain controller for the full picture." -ForegroundColor DarkYellow
}

# -NoZip: the archive is built at the end, once findings.csv exists too
& (Join-Path $here 'Export-AdHealth.ps1') -Domain $Domain -Server $Server -OutDir $outDir -NoZip

if (-not $SkipAnalyze) {
    $analyzeArgs = @{ Path = $outDir; Domain = $Domain }
    if ($previous) { $analyzeArgs['ComparePath'] = $previous.FullName }
    & (Join-Path $here 'Analyze-AdHealth.ps1') @analyzeArgs
}

# ---------------------------------------------------------------
# Archive everything, analysis output included
# ---------------------------------------------------------------
try {
    $zip = Join-Path $Root ("ad-$Domain-$today.zip")
    $files = Get-ChildItem $outDir -Filter *.csv -File
    if ($files) {
        Compress-Archive -Path $files.FullName -DestinationPath $zip -Force
        $kb = [math]::Round((Get-Item $zip).Length / 1KB, 1)
        Write-Host ""
        Write-Host "Archive: $zip  ($kb KB, $($files.Count) files)" -ForegroundColor Green
        $files | ForEach-Object { Write-Host "    $($_.Name)" -ForegroundColor DarkGray }
    }
    else { Write-Warning "No CSV files found in $outDir" }
}
catch { Write-Warning "Could not build the archive: $($_.Exception.Message)" }