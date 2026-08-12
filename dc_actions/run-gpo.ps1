<#
    run-gpo.ps1

    Convenience wrapper: collect, then analyse, then compare with the
    previous dated run if one exists.

    Everything can be typed in lowercase.

    Usage:
        .\run-gpo.ps1
        .\run-gpo.ps1 -domain kkk.lo -server dc-iiii.kkk.lo
        .\run-gpo.ps1 -root d:\gpo
#>

[CmdletBinding()]
param(
    [string]$Domain = 'nnn.lo',
    [string]$Server = 'dc-nnn.nnn.lo',
    [string]$Root = 'C:\gpo-export',
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

& (Join-Path $here 'Export-GpoMap.ps1') -Domain $Domain -Server $Server -OutDir $outDir

if ($SkipAnalyze) { return }

$analyzeArgs = @{ Path = $outDir; Domain = $Domain }
if ($previous) { $analyzeArgs['ComparePath'] = $previous.FullName }

& (Join-Path $here 'Analyze-GpoMap.ps1') @analyzeArgs