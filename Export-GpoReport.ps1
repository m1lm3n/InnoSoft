<#
    Export-GpoReport.ps1

    Full export of all domain GPOs to XML and HTML.

    Three retrieval methods, selected automatically:
      Direct  - Get-GPOReport with -Server, from your workstation.
                Always works, but slow: it pulls SYSVOL over the network.
      Remote  - Invoke-Command on the domain controller. Fast, but needs
                WinRM, which is usually closed on a DC.
      Fetch   - copy ready-made files from \\<DC>\c$\gpo-export\.
                For the case where the report was generated on the DC console.

    Usage:
        .\Export-GpoReport.ps1
        .\Export-GpoReport.ps1 -Domain kkk.lo -Server dc-iiii.kkk.lo
        .\Export-GpoReport.ps1 -Method Fetch
        .\Export-GpoReport.ps1 -SkipHtml

    Works from a window started with runas /netonly.
#>

[CmdletBinding()]
param(
    [string]$Domain = 'nnn.lo',
    [string]$Server = 'dc-nnn.nnn.lo',
    [string]$OutDir = 'C:\gpo-export',

    [ValidateSet('Auto','Direct','Remote','Fetch')]
    [string]$Method = 'Auto',

    # Folder holding the reports on the DC itself (used by the Fetch method)
    [string]$RemoteDir = 'C:\gpo-export',

    [switch]$SkipHtml,
    [switch]$NoZip,

    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'
$sw = [System.Diagnostics.Stopwatch]::StartNew()

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$xmlPath  = Join-Path $OutDir "$Domain.xml"
$htmlPath = Join-Path $OutDir "$Domain.html"

Write-Host "`n=== GPO export: $Domain via $Server ===" -ForegroundColor Cyan

# ---------------------------------------------------------------
# Write file without BOM - some XML parsers choke on it
# ---------------------------------------------------------------
function Save-Text {
    param([string]$Text, [string]$Path)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function Show-File {
    param([string]$Path)
    if (Test-Path $Path) {
        $f = Get-Item $Path
        $mb = [math]::Round($f.Length / 1MB, 2)
        Write-Host ("  {0}  -  {1} MB" -f $f.Name, $mb) -ForegroundColor Green
    }
}

# ---------------------------------------------------------------
# Method selection
# ---------------------------------------------------------------
if ($Method -eq 'Auto') {
    Write-Host "`nChecking WinRM on $Server..." -NoNewline
    try {
        Test-WSMan -ComputerName $Server -ErrorAction Stop | Out-Null
        $Method = 'Remote'
        Write-Host " available" -ForegroundColor Green
    }
    catch {
        $Method = 'Direct'
        Write-Host " not available, falling back to Direct" -ForegroundColor Yellow
    }
}
Write-Host "Method: $Method`n" -ForegroundColor Cyan

# ---------------------------------------------------------------
# METHOD 1: direct, from the local machine
# ---------------------------------------------------------------
if ($Method -eq 'Direct') {
    Import-Module GroupPolicy

    Write-Host "XML (may take 10-20 min, the report pulls SYSVOL over the network)..." -ForegroundColor Yellow
    Get-GPOReport -All -Domain $Domain -Server $Server -ReportType Xml -Path $xmlPath
    Show-File $xmlPath

    if (-not $SkipHtml) {
        Write-Host "HTML..." -ForegroundColor Yellow
        Get-GPOReport -All -Domain $Domain -Server $Server -ReportType Html -Path $htmlPath
        Show-File $htmlPath
    }
}

# ---------------------------------------------------------------
# METHOD 2: remote execution on the domain controller
# ---------------------------------------------------------------
elseif ($Method -eq 'Remote') {
    $icmArgs = @{ ComputerName = $Server; ErrorAction = 'Stop' }
    if ($Credential) {
        $icmArgs['Credential']     = $Credential
        $icmArgs['Authentication'] = 'Negotiate'
    }

    Write-Host "XML (generated on the DC, returned as a string)..." -ForegroundColor Yellow
    $xml = Invoke-Command @icmArgs -ScriptBlock {
        Import-Module GroupPolicy
        Get-GPOReport -All -ReportType Xml
    }
    Save-Text -Text $xml -Path $xmlPath
    Show-File $xmlPath

    if (-not $SkipHtml) {
        Write-Host "HTML..." -ForegroundColor Yellow
        $html = Invoke-Command @icmArgs -ScriptBlock {
            Import-Module GroupPolicy
            Get-GPOReport -All -ReportType Html
        }
        Save-Text -Text $html -Path $htmlPath
        Show-File $htmlPath
    }

    Write-Host "  no files were created on the domain controller" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------
# METHOD 3: fetch ready-made files from the admin share
# ---------------------------------------------------------------
elseif ($Method -eq 'Fetch') {
    $share = "\\$Server\" + ($RemoteDir -replace '^([A-Za-z]):', '$1$')
    Write-Host "Source: $share" -ForegroundColor Yellow

    if (-not (Test-Path $share)) {
        throw "Path $share is not reachable. Make sure the report was generated on the DC and that the admin share is accessible."
    }

    $found = Get-ChildItem $share -Include *.xml, *.html -Recurse -ErrorAction SilentlyContinue
    if (-not $found) { throw "No .xml or .html files found in $share" }

    foreach ($f in $found) {
        Copy-Item $f.FullName -Destination $OutDir -Force
        Show-File (Join-Path $OutDir $f.Name)
    }

    Write-Host "`n  Remember to remove the export from the domain controller:" -ForegroundColor DarkYellow
    Write-Host "  Remove-Item '$share\*' -Force" -ForegroundColor DarkYellow
}

# ---------------------------------------------------------------
# XML integrity check
# ---------------------------------------------------------------
if (Test-Path $xmlPath) {
    Write-Host "`nValidating XML..." -ForegroundColor Yellow
    try {
        $doc = New-Object System.Xml.XmlDocument
        $doc.Load($xmlPath)
        $count = $doc.GetElementsByTagName('GPO').Count
        Write-Host "  parsed OK, policies inside: $count" -ForegroundColor Green
    }
    catch {
        Write-Warning "XML does not parse: $($_.Exception.Message)"
        Write-Warning "The export probably got truncated. Run it again."
    }
}

# ---------------------------------------------------------------
# Archive
# ---------------------------------------------------------------
if (-not $NoZip) {
    $zip = "C:\gpo-report-$Domain.zip"
    $items = Get-ChildItem $OutDir -Include *.xml, *.html -Recurse -ErrorAction SilentlyContinue
    if ($items) {
        Compress-Archive -Path $items.FullName -DestinationPath $zip -Force
        $mb = [math]::Round((Get-Item $zip).Length / 1MB, 2)
        Write-Host "`nArchive: $zip  ($mb MB)" -ForegroundColor Green
    }
}

$sw.Stop()
Write-Host ("Elapsed: {0:mm\:ss}`n" -f $sw.Elapsed) -ForegroundColor Cyan
