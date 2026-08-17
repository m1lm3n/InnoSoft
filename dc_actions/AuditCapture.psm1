<#
    AuditCapture.psm1

    Captures console output produced by Write-Host, keeping the colour of
    every fragment, so it can be rendered later instead of scrolling past.

    How it works
        Write-Host writes straight to the host and never touches the
        pipeline, so it cannot be redirected. A function of the same name
        defined in the global scope shadows the cmdlet everywhere, including
        inside scripts called afterwards. The proxy records what it is given
        and, unless asked to echo, prints nothing.

    The analyzers need no changes at all.

    Usage
        Import-Module .\AuditCapture.psm1
        Start-ConsoleCapture
        & .\Analyze-AdHealth.ps1 -Path C:\audit\nnn.lo\2026-08-14
        $lines = Stop-ConsoleCapture

    Returned shape: an array of lines, each line an array of segments:
        @{ Text = 'MS16-072 RISK: 1'; Color = 'Red' }
#>

# State lives in the global scope on purpose. The proxy is registered as a
# global function, and a script block registered that way loses its link to
# the module scope, so anything it referenced there would be unreachable.
# Keeping everything global is less elegant and actually works.
$global:AuditCaptureLines = $null
$global:AuditCaptureCurrent = $null
$global:AuditCaptureEcho = $false
$global:AuditCaptureActive = $false

function Start-ConsoleCapture {
    <#
        .SYNOPSIS
        Redirects Write-Host into a buffer until Stop-ConsoleCapture.

        .PARAMETER Echo
        Also print to the console, for debugging the capture itself.
    #>
    [CmdletBinding()]
    param([switch]$Echo)

    if ($global:AuditCaptureActive) { [void](Stop-ConsoleCapture) }

    $global:AuditCaptureLines = New-Object System.Collections.Generic.List[object]
    $global:AuditCaptureCurrent = New-Object System.Collections.Generic.List[object]
    $global:AuditCaptureEcho = [bool]$Echo
    $global:AuditCaptureActive = $true

    $proxy = {
        [CmdletBinding()]
        param(
            [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
            [object[]]$Object,

            [System.ConsoleColor]$ForegroundColor,
            [System.ConsoleColor]$BackgroundColor,
            [switch]$NoNewline,
            [object]$Separator = ' '
        )

        process {
            # A failure here would silence the console for the rest of the
            # session, so nothing in this block is allowed to throw.
            try {
                $text = ''
                if ($null -ne $Object) {
                    $text = ($Object | ForEach-Object { "$_" }) -join "$Separator"
                }

                $colour = 'Gray'
                if ($PSBoundParameters.ContainsKey('ForegroundColor')) { $colour = "$ForegroundColor" }

                # one Write-Host may carry several lines
                $parts = "$text" -split "`r?`n"
                for ($i = 0; $i -lt $parts.Count; $i++) {
                    $global:AuditCaptureCurrent.Add([PSCustomObject]@{ Text = $parts[$i]; Color = $colour })
                    $isLast = ($i -eq $parts.Count - 1)
                    if (-not $isLast -or -not $NoNewline) {
                        $global:AuditCaptureLines.Add(@($global:AuditCaptureCurrent.ToArray()))
                        $global:AuditCaptureCurrent = New-Object System.Collections.Generic.List[object]
                    }
                }
            }
            catch {
                # fall through to the real cmdlet rather than lose the line
                $global:AuditCaptureEcho = $true
            }

            if ($global:AuditCaptureEcho) {
                $fwd = @{}
                foreach ($k in $PSBoundParameters.Keys) { $fwd[$k] = $PSBoundParameters[$k] }
                Microsoft.PowerShell.Utility\Write-Host @fwd
            }
        }
    }

    Set-Item -Path function:global:Write-Host -Value $proxy -Force
}

function Stop-ConsoleCapture {
    <#
        .SYNOPSIS
        Restores the real Write-Host and returns everything captured.
        Safe to call even if capture was never started.
    #>
    [CmdletBinding()]
    param()

    try {
        if ($global:AuditCaptureCurrent -and $global:AuditCaptureCurrent.Count) {
            $global:AuditCaptureLines.Add(@($global:AuditCaptureCurrent.ToArray()))
        }
    }
    catch { }

    $global:AuditCaptureCurrent = New-Object System.Collections.Generic.List[object]
    Remove-Item -Path function:global:Write-Host -Force -ErrorAction SilentlyContinue
    $global:AuditCaptureActive = $false

    $out = @()
    if ($global:AuditCaptureLines) { $out = @($global:AuditCaptureLines.ToArray()) }
    $global:AuditCaptureLines = New-Object System.Collections.Generic.List[object]
    return , $out
}

function Reset-ConsoleCapture {
    <#
        .SYNOPSIS
        Emergency release: removes the proxy whatever state it is in.
        Call this if console output ever goes quiet.
    #>
    [CmdletBinding()]
    param()
    Remove-Item -Path function:global:Write-Host -Force -ErrorAction SilentlyContinue
    $global:AuditCaptureActive = $false
    $global:AuditCaptureLines = New-Object System.Collections.Generic.List[object]
    $global:AuditCaptureCurrent = New-Object System.Collections.Generic.List[object]
}

function Test-ConsoleCapture {
    [CmdletBinding()]
    param()
    return [bool]$global:AuditCaptureActive
}

function Invoke-CapturedScript {
    <#
        .SYNOPSIS
        Runs a script with its console output captured, returning both the
        captured lines and whatever it threw.

        .EXAMPLE
        Invoke-CapturedScript -Path .\Analyze-AdHealth.ps1 `
            -Arguments @{ Path = 'C:\audit\nnn.lo\2026-08-14'; Domain = 'nnn.lo' }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [hashtable]$Arguments = @{},
        [switch]$Echo
    )

    if (-not (Test-Path $Path)) { throw "Script not found: $Path" }

    Start-ConsoleCapture -Echo:$Echo
    $err = $null
    $lines = @()
    try { & $Path @Arguments | Out-Null }
    catch { $err = $_.Exception.Message }
    finally {
        $lines = Stop-ConsoleCapture
        # belt and braces: the proxy must never outlive this call
        if (Test-Path function:global:Write-Host) { Reset-ConsoleCapture }
    }

    return [PSCustomObject]@{
        Lines = $lines
        Error = $err
        Count = @($lines).Count
    }
}

Export-ModuleMember -Function Start-ConsoleCapture, Stop-ConsoleCapture,
    Test-ConsoleCapture, Reset-ConsoleCapture, Invoke-CapturedScript