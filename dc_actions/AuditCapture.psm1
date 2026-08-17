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

$script:Lines = New-Object System.Collections.Generic.List[object]
$script:Current = New-Object System.Collections.Generic.List[object]
$script:Echo = $false
$script:Active = $false

function Add-CapturedSegment {
    param(
        [string]$Text,
        [string]$Color,
        [switch]$NoNewline
    )

    # A single Write-Host may carry embedded newlines; split so the report
    # keeps one line per line rather than one blob per call.
    $parts = "$Text" -split "`r?`n"

    for ($i = 0; $i -lt $parts.Count; $i++) {
        $script:Current.Add([PSCustomObject]@{ Text = $parts[$i]; Color = $Color })
        $isLast = ($i -eq $parts.Count - 1)
        if (-not $isLast -or -not $NoNewline) {
            $script:Lines.Add(@($script:Current.ToArray()))
            $script:Current = New-Object System.Collections.Generic.List[object]
        }
    }
}

function Start-ConsoleCapture {
    <#
        .SYNOPSIS
        Redirects Write-Host into a buffer until Stop-ConsoleCapture.

        .PARAMETER Echo
        Also print to the console, for debugging the capture itself.
    #>
    [CmdletBinding()]
    param([switch]$Echo)

    if ($script:Active) { Stop-ConsoleCapture | Out-Null }

    $script:Lines = New-Object System.Collections.Generic.List[object]
    $script:Current = New-Object System.Collections.Generic.List[object]
    $script:Echo = [bool]$Echo
    $script:Active = $true

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
            $text = ''
            if ($null -ne $Object) {
                $text = ($Object | ForEach-Object { "$_" }) -join "$Separator"
            }

            $colour = 'Gray'
            if ($PSBoundParameters.ContainsKey('ForegroundColor')) { $colour = "$ForegroundColor" }

            Add-CapturedSegment -Text $text -Color $colour -NoNewline:$NoNewline

            if ($script:Echo) {
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
    #>
    [CmdletBinding()]
    param()

    if ($script:Current.Count) {
        $script:Lines.Add(@($script:Current.ToArray()))
        $script:Current = New-Object System.Collections.Generic.List[object]
    }

    Remove-Item -Path function:global:Write-Host -Force -ErrorAction SilentlyContinue
    $script:Active = $false

    $out = @($script:Lines.ToArray())
    $script:Lines = New-Object System.Collections.Generic.List[object]
    return , $out
}

function Test-ConsoleCapture {
    [CmdletBinding()]
    param()
    return $script:Active
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
    try { & $Path @Arguments | Out-Null }
    catch { $err = $_.Exception.Message }
    finally { $lines = Stop-ConsoleCapture }

    return [PSCustomObject]@{
        Lines = $lines
        Error = $err
    }
}

Export-ModuleMember -Function Start-ConsoleCapture, Stop-ConsoleCapture,
    Test-ConsoleCapture, Invoke-CapturedScript