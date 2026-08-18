<#
    AuditCapture.psm1

    Captures the console output of a script, keeping the colour of every
    fragment, so it can be rendered into a report instead of scrolling past.

    How it works
        In Windows PowerShell 5 Write-Host writes to the information stream.
        Redirecting that stream into the pipeline with 6>&1 yields
        InformationRecord objects whose MessageData is a
        HostInformationMessage carrying Message, ForegroundColor,
        BackgroundColor and NoNewLine.

        Nothing is overridden and no global state is touched, so a failure
        here can never silence the console for the rest of the session.
        An earlier version replaced Write-Host with a proxy function and did
        exactly that whenever anything went wrong.

    Usage
        Import-Module .\AuditCapture.psm1
        $r = Invoke-CapturedScript -Path .\Analyze-AdHealth.ps1 `
                -Arguments @{ Path = 'C:\audit\nnn.lo\2026-08-17'; Domain = 'nnn.lo' }
        $r.Lines    # array of lines, each an array of @{ Text; Color }
        $r.Warnings # warning stream, separately
        $r.Error    # message if the script threw
#>

function ConvertFrom-InformationRecords {
    <#
        Turns a stream of records into lines of coloured segments,
        honouring NoNewLine so multi-colour lines stay on one line.
    #>
    param($Records)

    $lines = New-Object System.Collections.Generic.List[object]
    $current = New-Object System.Collections.Generic.List[object]

    foreach ($rec in @($Records)) {
        if ($null -eq $rec) { continue }

        $text = $null
        $colour = 'Gray'
        $noNewline = $false

        $data = $null
        if ($rec -is [System.Management.Automation.InformationRecord]) { $data = $rec.MessageData }
        else { $data = $rec }

        if ($null -eq $data) { continue }

        # Write-Host produces this type; Write-Information produces a string
        if ($data.GetType().Name -eq 'HostInformationMessage') {
            $text = "$($data.Message)"
            if ($null -ne $data.ForegroundColor) { $colour = "$($data.ForegroundColor)" }
            if ($null -ne $data.NoNewLine) { $noNewline = [bool]$data.NoNewLine }
        }
        else {
            $text = "$data"
        }

        # a single call may still carry embedded newlines
        $parts = "$text" -split "`r?`n"
        for ($i = 0; $i -lt $parts.Count; $i++) {
            $current.Add([PSCustomObject]@{ Text = $parts[$i]; Color = $colour })
            $isLast = ($i -eq $parts.Count - 1)
            if (-not $isLast -or -not $noNewline) {
                $lines.Add(@($current.ToArray()))
                $current = New-Object System.Collections.Generic.List[object]
            }
        }
    }

    if ($current.Count) { $lines.Add(@($current.ToArray())) }
    return , @($lines.ToArray())
}

function Invoke-CapturedScript {
    <#
        .SYNOPSIS
        Runs a script with its console output captured rather than printed.

        .PARAMETER Echo
        Also print the captured output, for debugging.

        .EXAMPLE
        Invoke-CapturedScript -Path .\Analyze-AdHealth.ps1 `
            -Arguments @{ Path = 'C:\audit\nnn.lo\2026-08-17'; Domain = 'nnn.lo' }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [hashtable]$Arguments = @{},
        [switch]$Echo
    )

    if (-not (Test-Path $Path)) { throw "Script not found: $Path" }

    $err = $null
    $records = @()
    $warnings = @()

    try {
        # 6>&1 folds the information stream into the pipeline, 3>&1 the
        # warnings; both then arrive as objects instead of hitting the host
        $records = & $Path @Arguments 6>&1 3>&1
    }
    catch {
        $err = $_.Exception.Message
    }

    $info = @()
    foreach ($r in @($records)) {
        if ($r -is [System.Management.Automation.WarningRecord]) {
            $warnings += "$($r.Message)"
            $info += [System.Management.Automation.HostInformationMessage]@{
                Message         = "WARNING: $($r.Message)"
                ForegroundColor = [System.ConsoleColor]::Yellow
            }
        }
        elseif ($r -is [System.Management.Automation.InformationRecord]) { $info += $r }
        elseif ($r -is [System.Management.Automation.ErrorRecord]) {
            $info += [System.Management.Automation.HostInformationMessage]@{
                Message         = "ERROR: $($r.Exception.Message)"
                ForegroundColor = [System.ConsoleColor]::Red
            }
        }
        # anything else is ordinary pipeline output and is dropped: the
        # analyzers return nothing useful, they only print
    }

    $lines = ConvertFrom-InformationRecords -Records $info

    if ($Echo) {
        foreach ($line in $lines) {
            foreach ($seg in @($line)) {
                Microsoft.PowerShell.Utility\Write-Host $seg.Text -ForegroundColor $seg.Color -NoNewline
            }
            Microsoft.PowerShell.Utility\Write-Host ''
        }
    }

    return [PSCustomObject]@{
        Lines    = $lines
        Warnings = @($warnings)
        Error    = $err
        Count    = @($lines).Count
    }
}

function Reset-ConsoleCapture {
    <#
        .SYNOPSIS
        Removes a Write-Host proxy left behind by an older version of this
        module. Harmless to call at any time.
    #>
    [CmdletBinding()]
    param()
    if (Test-Path function:global:Write-Host) {
        Remove-Item -Path function:global:Write-Host -Force -ErrorAction SilentlyContinue
        Write-Verbose 'Removed a leftover Write-Host proxy.'
    }
}

Export-ModuleMember -Function Invoke-CapturedScript, ConvertFrom-InformationRecords, Reset-ConsoleCapture