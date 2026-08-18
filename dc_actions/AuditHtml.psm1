<#
    AuditHtml.psm1

    Builds a single self-contained HTML report from the audit results:
    one tab per domain, a sortable table of findings, and the full console
    output of each analyzer with its colours preserved.

    No external files, no CDN. The report can be copied or mailed as is.

    Usage
        Import-Module .\AuditHtml.psm1

        $report = @(
            [PSCustomObject]@{
                Domain   = 'nnn.lo'
                DataPath = 'C:\audit\nnn.lo\2026-08-14'
                Sections = @(
                    [PSCustomObject]@{ Name = 'Group Policy'; Lines = $gpoLines }
                    [PSCustomObject]@{ Name = 'AD Health';    Lines = $adLines  }
                )
            }
        )
        New-AuditHtmlReport -Report $report -Path C:\audit\report.html
#>

# PowerShell console colours mapped to a palette that stays readable on the
# dark log panel. The classic values are too harsh on a screen.
$script:ColourMap = @{
    'Black'       = '#1b1e24'
    'DarkBlue'    = '#5c7fd6'
    'DarkGreen'   = '#7fb069'
    'DarkCyan'    = '#4fa8b8'
    'DarkRed'     = '#c2554f'
    'DarkMagenta' = '#a878c8'
    'DarkYellow'  = '#c99a4a'
    'Gray'        = '#c8ccd4'
    'DarkGray'    = '#7d8492'
    'Blue'        = '#7aa2f7'
    'Green'       = '#8fd67a'
    'Cyan'        = '#6fd6d6'
    'Red'         = '#ff6b64'
    'Magenta'     = '#ff85d0'
    'Yellow'      = '#ffd479'
    'White'       = '#f4f6fa'
}

function ConvertTo-HtmlText {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;')
}

function ConvertTo-CssClass {
    param([string]$Name)
    return ($Name -replace '[^a-zA-Z0-9]', '-').ToLower()
}

function Get-FindingsForDomain {
    <#
        Collects every findings file produced for a domain and tags each row
        with the toolkit it came from.
    #>
    param([string]$DataPath, [string]$Domain)

    $map = @{
        "$Domain-findings.csv"            = 'Group Policy'
        "$Domain-adhealth-findings.csv"   = 'AD Health'
        "$Domain-adsecurity-findings.csv" = 'AD Security'
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($file in $map.Keys) {
        $full = Join-Path $DataPath $file
        if (-not (Test-Path $full)) { continue }
        try {
            foreach ($r in (Import-Csv $full)) {
                $rows.Add([PSCustomObject]@{
                        Source   = $map[$file]
                        Area     = $r.Area
                        Severity = "$($r.Severity)".ToLower()
                        Item     = $r.Item
                        Detail   = $r.Detail
                    })
            }
        }
        catch { }
    }
    return , @($rows.ToArray())
}

function Compare-FindingSets {
    <#
        Compares two findings sets and returns what appeared, what went
        away and what stayed. Identity is source plus area plus item: the
        detail text often carries a count that moves on its own and would
        otherwise make every row look new.
    #>
    param($Current, $Baseline)

    function Get-Key { param($f) return "$($f.Source)|$($f.Area)|$($f.Item)" }

    $baseKeys = @{}
    foreach ($f in @($Baseline)) { $baseKeys[(Get-Key $f)] = $f }

    $curKeys = @{}
    foreach ($f in @($Current)) { $curKeys[(Get-Key $f)] = $f }

    $new = @()
    $same = @()
    foreach ($f in @($Current)) {
        $k = Get-Key $f
        if ($baseKeys.ContainsKey($k)) { $same += $f } else { $new += $f }
    }

    $gone = @()
    foreach ($f in @($Baseline)) {
        $k = Get-Key $f
        if (-not $curKeys.ContainsKey($k)) { $gone += $f }
    }

    return [PSCustomObject]@{
        New      = @($new)
        Resolved = @($gone)
        Same     = @($same)
        NewKeys  = @($new | ForEach-Object { Get-Key $_ })
    }
}

function Get-MetaForDomain {
    param([string]$DataPath, [string]$Domain)

    $out = [ordered]@{}
    foreach ($f in @("$Domain-meta.csv", "$Domain-adhealth-meta.csv", "$Domain-adsecurity-meta.csv")) {
        $full = Join-Path $DataPath $f
        if (-not (Test-Path $full)) { continue }
        try {
            $row = @(Import-Csv $full)[0]
            foreach ($p in $row.PSObject.Properties) {
                if ($p.Value -and -not $out.Contains($p.Name)) { $out[$p.Name] = $p.Value }
            }
        }
        catch { }
    }
    return $out
}

function ConvertTo-LogHtml {
    param($Lines)

    if (-not $Lines -or @($Lines).Count -eq 0) {
        return '<div class="empty">nothing was captured - the analyzer either produced no output or did not run</div>'
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<pre class="term">')

    foreach ($line in $Lines) {
        foreach ($seg in @($line)) {
            $colour = $script:ColourMap[$seg.Color]
            if (-not $colour) { $colour = $script:ColourMap['Gray'] }
            $text = ConvertTo-HtmlText $seg.Text
            [void]$sb.Append('<span style="color:' + $colour + '">' + $text + '</span>')
        }
        [void]$sb.Append("`n")
    }

    [void]$sb.Append('</pre>')
    return $sb.ToString()
}

function New-AuditHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Report,

        [Parameter(Mandatory = $true)][string]$Path,

        [string]$Title = 'Active Directory audit',
        [switch]$Open
    )

    $generated = Get-Date
    $domains = @($Report)

    # ---------- totals ----------
    $grand = @{ high = 0; medium = 0; low = 0; new = 0; resolved = 0 }
    $prepared = foreach ($d in $domains) {
        $findings = Get-FindingsForDomain -DataPath $d.DataPath -Domain $d.Domain
        $meta = Get-MetaForDomain -DataPath $d.DataPath -Domain $d.Domain
        $counts = @{
            high   = @($findings | Where-Object { $_.Severity -eq 'high' }).Count
            medium = @($findings | Where-Object { $_.Severity -eq 'medium' }).Count
            low    = @($findings | Where-Object { $_.Severity -eq 'low' }).Count
        }
        $grand.high += $counts.high
        $grand.medium += $counts.medium
        $grand.low += $counts.low

        # ---- baseline ----
        $diff = $null
        $baseCounts = $null
        $baseLabel = ''
        $basePath = $null
        if ($d.PSObject.Properties.Name -contains 'BaselinePath') { $basePath = $d.BaselinePath }

        if ($basePath -and (Test-Path $basePath)) {
            $baseFindings = Get-FindingsForDomain -DataPath $basePath -Domain $d.Domain
            if (@($baseFindings).Count -or @($findings).Count) {
                $diff = Compare-FindingSets -Current $findings -Baseline $baseFindings
                $baseCounts = @{
                    high   = @($baseFindings | Where-Object { $_.Severity -eq 'high' }).Count
                    medium = @($baseFindings | Where-Object { $_.Severity -eq 'medium' }).Count
                    low    = @($baseFindings | Where-Object { $_.Severity -eq 'low' }).Count
                }
                $grand.new += @($diff.New).Count
                $grand.resolved += @($diff.Resolved).Count
                $baseLabel = Split-Path $basePath -Leaf
            }
        }

        [PSCustomObject]@{
            Domain     = $d.Domain
            DataPath   = $d.DataPath
            Sections   = $d.Sections
            Findings   = $findings
            Meta       = $meta
            Counts     = $counts
            Diff       = $diff
            BaseCounts = $baseCounts
            BaseLabel  = $baseLabel
        }
    }
    $prepared = @($prepared)

    # ---------- tabs ----------
    $tabs = New-Object System.Text.StringBuilder
    $panels = New-Object System.Text.StringBuilder
    $i = 0

    foreach ($d in $prepared) {
        $id = 'dom-' + (ConvertTo-CssClass $d.Domain)
        $active = if ($i -eq 0) { ' active' } else { '' }

        $badge = ''
        if ($d.Counts.high -gt 0) { $badge = '<span class="tab-badge high">' + $d.Counts.high + '</span>' }
        elseif ($d.Counts.medium -gt 0) { $badge = '<span class="tab-badge medium">' + $d.Counts.medium + '</span>' }

        [void]$tabs.Append('<button class="tab' + $active + '" data-target="' + $id + '">' +
            (ConvertTo-HtmlText $d.Domain) + $badge + '</button>')

        # --- cards, with a delta when a baseline exists ---
        function Get-DeltaHtml {
            param([int]$Now, $Before)
            if ($null -eq $Before) { return '' }
            $delta = $Now - [int]$Before
            if ($delta -eq 0) { return '<span class="delta flat">no change</span>' }
            # fewer findings is an improvement, so down is the good direction
            $cls = if ($delta -lt 0) { 'good' } else { 'bad' }
            $sign = if ($delta -gt 0) { '+' } else { '' }
            return '<span class="delta ' + $cls + '">' + $sign + $delta + '</span>'
        }

        $cards = '<div class="cards">'
        $cards += '<div class="card sev-high"><div class="num">' + $d.Counts.high +
        (Get-DeltaHtml -Now $d.Counts.high -Before $(if ($d.BaseCounts) { $d.BaseCounts.high } else { $null })) +
        '</div><div class="lbl">high</div></div>'
        $cards += '<div class="card sev-medium"><div class="num">' + $d.Counts.medium +
        (Get-DeltaHtml -Now $d.Counts.medium -Before $(if ($d.BaseCounts) { $d.BaseCounts.medium } else { $null })) +
        '</div><div class="lbl">medium</div></div>'
        $cards += '<div class="card sev-low"><div class="num">' + $d.Counts.low +
        (Get-DeltaHtml -Now $d.Counts.low -Before $(if ($d.BaseCounts) { $d.BaseCounts.low } else { $null })) +
        '</div><div class="lbl">low</div></div>'

        $warnTotal = 0
        foreach ($sec in @($d.Sections)) {
            if ($sec.PSObject.Properties.Name -contains 'Warnings') { $warnTotal += @($sec.Warnings).Count }
        }
        if ($warnTotal) {
            $cards += '<div class="card sev-medium"><div class="num">' + $warnTotal +
            '</div><div class="lbl">warnings</div></div>'
        }

        foreach ($k in @('DcCount', 'GpoCount', 'ComputerCount', 'PrivEntries')) {
            if ($d.Meta.Contains($k)) {
                $label = switch ($k) {
                    'DcCount' { 'controllers' }
                    'GpoCount' { 'policies' }
                    'ComputerCount' { 'computers' }
                    'PrivEntries' { 'priv. entries' }
                }
                $cards += '<div class="card plain"><div class="num">' + (ConvertTo-HtmlText $d.Meta[$k]) +
                '</div><div class="lbl">' + $label + '</div></div>'
            }
        }
        $cards += '</div>'

        # --- meta strip ---
        $metaBits = @()
        foreach ($k in @('Server', 'CollectedAt', 'CollectedBy')) {
            if ($d.Meta.Contains($k)) { $metaBits += (ConvertTo-HtmlText $d.Meta[$k]) }
        }
        $metaLine = ''
        if ($metaBits.Count) { $metaLine = '<div class="meta">' + ($metaBits -join ' &middot; ') + '</div>' }

        # --- what changed since the baseline ---
        $changes = ''
        if ($d.Diff) {
            $newCount = @($d.Diff.New).Count
            $goneCount = @($d.Diff.Resolved).Count

            $verdict = 'nothing changed'
            $verdictCls = 'flat'
            if ($newCount -and $goneCount) { $verdict = "$newCount new, $goneCount resolved"; $verdictCls = 'mixed' }
            elseif ($newCount) { $verdict = "$newCount new"; $verdictCls = 'bad' }
            elseif ($goneCount) { $verdict = "$goneCount resolved"; $verdictCls = 'good' }

            $changes = '<div class="changes ' + $verdictCls + '">'
            $changes += '<div class="changes-head"><span class="changes-verdict">' + $verdict + '</span>'
            $changes += '<span class="changes-base">since ' + (ConvertTo-HtmlText $d.BaseLabel) + '</span></div>'

            if ($newCount -or $goneCount) {
                $changes += '<div class="changes-body">'

                if ($newCount) {
                    $changes += '<div class="changes-col"><h4 class="new">appeared</h4><ul>'
                    foreach ($f in (@($d.Diff.New) | Sort-Object @{ E = { @{ high = 0; medium = 1; low = 2 }["$($_.Severity)"] } } | Select-Object -First 15)) {
                        $changes += '<li><span class="pill ' + $f.Severity + '">' + $f.Severity + '</span> ' +
                        (ConvertTo-HtmlText $f.Item) + ' <em>' + (ConvertTo-HtmlText $f.Area) + '</em></li>'
                    }
                    if ($newCount -gt 15) { $changes += '<li class="more">... and ' + ($newCount - 15) + ' more</li>' }
                    $changes += '</ul></div>'
                }

                if ($goneCount) {
                    $changes += '<div class="changes-col"><h4 class="gone">resolved</h4><ul>'
                    foreach ($f in (@($d.Diff.Resolved) | Select-Object -First 15)) {
                        $changes += '<li><span class="pill ' + $f.Severity + '">' + $f.Severity + '</span> ' +
                        (ConvertTo-HtmlText $f.Item) + ' <em>' + (ConvertTo-HtmlText $f.Area) + '</em></li>'
                    }
                    if ($goneCount -gt 15) { $changes += '<li class="more">... and ' + ($goneCount - 15) + ' more</li>' }
                    $changes += '</ul></div>'
                }

                $changes += '</div>'
            }
            $changes += '</div>'
        }
        elseif ($d.BaseLabel) {
            $changes = '<div class="changes flat"><div class="changes-head">' +
            '<span class="changes-verdict">no comparable baseline</span></div></div>'
        }

        # ---------------------------------------------------------------
        # Findings, grouped into collapsed accordions by area.
        #
        # Six domains with several hundred findings between them is not
        # something anyone reads as one long table. Everything starts shut;
        # the header of each group carries enough to decide whether to open
        # it. Filtering opens the groups that still have matches.
        # ---------------------------------------------------------------
        $table = ''
        if (@($d.Findings).Count) {
            $sevRank = @{ 'high' = 0; 'medium' = 1; 'low' = 2 }

            $newKeys = @()
            if ($d.Diff) { $newKeys = @($d.Diff.NewKeys) }

            # areas ordered by worst severity first, then by size
            $groups = $d.Findings | Group-Object Area | Sort-Object `
            @{ E = { ($_.Group | ForEach-Object { $sevRank["$($_.Severity)"] } | Measure-Object -Minimum).Minimum } },
            @{ E = { - $_.Count } },
            Name

            $acc = New-Object System.Text.StringBuilder

            foreach ($g in $groups) {
                $gHigh = @($g.Group | Where-Object { $_.Severity -eq 'high' }).Count
                $gMed = @($g.Group | Where-Object { $_.Severity -eq 'medium' }).Count
                $gLow = @($g.Group | Where-Object { $_.Severity -eq 'low' }).Count
                $gNew = @($g.Group | Where-Object { $newKeys -contains "$($_.Source)|$($_.Area)|$($_.Item)" }).Count

                $badges = ''
                if ($gHigh) { $badges += '<span class="pill high">' + $gHigh + '</span>' }
                if ($gMed) { $badges += '<span class="pill medium">' + $gMed + '</span>' }
                if ($gLow) { $badges += '<span class="pill low">' + $gLow + '</span>' }
                if ($gNew) { $badges += '<span class="pill new">' + $gNew + ' new</span>' }

                [void]$acc.Append('<details class="area"><summary>')
                [void]$acc.Append('<span class="area-name">' + (ConvertTo-HtmlText $g.Name) + '</span>')
                [void]$acc.Append('<span class="area-badges">' + $badges + '</span>')
                [void]$acc.Append('<span class="area-count">' + $g.Count + '</span>')
                [void]$acc.Append('</summary>')

                [void]$acc.Append('<table class="findings"><tbody>')

                $ordered = $g.Group | Sort-Object @{ E = { $sevRank["$($_.Severity)"] } }, Source, Item
                foreach ($f in $ordered) {
                    $key = "$($f.Source)|$($f.Area)|$($f.Item)"
                    $isNew = ($newKeys -contains $key)
                    $rowCls = if ($isNew) { ' class="is-new"' } else { '' }

                    [void]$acc.Append('<tr data-sev="' + $f.Severity + '" data-new="' +
                        $(if ($isNew) { '1' } else { '0' }) + '"' + $rowCls + '>')
                    [void]$acc.Append('<td class="c-sev"><span class="pill ' + $f.Severity + '">' + $f.Severity + '</span>' +
                        $(if ($isNew) { '<span class="pill new">new</span>' } else { '' }) + '</td>')
                    [void]$acc.Append('<td class="src">' + (ConvertTo-HtmlText $f.Source) + '</td>')
                    [void]$acc.Append('<td class="item">' + (ConvertTo-HtmlText $f.Item) + '</td>')
                    [void]$acc.Append('<td class="detail">' + (ConvertTo-HtmlText $f.Detail) + '</td>')
                    [void]$acc.Append('</tr>')
                }

                [void]$acc.Append('</tbody></table></details>')
            }

            $newChip = ''
            if ($d.Diff -and @($d.Diff.New).Count) {
                $newChip = '<button class="chip newonly" data-newonly="1">new only</button>'
            }

            $table = '<div class="toolbar">' +
            '<input type="search" class="filter" placeholder="filter findings...">' +
            '<div class="chips">' +
            '<button class="chip on" data-sev="high">high</button>' +
            '<button class="chip on" data-sev="medium">medium</button>' +
            '<button class="chip" data-sev="low">low</button>' +
            $newChip +
            '</div>' +
            '<div class="acc-ctl">' +
            '<button class="linkbtn expand-all">expand all</button>' +
            '<button class="linkbtn collapse-all">collapse all</button>' +
            '</div>' +
            '<span class="shown"></span></div>' +
            '<div class="areas">' + $acc.ToString() + '</div>'
        }
        else {
            $table = '<div class="empty">no findings recorded</div>'
        }

        # --- logs ---
        $logs = '<h3 class="logs-title">Analyzer output</h3>'
        foreach ($sec in @($d.Sections)) {
            $warnCount = 0
            if ($sec.PSObject.Properties.Name -contains 'Warnings') { $warnCount = @($sec.Warnings).Count }

            $tag = ''
            if ($sec.PSObject.Properties.Name -contains 'Error' -and $sec.Error) {
                $tag = '<span class="sec-tag err">failed</span>'
            }
            elseif ($warnCount) {
                $tag = '<span class="sec-tag warn">' + $warnCount + ' warning' +
                $(if ($warnCount -gt 1) { 's' } else { '' }) + '</span>'
            }

            $lineCount = @($sec.Lines).Count
            $tag += '<span class="sec-count">' + $lineCount + ' lines</span>'

            $logs += '<details class="logbox"><summary>' + (ConvertTo-HtmlText $sec.Name) + $tag + '</summary>'

            if ($sec.PSObject.Properties.Name -contains 'Error' -and $sec.Error) {
                $logs += '<div class="secmsg err">' + (ConvertTo-HtmlText $sec.Error) + '</div>'
            }
            if ($warnCount) {
                $logs += '<div class="secmsg warn"><b>' + $warnCount + ' warning(s)</b><ul>'
                foreach ($w in (@($sec.Warnings) | Select-Object -First 12)) {
                    $logs += '<li>' + (ConvertTo-HtmlText $w) + '</li>'
                }
                if ($warnCount -gt 12) { $logs += '<li>... and ' + ($warnCount - 12) + ' more</li>' }
                $logs += '</ul></div>'
            }

            $logs += (ConvertTo-LogHtml $sec.Lines)
            $logs += '</details>'
        }
        if (-not @($d.Sections).Count) {
            $logs += '<div class="empty">no analyzer output was captured for this domain</div>'
        }

        [void]$panels.Append('<section class="panel' + $active + '" id="' + $id + '">' +
            $metaLine + $cards + $changes + $table + $logs + '</section>')
        $i++
    }

    # ---------- assemble ----------
    $css = @'
:root{
  --bg:#f5f6f8; --surface:#ffffff; --line:#e3e6ec; --ink:#1c2030; --ink-soft:#5b6376;
  --high:#d64545; --medium:#c98a1e; --low:#6b7280; --accent:#3a6ff7;
  --term-bg:#1b1e24;
  --font-ui:"Segoe UI Variable Text","Segoe UI",-apple-system,BlinkMacSystemFont,Inter,system-ui,sans-serif;
  --font-mono:"Cascadia Mono","Cascadia Code",ui-monospace,"JetBrains Mono",Consolas,"Courier New",monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--font-ui);
  font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
header{background:var(--surface);border-bottom:1px solid var(--line);padding:22px 28px 0}
h1{margin:0 0 4px;font-size:20px;font-weight:600;letter-spacing:-.01em}
.sub{color:var(--ink-soft);font-size:13px;margin-bottom:16px}
.totals{display:flex;gap:18px;margin-bottom:16px;flex-wrap:wrap}
.total{display:flex;align-items:baseline;gap:6px;font-size:13px;color:var(--ink-soft)}
.total b{font-size:17px;font-weight:600;color:var(--ink)}
.total.high b{color:var(--high)} .total.medium b{color:var(--medium)}
.tabs{display:flex;gap:2px;overflow-x:auto;padding-bottom:0}
.tab{appearance:none;border:0;background:transparent;font:inherit;color:var(--ink-soft);
  padding:9px 16px;border-radius:8px 8px 0 0;cursor:pointer;white-space:nowrap;
  border-bottom:2px solid transparent;display:flex;align-items:center;gap:7px}
.tab:hover{background:#eef1f6;color:var(--ink)}
.tab.active{color:var(--ink);font-weight:600;border-bottom-color:var(--accent);background:var(--bg)}
.tab-badge{font-size:11px;font-weight:600;padding:1px 6px;border-radius:9px;color:#fff}
.tab-badge.high{background:var(--high)} .tab-badge.medium{background:var(--medium)}
main{padding:22px 28px 60px;max-width:1500px}
.panel{display:none} .panel.active{display:block}
.meta{color:var(--ink-soft);font-size:12.5px;margin-bottom:14px;font-family:var(--font-mono)}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:10px;
  padding:12px 18px;min-width:96px}
.card .num{font-size:24px;font-weight:600;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.card .lbl{font-size:11.5px;color:var(--ink-soft);text-transform:uppercase;letter-spacing:.06em}
.card.sev-high .num{color:var(--high)} .card.sev-medium .num{color:var(--medium)}
.card.sev-low .num{color:var(--low)}
.toolbar{display:flex;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap}
.filter{flex:1;min-width:220px;max-width:420px;padding:8px 12px;border:1px solid var(--line);
  border-radius:8px;font:inherit;background:var(--surface)}
.filter:focus{outline:2px solid var(--accent);outline-offset:-1px;border-color:transparent}
.chips{display:flex;gap:6px}
.chip{appearance:none;border:1px solid var(--line);background:var(--surface);font:inherit;
  font-size:12.5px;padding:5px 12px;border-radius:20px;cursor:pointer;color:var(--ink-soft)}
.chip.on{background:var(--ink);color:#fff;border-color:var(--ink)}
.shown{color:var(--ink-soft);font-size:12.5px;margin-left:auto}
/* findings grouped by area */
.areas{display:flex;flex-direction:column;gap:8px}
details.area{background:var(--surface);border:1px solid var(--line);border-radius:10px;overflow:hidden}
details.area>summary{display:flex;align-items:center;gap:12px;padding:11px 16px;cursor:pointer;
  list-style:none;user-select:none}
details.area>summary::-webkit-details-marker{display:none}
details.area>summary::before{content:"";flex:0 0 auto;border:solid var(--ink-soft);
  border-width:0 1.5px 1.5px 0;padding:3px;transform:rotate(-45deg);transition:transform .15s}
details.area[open]>summary::before{transform:rotate(45deg)}
details.area>summary:hover{background:#f7f9fc}
details.area[open]>summary{border-bottom:1px solid var(--line);background:#fafbfc}
.area-name{font-weight:600;font-size:13.5px}
.area-badges{display:flex;gap:4px;align-items:center}
.area-count{margin-left:auto;font-size:12px;color:var(--ink-soft);font-family:var(--font-mono);
  font-variant-numeric:tabular-nums}
.acc-ctl{display:flex;gap:10px}
.linkbtn{appearance:none;border:0;background:none;font:inherit;font-size:12.5px;
  color:var(--accent);cursor:pointer;padding:0}
.linkbtn:hover{text-decoration:underline}

table.findings{width:100%;border-collapse:collapse}
table.findings td{padding:8px 16px;border-bottom:1px solid #f0f2f5;vertical-align:top}
table.findings tr:last-child td{border-bottom:0}
table.findings tbody tr:hover{background:#f7f9fc}
td.c-sev{white-space:nowrap;width:1%}
.pill{display:inline-block;font-size:11px;font-weight:600;padding:2px 9px;border-radius:20px;
  text-transform:uppercase;letter-spacing:.04em}
.pill.high{background:#fdecec;color:var(--high)}
.pill.medium{background:#fdf3e2;color:var(--medium)}
.pill.low{background:#f1f2f4;color:var(--low)}
td.src{color:var(--ink-soft);white-space:nowrap;font-size:13px}
td.item{font-family:var(--font-mono);font-size:12.5px}
td.detail{color:var(--ink-soft);font-size:13px}
.logs-title{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--ink-soft);
  margin:28px 0 10px;font-weight:600}
.logbox{background:var(--surface);border:1px solid var(--line);border-radius:10px;
  margin-bottom:10px;overflow:hidden}
.logbox summary{padding:11px 16px;cursor:pointer;font-weight:600;font-size:13.5px;
  list-style:none;display:flex;align-items:center;gap:8px}
.logbox summary::-webkit-details-marker{display:none}
.logbox summary::before{content:"";border:solid var(--ink-soft);border-width:0 1.5px 1.5px 0;
  padding:3px;transform:rotate(-45deg);transition:transform .15s}
.logbox[open] summary::before{transform:rotate(45deg)}
.logbox summary:hover{background:#f7f9fc}
pre.term{margin:0;background:var(--term-bg);color:#c8ccd4;padding:16px 18px;overflow-x:auto;
  font-family:var(--font-mono);font-size:12.5px;line-height:1.45;tab-size:4}
.empty{color:var(--ink-soft);font-style:italic;padding:14px 0}
.sec-tag{font-size:11px;font-weight:600;padding:2px 8px;border-radius:20px;margin-left:6px}
.sec-tag.warn{background:#fdf3e2;color:var(--medium)}
.sec-tag.err{background:#fdecec;color:var(--high)}
.sec-count{margin-left:auto;font-size:11.5px;font-weight:400;color:var(--ink-soft);
  font-family:var(--font-mono)}
.secmsg{padding:10px 16px;font-size:13px;border-top:1px solid var(--line)}
.secmsg.warn{background:#fffaf0;color:#8a5f10}
.secmsg.err{background:#fff5f5;color:#8f2d2d}
.secmsg ul{margin:6px 0 0;padding-left:20px}
.secmsg li{margin:2px 0;font-family:var(--font-mono);font-size:12px}

/* baseline comparison */
.delta{font-size:12px;font-weight:600;margin-left:8px;vertical-align:middle;
  padding:1px 7px;border-radius:20px;letter-spacing:0}
.delta.good{background:#e8f6ec;color:#1e7a3c}
.delta.bad{background:#fdecec;color:var(--high)}
.delta.flat{background:#f1f2f4;color:var(--ink-soft);font-weight:500}
.total.sep{margin-left:10px;padding-left:16px;border-left:1px solid var(--line);gap:8px}
.changes{background:var(--surface);border:1px solid var(--line);border-radius:10px;
  margin-bottom:20px;overflow:hidden;border-left-width:3px}
.changes.good{border-left-color:#3fa45f}
.changes.bad{border-left-color:var(--high)}
.changes.mixed{border-left-color:var(--medium)}
.changes.flat{border-left-color:var(--line)}
.changes-head{display:flex;align-items:baseline;gap:12px;padding:12px 18px}
.changes-verdict{font-weight:600;font-size:14px}
.changes-base{color:var(--ink-soft);font-size:12.5px;font-family:var(--font-mono)}
.changes-body{display:flex;gap:0;border-top:1px solid var(--line);flex-wrap:wrap}
.changes-col{flex:1;min-width:280px;padding:12px 18px 16px}
.changes-col+.changes-col{border-left:1px solid var(--line)}
.changes-col h4{margin:0 0 8px;font-size:11.5px;text-transform:uppercase;
  letter-spacing:.06em;font-weight:600}
.changes-col h4.new{color:var(--high)}
.changes-col h4.gone{color:#1e7a3c}
.changes-col ul{margin:0;padding:0;list-style:none}
.changes-col li{padding:3px 0;font-size:13px;line-height:1.45}
.changes-col li em{color:var(--ink-soft);font-style:normal;font-size:12px}
.changes-col li.more{color:var(--ink-soft);font-style:italic;padding-top:6px}
.pill.new{background:#eef2ff;color:#3a4fb8;margin-left:5px}
tr.is-new td:first-child{box-shadow:inset 3px 0 0 var(--high)}
.chip.newonly.on{background:#3a4fb8;border-color:#3a4fb8}
@media print{
  .tabs,.toolbar{display:none}
  .panel{display:block!important;page-break-after:always}
  .logbox{page-break-inside:avoid}
  details.area{page-break-inside:avoid}
  details.area>summary::before{display:none}
  /* paper has no toggles, so everything is shown */
  details.area>table.findings{display:table!important}
}
'@

    $js = @'
(function(){
  var tabs = document.querySelectorAll('.tab');
  tabs.forEach(function(t){
    t.addEventListener('click', function(){
      document.querySelectorAll('.tab').forEach(function(x){ x.classList.remove('active'); });
      document.querySelectorAll('.panel').forEach(function(x){ x.classList.remove('active'); });
      t.classList.add('active');
      var p = document.getElementById(t.dataset.target);
      if (p) { p.classList.add('active'); }
      location.hash = t.dataset.target;
    });
  });

  if (location.hash) {
    var want = document.querySelector('.tab[data-target="' + location.hash.slice(1) + '"]');
    if (want) { want.click(); }
  }

  document.querySelectorAll('.panel').forEach(function(panel){
    var input  = panel.querySelector('.filter');
    var chips  = panel.querySelectorAll('.chip');
    var rows   = panel.querySelectorAll('.area table.findings tbody tr');
    var areas  = panel.querySelectorAll('details.area');
    var shown  = panel.querySelector('.shown');
    var expand = panel.querySelector('.expand-all');
    var close  = panel.querySelector('.collapse-all');
    if (!rows.length) { return; }

    // remembers what the reader opened, so filtering does not fight them
    var manual = {};
    areas.forEach(function(a, i){
      a.dataset.idx = i;
      a.addEventListener('toggle', function(){
        if (!filtering) { manual[i] = a.open; }
      });
    });
    var filtering = false;

    function apply(){
      var q = (input && input.value ? input.value : '').toLowerCase();
      var allow = {};
      var newOnly = false;
      chips.forEach(function(c){
        if (c.dataset.newonly) { newOnly = c.classList.contains('on'); }
        else { allow[c.dataset.sev] = c.classList.contains('on'); }
      });

      var narrowed = (q.length > 0) || newOnly;
      var total = 0;

      filtering = true;
      areas.forEach(function(area){
        var visible = 0;
        area.querySelectorAll('tbody tr').forEach(function(r){
          var okSev = allow[r.dataset.sev];
          var okTxt = !q || r.textContent.toLowerCase().indexOf(q) !== -1;
          var okNew = !newOnly || r.dataset.new === '1';
          var vis = okSev && okTxt && okNew;
          r.style.display = vis ? '' : 'none';
          if (vis) { visible++; }
        });

        total += visible;

        // an area with nothing left to show is taken off the page entirely
        area.style.display = visible ? '' : 'none';

        var badge = area.querySelector('.area-count');
        if (badge) { badge.textContent = narrowed ? visible : area.querySelectorAll('tbody tr').length; }

        // open what matches while narrowing, restore the reader's choice
        // once the filter is cleared
        if (narrowed) { area.open = visible > 0; }
        else { area.open = !!manual[area.dataset.idx]; }
      });
      filtering = false;

      if (shown) { shown.textContent = total + ' of ' + rows.length + ' shown'; }
    }

    if (input) { input.addEventListener('input', apply); }
    chips.forEach(function(c){
      c.addEventListener('click', function(){ c.classList.toggle('on'); apply(); });
    });
    if (expand) {
      expand.addEventListener('click', function(){
        areas.forEach(function(a){
          if (a.style.display !== 'none') { a.open = true; manual[a.dataset.idx] = true; }
        });
      });
    }
    if (close) {
      close.addEventListener('click', function(){
        areas.forEach(function(a){ a.open = false; manual[a.dataset.idx] = false; });
      });
    }
    apply();
  });
})();
'@

    $head = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + (ConvertTo-HtmlText $Title) + '</title><style>' + $css + '</style></head><body>'

    $grandWarn = 0
    foreach ($d in $prepared) {
        foreach ($sec in @($d.Sections)) {
            if ($sec.PSObject.Properties.Name -contains 'Warnings') { $grandWarn += @($sec.Warnings).Count }
        }
    }

    $totals = '<div class="totals">' +
    '<div class="total high"><b>' + $grand.high + '</b> high</div>' +
    '<div class="total medium"><b>' + $grand.medium + '</b> medium</div>' +
    '<div class="total"><b>' + $grand.low + '</b> low</div>' +
    '<div class="total"><b>' + $prepared.Count + '</b> domains</div>'
    if ($grandWarn) {
        $totals += '<div class="total medium"><b>' + $grandWarn + '</b> warnings</div>'
    }
    if ($grand.new -or $grand.resolved) {
        $totals += '<div class="total sep">'
        if ($grand.new) { $totals += '<span class="delta bad">+' + $grand.new + ' new</span>' }
        if ($grand.resolved) { $totals += '<span class="delta good">-' + $grand.resolved + ' resolved</span>' }
        $totals += '</div>'
    }
    $totals += '</div>'

    $header = '<header><h1>' + (ConvertTo-HtmlText $Title) + '</h1>' +
    '<div class="sub">generated ' + $generated.ToString('yyyy-MM-dd HH:mm') +
    ' on ' + (ConvertTo-HtmlText $env:COMPUTERNAME) + '</div>' +
    $totals + '<nav class="tabs">' + $tabs.ToString() + '</nav></header>'

    $html = $head + $header + '<main>' + $panels.ToString() + '</main>' +
    '<script>' + $js + '</script></body></html>'

    $dir = Split-Path $Path -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $enc = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText($Path, $html, $enc)

    if ($Open) { Start-Process $Path }

    return [PSCustomObject]@{
        Path     = $Path
        Domains  = $prepared.Count
        High     = $grand.high
        Medium   = $grand.medium
        Low      = $grand.low
        Warnings = $grandWarn
        New      = $grand.new
        Resolved = $grand.resolved
        SizeKb   = [math]::Round((Get-Item $Path).Length / 1KB, 1)
    }
}

Export-ModuleMember -Function New-AuditHtmlReport