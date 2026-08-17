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
    $grand = @{ high = 0; medium = 0; low = 0 }
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

        [PSCustomObject]@{
            Domain   = $d.Domain
            DataPath = $d.DataPath
            Sections = $d.Sections
            Findings = $findings
            Meta     = $meta
            Counts   = $counts
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

        # --- cards ---
        $cards = '<div class="cards">'
        $cards += '<div class="card sev-high"><div class="num">' + $d.Counts.high + '</div><div class="lbl">high</div></div>'
        $cards += '<div class="card sev-medium"><div class="num">' + $d.Counts.medium + '</div><div class="lbl">medium</div></div>'
        $cards += '<div class="card sev-low"><div class="num">' + $d.Counts.low + '</div><div class="lbl">low</div></div>'

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

        # --- findings table ---
        $table = ''
        if (@($d.Findings).Count) {
            $order = @{ 'high' = 0; 'medium' = 1; 'low' = 2 }
            $sorted = $d.Findings | Sort-Object @{ E = { $order["$($_.Severity)"] } }, Source, Area, Item

            $rows = New-Object System.Text.StringBuilder
            foreach ($f in $sorted) {
                [void]$rows.Append('<tr data-sev="' + $f.Severity + '">')
                [void]$rows.Append('<td><span class="pill ' + $f.Severity + '">' + $f.Severity + '</span></td>')
                [void]$rows.Append('<td class="src">' + (ConvertTo-HtmlText $f.Source) + '</td>')
                [void]$rows.Append('<td>' + (ConvertTo-HtmlText $f.Area) + '</td>')
                [void]$rows.Append('<td class="item">' + (ConvertTo-HtmlText $f.Item) + '</td>')
                [void]$rows.Append('<td class="detail">' + (ConvertTo-HtmlText $f.Detail) + '</td>')
                [void]$rows.Append('</tr>')
            }

            $table = @'
<div class="toolbar">
  <input type="search" class="filter" placeholder="filter findings...">
  <div class="chips">
    <button class="chip on" data-sev="high">high</button>
    <button class="chip on" data-sev="medium">medium</button>
    <button class="chip" data-sev="low">low</button>
  </div>
  <span class="shown"></span>
</div>
<div class="tablewrap">
<table class="findings">
  <thead><tr><th>severity</th><th>source</th><th>area</th><th>item</th><th>detail</th></tr></thead>
  <tbody>
'@
            $table += $rows.ToString()
            $table += '</tbody></table></div>'
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
            $metaLine + $cards + $table + $logs + '</section>')
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
.tablewrap{background:var(--surface);border:1px solid var(--line);border-radius:10px;overflow:hidden}
table.findings{width:100%;border-collapse:collapse}
table.findings th{text-align:left;font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;
  color:var(--ink-soft);font-weight:600;padding:10px 14px;border-bottom:1px solid var(--line);
  background:#fafbfc;position:sticky;top:0}
table.findings td{padding:9px 14px;border-bottom:1px solid #f0f2f5;vertical-align:top}
table.findings tr:last-child td{border-bottom:0}
table.findings tbody tr:hover{background:#f7f9fc}
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
@media print{
  .tabs,.toolbar{display:none}
  .panel{display:block!important;page-break-after:always}
  .logbox{page-break-inside:avoid}
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
    var input = panel.querySelector('.filter');
    var chips = panel.querySelectorAll('.chip');
    var rows  = panel.querySelectorAll('table.findings tbody tr');
    var shown = panel.querySelector('.shown');
    if (!rows.length) { return; }

    function apply(){
      var q = (input && input.value ? input.value : '').toLowerCase();
      var allow = {};
      chips.forEach(function(c){ allow[c.dataset.sev] = c.classList.contains('on'); });
      var n = 0;
      rows.forEach(function(r){
        var okSev = allow[r.dataset.sev];
        var okTxt = !q || r.textContent.toLowerCase().indexOf(q) !== -1;
        var vis = okSev && okTxt;
        r.style.display = vis ? '' : 'none';
        if (vis) { n++; }
      });
      if (shown) { shown.textContent = n + ' of ' + rows.length + ' shown'; }
    }

    if (input) { input.addEventListener('input', apply); }
    chips.forEach(function(c){
      c.addEventListener('click', function(){ c.classList.toggle('on'); apply(); });
    });
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
        SizeKb   = [math]::Round((Get-Item $Path).Length / 1KB, 1)
    }
}

Export-ModuleMember -Function New-AuditHtmlReport