#Run as domain user
runas /netonly /user:kkk\olvin powershell.exe
########################################################################

#Create report of GPOs in the domain and export to XML
Import-Module GroupPolicy
New-Item -ItemType Directory -Path C:\gpo-export -Force | Out-Null

# Полный отчёт по всем политикам домена, один файл
Get-GPOReport -All -Domain nnn.lo -ReportType Xml -Path C:\gpo-export\nnn.xml
C:\gpo-export\nnn.xml -Encoding utf8
# То же в HTML — читаемо человеком, пригодится тебе самому
Get-GPOReport -All -Domain nnn.lo -ReportType Html -Path C:\gpo-export\nnn.html
C:\gpo-export\nnn.html -Encoding utf8
########################################################################

#Загрузка скриптов на DC
copy-item c:\users\adm\documents\projects\innosoft\dc_actions \\dc-nnn.nnn.lo\c$\scripts\ -recurse -force
get-childitem c:\scripts\dc_actions -recurse | unblock-file
########################################################################

#Copy to local machine
Copy-Item \\dc-nnn.nnn.lo\c$\gpo-export\nnn.xml C:\gpo-export\
Copy-Item \\dc-nnn.nnn.lo\c$\gpo-export\nnn.html C:\gpo-export\
copy-item \\dc-nnn.nnn.lo\c$\gpo-export\2026-08-12 c:\gpo-export\ -recurse
copy-item \\dc-nnn.nnn.lo\c$\ad-export\* c:\ad-export\ -recurse
########################################################################

#По другим доменам — с параметрами:
.\Export-GpoMap.ps1 -Domain kkk.lo -Server dc-kkk.kkk.lo
.\Export-GpoReport.ps1 -Domain kkk.lo -Server dc-kkk.kkk.lo
.\run-adhealth.ps1
.\run-adhealth.ps1 -domain kkk.lo -server dc-iiii.kkk.lo
########################################################################

#Сделать скрипты выполняемыми
Get-ChildItem . -Filter *.ps1 | Unblock-File
########################################################################

.\Export-GpoMap.ps1 -OutDir "C:\gpo-export\$(Get-Date -f yyyy-MM-dd)"
.\Export-GpoMap.ps1 -outdir "c:\gpo-export\$(get-date -f yyyy-mm-dd)"

.\Analyze-GpoMap.ps1 -Path "C:\gpo-export\$(Get-Date -f yyyy-MM-dd)"
.\Analyze-GpoMap.ps1 -path c:\gpo-export\2026-08-11 -domain nnn.lo

.\run-gpo.ps1
.\run-gpo.ps1 -domain kkk.lo -server dc-iiii.kkk.lo
########################################################################

#Git
git diff --staged > staged_changes.diff
git diff --staged --no-textconv > staged_changes.diff
########################################################################

#Правка политик
get-gppermission -name 'User - Chrome_unblock_settings' -domain nnn.lo -server dc-nnn.nnn.lo -all | export-csv c:\gpo-export\chrome-unblock-after.csv -notypeinformation
########################################################################