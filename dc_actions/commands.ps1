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

#Copy to local machine
Copy-Item \\dc-nnn.nnn.lo\c$\gpo-export\nnn.xml C:\gpo-export\
Copy-Item \\dc-nnn.nnn.lo\c$\gpo-export\nnn.html C:\gpo-export\
########################################################################

#По другим доменам — с параметрами:
.\Export-GpoMap.ps1 -Domain kkk.lo -Server dc-kkk.kkk.lo
.\Export-GpoReport.ps1 -Domain kkk.lo -Server dc-kkk.kkk.lo
########################################################################

Get-ChildItem . -Filter *.ps1 | Unblock-File
########################################################################
