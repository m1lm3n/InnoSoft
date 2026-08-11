Самая главная команда инфра-инженера для AD. Показывает общую сводку по всем контроллерам в домене, крупнейшие задержки (Largest delta) и количество ошибок (Fails).
repadmin /replsummary

########################################################################

Детальная репликация (Разбор полетов)
repadmin /showrepl

########################################################################

Глубокая диагностика здоровья DC
dcdiag /q

########################################################################

Разбираемся с "Зоопарком" (Доверительные отношения)
Get-ADTrust -Filter * | Format-Table Name, TrustType, TrustDirection, TrustAttributes -AutoSize

########################################################################

Проверка "Бомб замедленного действия" (Поиск всех DC)
Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, OperatingSystem, IsGlobalCatalog | Format-Table -AutoSize

Get-ADUser -Filter "SamAccountName -like '*monitoring*'" -Properties Description,LastLogonDate | Select-Object Name,SamAccountName,Enabled,Description,LastLogonDate