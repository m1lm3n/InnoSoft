# Смотрим все открытые файлы профилей FSLogix (VHDX) по сети
Get-SmbOpenFile | Where-Object { $_.Path -match "\.vhd" } | Select-Object ClientUserName, ClientComputerName, Path, LockCount

# Если нужно принудительно "отстрелить" зависшую сессию конкретного юзера (например, j.doe):
Close-SmbOpenFile -ClientUserName "NNN\j.doe" -Force

# Мониторинг "разбухания" дисков (Capacity Planning)
Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' } | Format-Table DriveLetter, FileSystemLabel, @{Label = "Size(GB)"; Expression = { [math]::Round($_.Size / 1GB, 2) } }, @{Label = "Free(GB)"; Expression = { [math]::Round($_.SizeRemaining / 1GB, 2) } }, @{Label = "% Free"; Expression = { [math]::Round(($_.SizeRemaining / $_.Size) * 100, 2) } } -AutoSize
