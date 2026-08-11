# Импортируем модуль, если он еще не загружен
Import-Module VMware.PowerCLI -ErrorAction SilentlyContinue

# Настройки подключения
$vCenterServer = "vcsa8.dc2.core64.com"

# Отключаем проверку сертификатов (полезно, если vCenter сомоподписанный)
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

Write-Host "Connect to vCenter: $vCenterServer ..." -ForegroundColor Cyan
Connect-VIServer -Server $vCenterServer -WarningAction SilentlyContinue

Write-Host "We're collecting data from Datastores. This may take a couple of minutes due to the collection of latency metrics...." -ForegroundColor Yellow
$datastores = Get-Datastore | Where-Object { $_.Type -match "VMFS|NFS" }

$report = foreach ($ds in $datastores) {
    # Считаем базовые метрики объема
    $capacityGB = [math]::Round($ds.CapacityGB, 2)
    $freeGB = [math]::Round($ds.FreeSpaceGB, 2)
    $percentFree = if ($capacityGB -gt 0) { [math]::Round(($freeGB / $capacityGB) * 100, 2) } else { 0 }

    # Считаем Provisioned (Overcommit) — сколько места реально роздано виртуалкам (включая Thin disks)
    $provisionedGB = [math]::Round(($ds.ExtensionData.Summary.Capacity - $ds.ExtensionData.Summary.FreeSpace + $ds.ExtensionData.Summary.Uncommitted) / 1GB, 2)

    # Пытаемся получить метрики Latency за последний интервал (Realtime)
    $readLat = 0
    $writeLat = 0
    try {
        $stats = Get-Stat -Entity $ds -Stat datastore.totalreadlatency.average, datastore.totalwritelatency.average -Realtime -MaxSamples 1 -ErrorAction SilentlyContinue
        if ($stats) {
            $readLatObject = $stats | Where-Object MetricId -eq 'datastore.totalreadlatency.average'
            $writeLatObject = $stats | Where-Object MetricId -eq 'datastore.totalwritelatency.average'

            if ($readLatObject) { $readLat = [math]::Round($readLatObject.Value, 2) }
            if ($writeLatObject) { $writeLat = [math]::Round($writeLatObject.Value, 2) }
        }
    }
    catch {
        # Игнорируем ошибки, если метрики недоступны или vCenter их не отдает
    }

    [PSCustomObject]@{
        Datastore      = $ds.Name
        Type           = $ds.Type
        Capacity_GB    = $capacityGB
        Free_GB        = $freeGB
        Free_Percent   = $percentFree
        Provisioned_GB = $provisionedGB
        ReadLat_ms     = $readLat
        WriteLat_ms    = $writeLat
    }
}

# Отключаемся от vCenter, соблюдаем гигиену
Disconnect-VIServer -Server $vCenterServer -Confirm:$false

Write-Host "`n--- DATASTORE REPORT ---" -ForegroundColor Cyan
# Сортируем так, чтобы самые забитые стораджи были вверху
$report | Sort-Object Free_Percent | Format-Table -AutoSize