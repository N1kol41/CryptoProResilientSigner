# ==============================================================================
# CryptoPro-IE-Watchdog.ps1
# Супервизор процесса Internet Explorer при пакетном подписании документов
# ==============================================================================

param(
    [string]$TargetUrl = "https://edi-portal.corp.local/batch-signing?resume=1",
    [int]$HeartbeatTimeoutSeconds = 45,
    [int]$MaxMemoryMb = 1400,
    [string]$LockFilePath = "$env:TEMP\cp_batch_heartbeat.lock"
)

Write-Host ">>> Запуск сторожевого процесса CryptoPro IE Watchdog..." -ForegroundColor Cyan

function Kill-HungCryptoProDialogs {
    # Снятие зависших процессов модальных окон ввода PIN при сбое токена
    Get-Process -Name "cpui*", "rundll32" -ErrorAction SilentlyContinue | Where-Object {
        $_.MainWindowTitle -match "КриптоПро|Ввод PIN|Сертификат"
    } | ForEach-Object {
        Write-Warning "Обнаружено зависшее модальное окно PIN: $($_.Id). Завершение..."
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
}

function Restart-InternetExplorer {
    Write-Host "[WATCHDOG] Принудительный перезапуск Internet Explorer..." -ForegroundColor Yellow
    
    # Снимаем зависшие дочерние диалоги
    Kill-HungCryptoProDialogs

    # Убиваем все процессы iexplore.exe
    Get-Process -Name "iexplore" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # Запускаем чистый процесс IE с URL восстановления сессии
    $iePath = "$env:ProgramFiles\Internet Explorer\iexplore.exe"
    if (-not (Test-Path $iePath)) {
        $iePath = "$env:ProgramFiles(x86)\Internet Explorer\iexplore.exe"
    }

    Write-Host "[WATCHDOG] Запуск $iePath $TargetUrl" -ForegroundColor Green
    Start-Process -FilePath $iePath -ArgumentList "$TargetUrl"
    
    # Обновляем отметку времени heartbeat
    (Get-Date).ToString("o") | Out-File -FilePath $LockFilePath -Force
}

# Основной цикл супервизора
while ($true) {
    Start-Sleep -Seconds 5

    $ieProcesses = Get-Process -Name "iexplore" -ErrorAction SilentlyContinue

    if (-not $ieProcesses) {
        # Если IE не запущен, а пакет должен работать - перезапуск
        if (Test-Path $LockFilePath) {
            Write-Warning "Процесс iexplore.exe исчез (падение или закрытие)! Восстановление..."
            Restart-InternetExplorer
        }
        continue
    }

    # Проверка 1: Утечка памяти (предел 32-битного процесса ~1.5 ГБ)
    foreach ($proc in $ieProcesses) {
        $memMb = [math]::Round($proc.WorkingSet64 / 1MB)
        if ($memMb -gt $MaxMemoryMb) {
            Write-Warning "Процесс IE (PID: $($proc.Id)) превысил лимит памяти: $memMb MB > $MaxMemoryMb MB!"
            Restart-InternetExplorer
            break
        }
    }

    # Проверка 2: Зависание UI-потока (Responding = False)
    $hungProcess = $ieProcesses | Where-Object { $_.Responding -eq $false }
    if ($hungProcess) {
        Write-Warning "Обнаружен зависший процесс IE PID $($hungProcess.Id)! Ожидание разблокировки..."
        Start-Sleep -Seconds 10
        if ($hungProcess.Responding -eq $false) {
            Write-Error "Процесс окончательно завис в системном вызове CryptoPro. Перезапуск..."
            Restart-InternetExplorer
            continue
        }
    }

    # Проверка 3: Watchdog Heartbeat файл (обновляется из JavaScript через LocalStorage/ActiveX FileSystemObject)
    if (Test-Path $LockFilePath) {
        $lastWrite = (Get-Item $LockFilePath).LastWriteTime
        $secondsIdle = (New-TimeSpan -Start $lastWrite -End (Get-Date)).TotalSeconds

        if ($secondsIdle -gt $HeartbeatTimeoutSeconds) {
            Write-Warning "Heartbeat не обновлялся $secondsIdle сек (таймаут $HeartbeatTimeoutSeconds сек). Зависание операции подписания!"
            Restart-InternetExplorer
        }
    }
}
