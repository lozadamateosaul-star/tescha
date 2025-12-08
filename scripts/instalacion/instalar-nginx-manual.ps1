# 🚀 INSTALACIÓN MANUAL DE NGINX - PASO A PASO

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   🚀 INSTALACIÓN NGINX PARA TESCHA - PASO A PASO            ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# PASO 1: Descargar Nginx
Write-Host "📥 PASO 1: Descargando Nginx..." -ForegroundColor Yellow
Write-Host ""

$nginxUrl = "http://nginx.org/download/nginx-1.24.0.zip"
$nginxZip = "$env:TEMP\nginx.zip"

try {
    Write-Host "   Descargando desde: $nginxUrl" -ForegroundColor White
    Invoke-WebRequest -Uri $nginxUrl -OutFile $nginxZip -UseBasicParsing
    Write-Host "   ✅ Descarga completada" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Error al descargar: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "   Intenta descargar manualmente desde:" -ForegroundColor Yellow
    Write-Host "   http://nginx.org/en/download.html" -ForegroundColor Cyan
    pause
    exit
}

Write-Host ""

# PASO 2: Extraer Nginx
Write-Host "📦 PASO 2: Extrayendo Nginx..." -ForegroundColor Yellow

try {
    Write-Host "   Extrayendo en C:\" -ForegroundColor White
    Expand-Archive -Path $nginxZip -DestinationPath "C:\" -Force
    
    # Buscar carpeta extraída
    $extractedFolder = Get-ChildItem "C:\" | Where-Object { $_.Name -like "nginx-*" -and $_.PSIsContainer } | Select-Object -First 1
    
    if ($extractedFolder) {
        Write-Host "   Carpeta encontrada: $($extractedFolder.Name)" -ForegroundColor White
        
        # Renombrar a C:\nginx
        if (Test-Path "C:\nginx") {
            Remove-Item "C:\nginx" -Recurse -Force
        }
        Rename-Item -Path $extractedFolder.FullName -NewName "nginx" -Force
        Write-Host "   ✅ Nginx extraído en C:\nginx" -ForegroundColor Green
    } else {
        throw "No se encontró la carpeta de Nginx"
    }
} catch {
    Write-Host "   ❌ Error al extraer: $_" -ForegroundColor Red
    pause
    exit
}

Write-Host ""

# PASO 3: Copiar configuración
Write-Host "⚙️  PASO 3: Configurando Nginx..." -ForegroundColor Yellow

$configSource = "$PSScriptRoot\nginx-ip-directa.conf"
$configDest = "C:\nginx\conf\nginx.conf"

if (Test-Path $configSource) {
    try {
        Copy-Item -Path $configSource -Destination $configDest -Force
        Write-Host "   ✅ Configuración copiada" -ForegroundColor Green
    } catch {
        Write-Host "   ⚠️  No se pudo copiar configuración: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "   ⚠️  Archivo de configuración no encontrado" -ForegroundColor Yellow
    Write-Host "   Usando configuración por defecto" -ForegroundColor White
}

Write-Host ""

# PASO 4: Probar configuración
Write-Host "🧪 PASO 4: Probando configuración..." -ForegroundColor Yellow

Set-Location "C:\nginx"
$testResult = & .\nginx.exe -t 2>&1 | Out-String

if ($testResult -like "*successful*") {
    Write-Host "   ✅ Configuración válida" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  Advertencias en configuración:" -ForegroundColor Yellow
    Write-Host $testResult -ForegroundColor Gray
}

Write-Host ""

# PASO 5: Configurar Firewall
Write-Host "🔥 PASO 5: Configurando Firewall..." -ForegroundColor Yellow

try {
    $existingRule = Get-NetFirewallRule -DisplayName "Nginx HTTP" -ErrorAction SilentlyContinue
    if (-not $existingRule) {
        New-NetFirewallRule -DisplayName "Nginx HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow | Out-Null
        Write-Host "   ✅ Regla de firewall creada" -ForegroundColor Green
    } else {
        Write-Host "   ℹ️  Regla de firewall ya existe" -ForegroundColor Cyan
    }
} catch {
    Write-Host "   ⚠️  No se pudo configurar firewall: $_" -ForegroundColor Yellow
}

Write-Host ""

# PASO 6: Verificar puerto 80
Write-Host "🔍 PASO 6: Verificando puerto 80..." -ForegroundColor Yellow

$port80 = Get-NetTCPConnection -LocalPort 80 -ErrorAction SilentlyContinue

if ($port80) {
    Write-Host "   ⚠️  Puerto 80 está ocupado por:" -ForegroundColor Yellow
    $port80 | ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        Write-Host "      - $($process.ProcessName) (PID: $($_.OwningProcess))" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "   Opciones:" -ForegroundColor Cyan
    Write-Host "   1. Detener el proceso que usa puerto 80" -ForegroundColor White
    Write-Host "   2. Cambiar Nginx a otro puerto (ej: 8080)" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "   ✅ Puerto 80 disponible" -ForegroundColor Green
}

Write-Host ""

# PASO 7: Iniciar Nginx
Write-Host "🚀 PASO 7: Iniciando Nginx..." -ForegroundColor Yellow

try {
    # Detener procesos nginx existentes
    Get-Process nginx -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    
    Start-Sleep -Seconds 1
    
    # Iniciar Nginx
    Start-Process -FilePath "C:\nginx\nginx.exe" -WorkingDirectory "C:\nginx" -WindowStyle Hidden
    
    Start-Sleep -Seconds 2
    
    # Verificar
    $nginxProcesses = Get-Process nginx -ErrorAction SilentlyContinue
    
    if ($nginxProcesses) {
        Write-Host "   ✅ Nginx iniciado correctamente" -ForegroundColor Green
        Write-Host "      Procesos: $($nginxProcesses.Count)" -ForegroundColor White
    } else {
        Write-Host "   ❌ Nginx no se inició" -ForegroundColor Red
        Write-Host "   Verifica los logs en: C:\nginx\logs\error.log" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error al iniciar Nginx: $_" -ForegroundColor Red
}

Write-Host ""

# PASO 8: Limpiar
Write-Host "🧹 PASO 8: Limpiando archivos temporales..." -ForegroundColor Yellow
Remove-Item -Path $nginxZip -Force -ErrorAction SilentlyContinue
Write-Host "   ✅ Limpieza completada" -ForegroundColor Green

Write-Host ""

# RESULTADO FINAL
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   ✅ INSTALACIÓN COMPLETADA                                  ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

Write-Host "📊 INFORMACIÓN:" -ForegroundColor Cyan
Write-Host "   • Nginx instalado en: C:\nginx" -ForegroundColor White
Write-Host "   • Puerto: 80" -ForegroundColor White
Write-Host "   • Hostname: coordinacion-tescha" -ForegroundColor White
Write-Host ""

Write-Host "🌐 ACCESO:" -ForegroundColor Cyan
Write-Host "   Desde tu PC:" -ForegroundColor White
Write-Host "   • http://localhost" -ForegroundColor Yellow
Write-Host "   • http://coordinacion-tescha.local" -ForegroundColor Yellow
Write-Host ""
Write-Host "   Desde otros PCs en la red:" -ForegroundColor White
Write-Host "   • http://coordinacion-tescha.local" -ForegroundColor Yellow
Write-Host "   • http://192.168.1.132" -ForegroundColor Yellow
Write-Host ""

Write-Host "⚙️  COMANDOS ÚTILES:" -ForegroundColor Cyan
Write-Host "   Detener:    cd C:\nginx; .\nginx.exe -s stop" -ForegroundColor White
Write-Host "   Reiniciar:  cd C:\nginx; .\nginx.exe -s reload" -ForegroundColor White
Write-Host "   Ver logs:   Get-Content C:\nginx\logs\error.log -Tail 20" -ForegroundColor White
Write-Host ""

Write-Host "📝 PRÓXIMOS PASOS:" -ForegroundColor Cyan
Write-Host "   1. Asegúrate de que tu frontend esté en puerto 3000" -ForegroundColor White
Write-Host "   2. Asegúrate de que tu backend esté en puerto 5000" -ForegroundColor White
Write-Host "   3. Prueba: http://coordinacion-tescha.local" -ForegroundColor White
Write-Host ""

Write-Host "🎉 ¡Listo para usar!" -ForegroundColor Green
Write-Host ""

pause
