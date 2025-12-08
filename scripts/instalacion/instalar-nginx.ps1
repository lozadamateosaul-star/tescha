# 🚀 SCRIPT DE INSTALACIÓN AUTOMÁTICA DE NGINX PARA TESCHA
# Ejecutar como Administrador

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                               ║" -ForegroundColor Cyan
Write-Host "║   🚀 INSTALACIÓN NGINX PARA TESCHA                           ║" -ForegroundColor Cyan
Write-Host "║   Dominio: coordinacion-tescha.local                          ║" -ForegroundColor Cyan
Write-Host "║                                                               ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Verificar si se ejecuta como Administrador
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "❌ ERROR: Este script debe ejecutarse como Administrador" -ForegroundColor Red
    Write-Host "   Haz clic derecho en PowerShell y selecciona 'Ejecutar como administrador'" -ForegroundColor Yellow
    pause
    exit
}

Write-Host "✅ Ejecutando como Administrador" -ForegroundColor Green
Write-Host ""

# Variables
$nginxPath = "C:\nginx"
$nginxUrl = "http://nginx.org/download/nginx-1.24.0.zip"
$nginxZip = "$env:TEMP\nginx.zip"
$hostsFile = "C:\Windows\System32\drivers\etc\hosts"
$configSource = "$PSScriptRoot\nginx.conf"

# PASO 1: Verificar si Nginx ya está instalado
Write-Host "📋 PASO 1: Verificando instalación existente..." -ForegroundColor Cyan

if (Test-Path $nginxPath) {
    Write-Host "⚠️  Nginx ya está instalado en $nginxPath" -ForegroundColor Yellow
    $response = Read-Host "¿Deseas reinstalar? (S/N)"
    if ($response -ne "S" -and $response -ne "s") {
        Write-Host "❌ Instalación cancelada" -ForegroundColor Red
        pause
        exit
    }
    Write-Host "🗑️  Deteniendo y eliminando Nginx existente..." -ForegroundColor Yellow
    taskkill /f /im nginx.exe 2>$null
    Remove-Item -Path $nginxPath -Recurse -Force
}

Write-Host "✅ Listo para instalar" -ForegroundColor Green
Write-Host ""

# PASO 2: Descargar Nginx
Write-Host "📥 PASO 2: Descargando Nginx..." -ForegroundColor Cyan

try {
    Invoke-WebRequest -Uri $nginxUrl -OutFile $nginxZip
    Write-Host "✅ Nginx descargado" -ForegroundColor Green
} catch {
    Write-Host "❌ Error al descargar Nginx: $_" -ForegroundColor Red
    pause
    exit
}

Write-Host ""

# PASO 3: Extraer Nginx
Write-Host "📦 PASO 3: Extrayendo Nginx..." -ForegroundColor Cyan

try {
    Expand-Archive -Path $nginxZip -DestinationPath "C:\" -Force
    
    # Renombrar carpeta a C:\nginx
    $extractedFolder = Get-ChildItem "C:\" | Where-Object { $_.Name -like "nginx-*" } | Select-Object -First 1
    if ($extractedFolder) {
        Rename-Item -Path $extractedFolder.FullName -NewName "nginx" -Force
    }
    
    Write-Host "✅ Nginx extraído en $nginxPath" -ForegroundColor Green
} catch {
    Write-Host "❌ Error al extraer Nginx: $_" -ForegroundColor Red
    pause
    exit
}

Write-Host ""

# PASO 4: Copiar configuración
Write-Host "⚙️  PASO 4: Configurando Nginx..." -ForegroundColor Cyan

if (Test-Path $configSource) {
    Copy-Item -Path $configSource -Destination "$nginxPath\conf\nginx.conf" -Force
    Write-Host "✅ Configuración copiada" -ForegroundColor Green
} else {
    Write-Host "⚠️  Archivo nginx.conf no encontrado en $configSource" -ForegroundColor Yellow
    Write-Host "   Deberás configurarlo manualmente" -ForegroundColor Yellow
}

Write-Host ""

# PASO 5: Configurar archivo hosts
Write-Host "📝 PASO 5: Configurando archivo hosts..." -ForegroundColor Cyan

$hostsEntry = "127.0.0.1    coordinacion-tescha.local"
$hostsContent = Get-Content $hostsFile

if ($hostsContent -notcontains $hostsEntry) {
    Add-Content -Path $hostsFile -Value "`n$hostsEntry"
    Write-Host "✅ Entrada agregada al archivo hosts" -ForegroundColor Green
} else {
    Write-Host "ℹ️  Entrada ya existe en archivo hosts" -ForegroundColor Yellow
}

Write-Host ""

# PASO 6: Configurar Firewall
Write-Host "🔥 PASO 6: Configurando Firewall..." -ForegroundColor Cyan

try {
    New-NetFirewallRule -DisplayName "Nginx HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -ErrorAction SilentlyContinue
    Write-Host "✅ Regla de firewall creada" -ForegroundColor Green
} catch {
    Write-Host "ℹ️  Regla de firewall ya existe o no se pudo crear" -ForegroundColor Yellow
}

Write-Host ""

# PASO 7: Probar configuración
Write-Host "🧪 PASO 7: Probando configuración..." -ForegroundColor Cyan

Set-Location $nginxPath
$testResult = & .\nginx.exe -t 2>&1

if ($testResult -like "*successful*") {
    Write-Host "✅ Configuración válida" -ForegroundColor Green
} else {
    Write-Host "❌ Error en la configuración:" -ForegroundColor Red
    Write-Host $testResult -ForegroundColor Yellow
    pause
    exit
}

Write-Host ""

# PASO 8: Iniciar Nginx
Write-Host "🚀 PASO 8: Iniciando Nginx..." -ForegroundColor Cyan

try {
    Start-Process -FilePath "$nginxPath\nginx.exe" -WorkingDirectory $nginxPath -WindowStyle Hidden
    Start-Sleep -Seconds 2
    
    $nginxProcesses = Get-Process nginx -ErrorAction SilentlyContinue
    if ($nginxProcesses) {
        Write-Host "✅ Nginx iniciado correctamente ($($nginxProcesses.Count) procesos)" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Nginx no se inició correctamente" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ Error al iniciar Nginx: $_" -ForegroundColor Red
}

Write-Host ""

# PASO 9: Verificación final
Write-Host "✅ PASO 9: Verificación final..." -ForegroundColor Cyan

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                                                               ║" -ForegroundColor Green
Write-Host "║   ✅ INSTALACIÓN COMPLETADA                                  ║" -ForegroundColor Green
Write-Host "║                                                               ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

Write-Host "📊 INFORMACIÓN:" -ForegroundColor Cyan
Write-Host "   • Nginx instalado en: $nginxPath" -ForegroundColor White
Write-Host "   • Dominio configurado: coordinacion-tescha.local" -ForegroundColor White
Write-Host "   • Puerto: 80 (HTTP)" -ForegroundColor White
Write-Host ""

Write-Host "🌐 ACCESO:" -ForegroundColor Cyan
Write-Host "   http://coordinacion-tescha.local" -ForegroundColor Yellow
Write-Host ""

Write-Host "⚙️  COMANDOS ÚTILES:" -ForegroundColor Cyan
Write-Host "   Detener:    cd $nginxPath; .\nginx.exe -s stop" -ForegroundColor White
Write-Host "   Reiniciar:  cd $nginxPath; .\nginx.exe -s reload" -ForegroundColor White
Write-Host "   Verificar:  tasklist /fi `"imagename eq nginx.exe`"" -ForegroundColor White
Write-Host ""

Write-Host "📝 PRÓXIMOS PASOS:" -ForegroundColor Cyan
Write-Host "   1. Asegúrate de que tu frontend esté corriendo en puerto 3000" -ForegroundColor White
Write-Host "   2. Asegúrate de que tu backend esté corriendo en puerto 5000" -ForegroundColor White
Write-Host "   3. Abre el navegador: http://coordinacion-tescha.local" -ForegroundColor White
Write-Host ""

Write-Host "🎉 ¡Listo para usar!" -ForegroundColor Green
Write-Host ""

# Limpiar archivo temporal
Remove-Item -Path $nginxZip -Force -ErrorAction SilentlyContinue

pause
