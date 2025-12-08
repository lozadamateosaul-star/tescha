# 🌐 CONFIGURACIÓN BONJOUR/MDNS PARA TESCHA
# Equivalente a Avahi en Ubuntu

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                               ║" -ForegroundColor Cyan
Write-Host "║   🌐 CONFIGURACIÓN BONJOUR (mDNS) PARA TESCHA               ║" -ForegroundColor Cyan
Write-Host "║   coordinacion-tescha.local (sin configurar nada)             ║" -ForegroundColor Cyan
Write-Host "║                                                               ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Verificar si se ejecuta como Administrador
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "❌ ERROR: Este script debe ejecutarse como Administrador" -ForegroundColor Red
    pause
    exit
}

Write-Host "✅ Ejecutando como Administrador" -ForegroundColor Green
Write-Host ""

# PASO 1: Verificar si Bonjour está instalado
Write-Host "📋 PASO 1: Verificando Bonjour..." -ForegroundColor Cyan

$bonjourService = Get-Service -Name "Bonjour Service" -ErrorAction SilentlyContinue

if ($bonjourService) {
    Write-Host "✅ Bonjour está instalado" -ForegroundColor Green
    Write-Host "   Estado: $($bonjourService.Status)" -ForegroundColor White
} else {
    Write-Host "❌ Bonjour NO está instalado" -ForegroundColor Red
    Write-Host ""
    Write-Host "📥 INSTALACIÓN DE BONJOUR:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Opción 1: Bonjour Print Services (Recomendado)" -ForegroundColor White
    Write-Host "  Descarga: https://support.apple.com/kb/DL999" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Opción 2: Instalar iTunes (incluye Bonjour)" -ForegroundColor White
    Write-Host "  Descarga: https://www.apple.com/itunes/download/" -ForegroundColor Cyan
    Write-Host ""
    
    $abrir = Read-Host "¿Abrir página de descarga de Bonjour? (S/N)"
    if ($abrir -eq "S" -or $abrir -eq "s") {
        Start-Process "https://support.apple.com/kb/DL999"
    }
    
    Write-Host ""
    Write-Host "⚠️  Instala Bonjour y vuelve a ejecutar este script" -ForegroundColor Yellow
    pause
    exit
}

Write-Host ""

# PASO 2: Cambiar hostname de Windows
Write-Host "📋 PASO 2: Configurando hostname..." -ForegroundColor Cyan

$currentHostname = $env:COMPUTERNAME
Write-Host "   Hostname actual: $currentHostname" -ForegroundColor White

$newHostname = "coordinacion-tescha"
Write-Host "   Hostname deseado: $newHostname" -ForegroundColor White
Write-Host ""

if ($currentHostname -ne $newHostname) {
    Write-Host "⚠️  Para que funcione coordinacion-tescha.local automáticamente," -ForegroundColor Yellow
    Write-Host "   necesitas cambiar el nombre de la PC a: $newHostname" -ForegroundColor Yellow
    Write-Host ""
    
    $cambiar = Read-Host "¿Cambiar nombre de PC ahora? (S/N)"
    
    if ($cambiar -eq "S" -or $cambiar -eq "s") {
        try {
            Rename-Computer -NewName $newHostname -Force
            Write-Host "✅ Nombre de PC cambiado a: $newHostname" -ForegroundColor Green
            Write-Host "⚠️  DEBES REINICIAR la PC para que tome efecto" -ForegroundColor Yellow
            
            $reiniciar = Read-Host "¿Reiniciar ahora? (S/N)"
            if ($reiniciar -eq "S" -or $reiniciar -eq "s") {
                Restart-Computer -Force
            }
        } catch {
            Write-Host "❌ Error al cambiar nombre: $_" -ForegroundColor Red
        }
    } else {
        Write-Host ""
        Write-Host "ℹ️  Puedes cambiarlo manualmente:" -ForegroundColor Cyan
        Write-Host "   1. Panel de Control → Sistema" -ForegroundColor White
        Write-Host "   2. Cambiar configuración → Cambiar" -ForegroundColor White
        Write-Host "   3. Nombre: $newHostname" -ForegroundColor White
        Write-Host "   4. Reiniciar" -ForegroundColor White
    }
} else {
    Write-Host "✅ Hostname ya está configurado correctamente" -ForegroundColor Green
}

Write-Host ""

# PASO 3: Verificar servicio Bonjour
Write-Host "📋 PASO 3: Verificando servicio Bonjour..." -ForegroundColor Cyan

if ($bonjourService.Status -eq "Running") {
    Write-Host "✅ Servicio Bonjour está corriendo" -ForegroundColor Green
} else {
    Write-Host "⚠️  Iniciando servicio Bonjour..." -ForegroundColor Yellow
    Start-Service "Bonjour Service"
    Write-Host "✅ Servicio Bonjour iniciado" -ForegroundColor Green
}

Write-Host ""

# PASO 4: Información final
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                                                               ║" -ForegroundColor Green
Write-Host "║   ✅ CONFIGURACIÓN COMPLETADA                                ║" -ForegroundColor Green
Write-Host "║                                                               ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

Write-Host "🌐 ACCESO:" -ForegroundColor Cyan
Write-Host "   Los maestros pueden acceder con:" -ForegroundColor White
Write-Host ""
Write-Host "   http://coordinacion-tescha.local" -ForegroundColor Yellow
Write-Host ""
Write-Host "   ✅ SIN configurar nada en sus PCs" -ForegroundColor Green
Write-Host "   ✅ Solo conectarse al WiFi" -ForegroundColor Green
Write-Host "   ✅ Funciona automáticamente (mDNS/Bonjour)" -ForegroundColor Green
Write-Host ""

Write-Host "📝 REQUISITOS:" -ForegroundColor Cyan
Write-Host "   1. ✅ Bonjour instalado en tu PC" -ForegroundColor White
Write-Host "   2. ✅ Hostname: coordinacion-tescha" -ForegroundColor White
Write-Host "   3. ✅ Nginx corriendo en puerto 80" -ForegroundColor White
Write-Host "   4. ✅ Frontend y Backend corriendo" -ForegroundColor White
Write-Host ""

Write-Host "🧪 PRUEBA:" -ForegroundColor Cyan
Write-Host "   Desde otra PC en la misma red:" -ForegroundColor White
Write-Host "   http://coordinacion-tescha.local" -ForegroundColor Yellow
Write-Host ""

Write-Host "💡 NOTA:" -ForegroundColor Cyan
Write-Host "   Si cambiaste el hostname, DEBES REINICIAR la PC" -ForegroundColor Yellow
Write-Host ""

pause
