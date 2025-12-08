# 🌐 SERVIDOR DNS LOCAL PARA TESCHA
# Configuración automática de DNS local en Windows

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                               ║" -ForegroundColor Cyan
Write-Host "║   🌐 CONFIGURACIÓN DNS LOCAL PARA TESCHA                     ║" -ForegroundColor Cyan
Write-Host "║   coordinacion-tescha.local → 192.168.1.132                   ║" -ForegroundColor Cyan
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

# OPCIÓN RECOMENDADA: Usar Acrylic DNS Proxy
Write-Host "📋 OPCIONES DISPONIBLES:" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Instalar Acrylic DNS Proxy (Recomendado - Fácil)" -ForegroundColor Yellow
Write-Host "2. Configurar manualmente" -ForegroundColor Yellow
Write-Host "3. Solo usar IP directa (sin DNS)" -ForegroundColor Yellow
Write-Host ""

$opcion = Read-Host "Selecciona una opción (1-3)"

switch ($opcion) {
    "1" {
        Write-Host ""
        Write-Host "📥 INSTALACIÓN DE ACRYLIC DNS PROXY" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Pasos:" -ForegroundColor Yellow
        Write-Host "1. Descarga desde: https://mayakron.altervista.org/support/acrylic/Home.htm" -ForegroundColor White
        Write-Host "2. Instala el programa" -ForegroundColor White
        Write-Host "3. Edita: C:\Program Files (x86)\Acrylic DNS Proxy\AcrylicHosts.txt" -ForegroundColor White
        Write-Host "4. Agrega la línea: 192.168.1.132 coordinacion-tescha.local" -ForegroundColor White
        Write-Host "5. Reinicia el servicio Acrylic DNS Proxy" -ForegroundColor White
        Write-Host ""
        Write-Host "Luego configura el router:" -ForegroundColor Yellow
        Write-Host "- DNS Primario: 192.168.1.132" -ForegroundColor White
        Write-Host ""
        
        $abrir = Read-Host "¿Abrir página de descarga? (S/N)"
        if ($abrir -eq "S" -or $abrir -eq "s") {
            Start-Process "https://mayakron.altervista.org/support/acrylic/Home.htm"
        }
    }
    
    "2" {
        Write-Host ""
        Write-Host "📝 CONFIGURACIÓN MANUAL" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "OPCIÓN A: Usar archivo hosts en cada PC" -ForegroundColor Yellow
        Write-Host "Archivo: C:\Windows\System32\drivers\etc\hosts" -ForegroundColor White
        Write-Host "Agregar: 192.168.1.132    coordinacion-tescha.local" -ForegroundColor White
        Write-Host ""
        Write-Host "OPCIÓN B: Configurar DNS en el router" -ForegroundColor Yellow
        Write-Host "1. Entra al router (192.168.1.1)" -ForegroundColor White
        Write-Host "2. Busca sección DNS/DHCP" -ForegroundColor White
        Write-Host "3. Agrega: coordinacion-tescha.local → 192.168.1.132" -ForegroundColor White
        Write-Host ""
    }
    
    "3" {
        Write-Host ""
        Write-Host "✅ USAR IP DIRECTA (SIN DNS)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Los maestros accederán con:" -ForegroundColor Yellow
        Write-Host "http://192.168.1.132" -ForegroundColor Green
        Write-Host ""
        Write-Host "Ventajas:" -ForegroundColor Yellow
        Write-Host "✅ No necesitas configurar DNS" -ForegroundColor White
        Write-Host "✅ Funciona inmediatamente" -ForegroundColor White
        Write-Host "✅ Sin instalaciones adicionales" -ForegroundColor White
        Write-Host ""
        Write-Host "Desventajas:" -ForegroundColor Yellow
        Write-Host "⚠️  Los maestros ven la IP" -ForegroundColor White
        Write-Host "⚠️  Si cambias de IP, deben actualizar" -ForegroundColor White
        Write-Host ""
    }
    
    default {
        Write-Host "❌ Opción inválida" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "💡 RECOMENDACIÓN FINAL:" -ForegroundColor Yellow
Write-Host ""
Write-Host "Si NO tienes acceso al router:" -ForegroundColor White
Write-Host ""
Write-Host "OPCIÓN 1 (Más simple):" -ForegroundColor Cyan
Write-Host "  Los maestros usan: http://192.168.1.132" -ForegroundColor Green
Write-Host "  ✅ Sin configurar nada" -ForegroundColor White
Write-Host "  ✅ Funciona inmediatamente" -ForegroundColor White
Write-Host ""
Write-Host "OPCIÓN 2 (Más profesional):" -ForegroundColor Cyan
Write-Host "  1. Instala Acrylic DNS Proxy en tu PC" -ForegroundColor White
Write-Host "  2. Configura: 192.168.1.132 → coordinacion-tescha.local" -ForegroundColor White
Write-Host "  3. Los maestros configuran DNS manualmente:" -ForegroundColor White
Write-Host "     DNS Primario: 192.168.1.132" -ForegroundColor Green
Write-Host "  4. Acceden con: http://coordinacion-tescha.local" -ForegroundColor Green
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

pause
