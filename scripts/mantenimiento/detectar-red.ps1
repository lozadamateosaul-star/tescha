# 🌐 DETECTOR DE RED - ¿Qué URL deben usar los maestros?

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                               ║" -ForegroundColor Cyan
Write-Host "║   🌐 DETECTOR DE RED TESCHA                                  ║" -ForegroundColor Cyan
Write-Host "║   ¿Qué URL deben usar los maestros?                           ║" -ForegroundColor Cyan
Write-Host "║                                                               ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Obtener todas las IPs
$ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" -and $_.PrefixOrigin -eq "Dhcp" -or $_.PrefixOrigin -eq "Manual" }

Write-Host "📊 TUS IPs ACTIVAS:" -ForegroundColor Yellow
Write-Host ""

$wifiIP = $null
$hotspotIP = $null

foreach ($ip in $ips) {
    $ipAddr = $ip.IPAddress
    $interface = (Get-NetAdapter -InterfaceIndex $ip.InterfaceIndex).Name
    
    Write-Host "   • $ipAddr" -ForegroundColor White
    Write-Host "     Interfaz: $interface" -ForegroundColor Gray
    
    # Detectar tipo de red
    if ($ipAddr -like "192.168.1.*") {
        $wifiIP = $ipAddr
        Write-Host "     Tipo: WiFi Compartido ✅" -ForegroundColor Green
    }
    elseif ($ipAddr -like "192.168.137.*") {
        $hotspotIP = $ipAddr
        Write-Host "     Tipo: Hotspot (Compartir Internet) 📶" -ForegroundColor Magenta
    }
    else {
        Write-Host "     Tipo: Otra red" -ForegroundColor Gray
    }
    Write-Host ""
}

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Recomendación
if ($wifiIP -and $hotspotIP) {
    Write-Host "⚠️  TIENES AMBAS REDES ACTIVAS" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "📍 WiFi Compartido:" -ForegroundColor Green
    Write-Host "   Los maestros usan: http://coordinacion-tescha.local" -ForegroundColor Cyan
    Write-Host "   o: http://$wifiIP" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "📍 Hotspot:" -ForegroundColor Magenta
    Write-Host "   Los maestros usan: http://$hotspotIP" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "💡 Recomendación: Usa WiFi Compartido (más estable)" -ForegroundColor Yellow
}
elseif ($wifiIP) {
    Write-Host "✅ MODO: WIFI COMPARTIDO" -ForegroundColor Green
    Write-Host ""
    Write-Host "📍 Los maestros deben usar:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   http://coordinacion-tescha.local" -ForegroundColor Cyan -NoNewline
    Write-Host "  ⭐ (Recomendado)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   o" -ForegroundColor Gray
    Write-Host ""
    Write-Host "   http://$wifiIP" -ForegroundColor Cyan
    Write-Host ""
}
elseif ($hotspotIP) {
    Write-Host "✅ MODO: HOTSPOT (Compartir Internet)" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "📍 Los maestros deben usar:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   http://$hotspotIP" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "⚠️  Nota: coordinacion-tescha.local NO funcionará en hotspot" -ForegroundColor Yellow
    Write-Host ""
}
else {
    Write-Host "❌ NO SE DETECTÓ RED WIFI NI HOTSPOT" -ForegroundColor Red
    Write-Host ""
    Write-Host "Opciones:" -ForegroundColor Yellow
    Write-Host "1. Conéctate a un WiFi" -ForegroundColor White
    Write-Host "2. Activa el Hotspot (Compartir Internet)" -ForegroundColor White
    Write-Host ""
}

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Verificar servicios
Write-Host "🔍 ESTADO DE SERVICIOS:" -ForegroundColor Yellow
Write-Host ""

# Nginx
$nginx = Get-Process nginx -ErrorAction SilentlyContinue
if ($nginx) {
    Write-Host "   ✅ Nginx: Corriendo ($($nginx.Count) procesos)" -ForegroundColor Green
} else {
    Write-Host "   ❌ Nginx: NO está corriendo" -ForegroundColor Red
    Write-Host "      Ejecuta: cd C:\nginx; start nginx" -ForegroundColor Gray
}

# Frontend (puerto 3000)
$port3000 = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue
if ($port3000) {
    Write-Host "   ✅ Frontend: Corriendo en puerto 3000" -ForegroundColor Green
} else {
    Write-Host "   ❌ Frontend: NO está corriendo" -ForegroundColor Red
    Write-Host "      Ejecuta: cd frontend; npm run dev" -ForegroundColor Gray
}

# Backend (puerto 5000)
$port5000 = Get-NetTCPConnection -LocalPort 5000 -ErrorAction SilentlyContinue
if ($port5000) {
    Write-Host "   ✅ Backend: Corriendo en puerto 5000" -ForegroundColor Green
} else {
    Write-Host "   ❌ Backend: NO está corriendo" -ForegroundColor Red
    Write-Host "      Ejecuta: cd backend; npm run pm2:start" -ForegroundColor Gray
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Instrucciones finales
Write-Host "📝 INSTRUCCIONES PARA LOS MAESTROS:" -ForegroundColor Yellow
Write-Host ""

if ($wifiIP) {
    Write-Host "1. Conectarse al WiFi de la escuela" -ForegroundColor White
    Write-Host "2. Abrir navegador" -ForegroundColor White
    Write-Host "3. Escribir: http://coordinacion-tescha.local" -ForegroundColor Cyan
    Write-Host "4. ¡Listo!" -ForegroundColor Green
}
elseif ($hotspotIP) {
    Write-Host "1. Conectarse al WiFi: [TU NOMBRE DE HOTSPOT]" -ForegroundColor White
    Write-Host "2. Contraseña: [TU CONTRASEÑA]" -ForegroundColor White
    Write-Host "3. Abrir navegador" -ForegroundColor White
    Write-Host "4. Escribir: http://$hotspotIP" -ForegroundColor Cyan
    Write-Host "5. ¡Listo!" -ForegroundColor Green
}

Write-Host ""
pause
