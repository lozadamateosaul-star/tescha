# 🔄 REINICIAR SERVIDOR - APLICAR CAMBIOS

Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
Write-Host "🔄 REINICIANDO SERVIDOR BACKEND" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# 1. Detener procesos de Node.js
Write-Host "1️⃣ Deteniendo procesos de Node.js..." -ForegroundColor Green
$nodeProcesses = Get-Process node -ErrorAction SilentlyContinue
if ($nodeProcesses) {
    $nodeProcesses | Stop-Process -Force
    Write-Host "   ✅ Procesos detenidos: $($nodeProcesses.Count)" -ForegroundColor Green
} else {
    Write-Host "   ℹ️  No hay procesos de Node.js corriendo" -ForegroundColor Gray
}

Write-Host ""
Start-Sleep -Seconds 2

# 2. Iniciar servidor en nueva ventana
Write-Host "2️⃣ Iniciando servidor backend..." -ForegroundColor Green
Set-Location "c:\Users\dush3\Downloads\TESCHA\backend"

Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd 'c:\Users\dush3\Downloads\TESCHA\backend'; npm run dev"

Write-Host "   ✅ Servidor iniciado en nueva ventana" -ForegroundColor Green
Write-Host ""

# 3. Esperar a que el servidor esté listo
Write-Host "3️⃣ Esperando a que el servidor esté listo..." -ForegroundColor Green
Start-Sleep -Seconds 5

# 4. Verificar que el servidor responde
try {
    $response = Invoke-WebRequest -Uri "http://localhost:5000/health" -Method GET -TimeoutSec 5 -ErrorAction Stop
    if ($response.StatusCode -eq 200) {
        Write-Host "   ✅ Servidor respondiendo correctamente" -ForegroundColor Green
    }
} catch {
    Write-Host "   ⚠️  Servidor aún no responde (puede tardar unos segundos más)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
Write-Host "✅ SERVIDOR REINICIADO" -ForegroundColor Green
Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "📝 Cambios aplicados:" -ForegroundColor White
Write-Host "   - Rate limiter: 100 → 1000 requests/15min" -ForegroundColor Gray
Write-Host ""
Write-Host "🔄 Ahora recarga el navegador (Ctrl + Shift + R)" -ForegroundColor Yellow
Write-Host ""
