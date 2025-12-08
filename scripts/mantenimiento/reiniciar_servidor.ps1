# Script para reiniciar el servidor backend
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "🔄 REINICIANDO SERVIDOR BACKEND" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Detener procesos de Node existentes
Write-Host "🛑 Deteniendo procesos de Node..." -ForegroundColor Yellow
$nodeProcesses = Get-Process node -ErrorAction SilentlyContinue
if ($nodeProcesses) {
    $nodeProcesses | ForEach-Object {
        Write-Host "   Deteniendo proceso ID: $($_.Id)" -ForegroundColor Gray
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 2
    Write-Host "✅ Procesos detenidos" -ForegroundColor Green
} else {
    Write-Host "ℹ️  No hay procesos de Node corriendo" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "🚀 Iniciando servidor backend..." -ForegroundColor Yellow
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "IMPORTANTE: El servidor se iniciará en una nueva ventana" -ForegroundColor Yellow
Write-Host "Presiona Ctrl+C en esa ventana para detener el servidor" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Cambiar al directorio backend e iniciar el servidor
Set-Location backend
Start-Process powershell -ArgumentList "-NoExit", "-Command", "npm run dev"

Write-Host "✅ Servidor iniciado en nueva ventana" -ForegroundColor Green
Write-Host ""
Write-Host "📝 Verifica en la ventana del servidor que:" -ForegroundColor Cyan
Write-Host "   1. El servidor arrancó correctamente" -ForegroundColor White
Write-Host "   2. No hay errores de conexión a la base de datos" -ForegroundColor White
Write-Host "   3. Las rutas se cargaron correctamente" -ForegroundColor White
Write-Host ""
