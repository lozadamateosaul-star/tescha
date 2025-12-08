# 🚀 REINICIAR NGINX Y PROBAR
# Ejecutar como Administrador

Write-Host "Deteniendo Nginx..." -ForegroundColor Yellow
taskkill /f /im nginx.exe 2>$null

Start-Sleep 2

Write-Host "Iniciando Nginx..." -ForegroundColor Yellow
cd C:\nginx
start nginx

Start-Sleep 3

Write-Host ""
Write-Host "Verificando..." -ForegroundColor Cyan
$nginx = Get-Process nginx -ErrorAction SilentlyContinue
if ($nginx) {
    Write-Host "✅ Nginx corriendo ($($nginx.Count) procesos)" -ForegroundColor Green
} else {
    Write-Host "❌ Nginx NO está corriendo" -ForegroundColor Red
}

Write-Host ""
Write-Host "Probando conexión..." -ForegroundColor Cyan
try {
    $response = Invoke-WebRequest -Uri "http://localhost" -UseBasicParsing -TimeoutSec 5
    Write-Host "✅ Nginx responde: $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "❌ Error: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Ver logs:" -ForegroundColor Yellow
    Get-Content C:\nginx\logs\error.log -Tail 10
}

Write-Host ""
Write-Host "Prueba en el navegador:" -ForegroundColor Cyan
Write-Host "  http://coordinacion-tescha.local" -ForegroundColor Yellow
Write-Host "  http://192.168.1.132" -ForegroundColor Yellow

pause
