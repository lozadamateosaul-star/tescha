Write-Host "Instalando Nginx..." -ForegroundColor Cyan

# Descargar
$url = "http://nginx.org/download/nginx-1.24.0.zip"
$zip = "$env:TEMP\nginx.zip"

Write-Host "Descargando..."
Invoke-WebRequest -Uri $url -OutFile $zip

Write-Host "Extrayendo..."
Expand-Archive -Path $zip -DestinationPath "C:\" -Force

# Renombrar
$folder = Get-ChildItem "C:\" | Where-Object { $_.Name -like "nginx-*" } | Select-Object -First 1
if (Test-Path "C:\nginx") { Remove-Item "C:\nginx" -Recurse -Force }
Rename-Item -Path $folder.FullName -NewName "nginx"

Write-Host "Nginx instalado en C:\nginx" -ForegroundColor Green

# Copiar configuración
$config = "$PSScriptRoot\nginx-ip-directa.conf"
if (Test-Path $config) {
    Copy-Item $config "C:\nginx\conf\nginx.conf" -Force
    Write-Host "Configuracion copiada" -ForegroundColor Green
}

# Probar
cd C:\nginx
.\nginx.exe -t

Write-Host ""
Write-Host "Iniciando Nginx..." -ForegroundColor Yellow
Start-Process nginx.exe -WindowStyle Hidden

Start-Sleep 2

$proc = Get-Process nginx -ErrorAction SilentlyContinue
if ($proc) {
    Write-Host "Nginx iniciado correctamente!" -ForegroundColor Green
    Write-Host "Accede a: http://coordinacion-tescha.local" -ForegroundColor Yellow
} else {
    Write-Host "Error al iniciar Nginx" -ForegroundColor Red
}

pause
