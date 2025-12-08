# 🚀 INSTALADOR AUTOMÁTICO DE TESCHA
# Ejecutar como Administrador

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                               ║" -ForegroundColor Cyan
Write-Host "║   🚀 INSTALADOR AUTOMÁTICO TESCHA                            ║" -ForegroundColor Cyan
Write-Host "║   Sistema de Coordinación de Inglés                           ║" -ForegroundColor Cyan
Write-Host "║                                                               ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Verificar permisos de administrador
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "❌ ERROR: Este script debe ejecutarse como Administrador" -ForegroundColor Red
    Write-Host "   Haz clic derecho en PowerShell y selecciona 'Ejecutar como administrador'" -ForegroundColor Yellow
    pause
    exit
}

Write-Host "✅ Ejecutando como Administrador" -ForegroundColor Green
Write-Host ""

# Paso 1: Verificar Node.js
Write-Host "📋 PASO 1: Verificando Node.js..." -ForegroundColor Cyan
$node = Get-Command node -ErrorAction SilentlyContinue

if ($node) {
    $nodeVersion = node --version
    Write-Host "   ✅ Node.js instalado: $nodeVersion" -ForegroundColor Green
} else {
    Write-Host "   ❌ Node.js NO está instalado" -ForegroundColor Red
    Write-Host "   Descarga desde: https://nodejs.org/" -ForegroundColor Yellow
    Write-Host "   Instala Node.js y vuelve a ejecutar este script" -ForegroundColor Yellow
    pause
    exit
}

Write-Host ""

# Paso 2: Verificar PostgreSQL
Write-Host "📋 PASO 2: Verificando PostgreSQL..." -ForegroundColor Cyan
$postgres = Get-Service postgresql* -ErrorAction SilentlyContinue

if ($postgres) {
    Write-Host "   ✅ PostgreSQL instalado" -ForegroundColor Green
    if ($postgres.Status -eq "Running") {
        Write-Host "   ✅ PostgreSQL corriendo" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  Iniciando PostgreSQL..." -ForegroundColor Yellow
        Start-Service $postgres.Name
    }
} else {
    Write-Host "   ❌ PostgreSQL NO está instalado" -ForegroundColor Red
    Write-Host "   Descarga desde: https://www.postgresql.org/download/windows/" -ForegroundColor Yellow
    Write-Host "   Instala PostgreSQL y vuelve a ejecutar este script" -ForegroundColor Yellow
    pause
    exit
}

Write-Host ""

# Paso 3: Instalar dependencias del backend
Write-Host "📋 PASO 3: Instalando dependencias del backend..." -ForegroundColor Cyan
cd "$PSScriptRoot\backend"

if (Test-Path "node_modules") {
    Write-Host "   ℹ️  Dependencias ya instaladas" -ForegroundColor Cyan
} else {
    Write-Host "   Instalando... (esto puede tardar 3-5 minutos)" -ForegroundColor Yellow
    npm install --silent
    Write-Host "   ✅ Dependencias instaladas" -ForegroundColor Green
}

Write-Host ""

# Paso 4: Configurar .env
Write-Host "📋 PASO 4: Configurando variables de entorno..." -ForegroundColor Cyan

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "   ✅ Archivo .env creado" -ForegroundColor Green
    Write-Host "   ⚠️  IMPORTANTE: Edita el archivo .env con tus credenciales" -ForegroundColor Yellow
} else {
    Write-Host "   ℹ️  Archivo .env ya existe" -ForegroundColor Cyan
}

Write-Host ""

# Paso 5: Instalar PM2
Write-Host "📋 PASO 5: Instalando PM2..." -ForegroundColor Cyan
$pm2 = Get-Command pm2 -ErrorAction SilentlyContinue

if ($pm2) {
    Write-Host "   ✅ PM2 ya está instalado" -ForegroundColor Green
} else {
    npm install -g pm2 --silent
    Write-Host "   ✅ PM2 instalado" -ForegroundColor Green
}

Write-Host ""

# Paso 6: Instalar dependencias del frontend
Write-Host "📋 PASO 6: Instalando dependencias del frontend..." -ForegroundColor Cyan
cd "$PSScriptRoot\frontend"

if (Test-Path "node_modules") {
    Write-Host "   ℹ️  Dependencias ya instaladas" -ForegroundColor Cyan
} else {
    Write-Host "   Instalando... (esto puede tardar 3-5 minutos)" -ForegroundColor Yellow
    npm install --silent
    Write-Host "   ✅ Dependencias instaladas" -ForegroundColor Green
}

Write-Host ""

# Paso 7: Construir frontend
Write-Host "📋 PASO 7: Construyendo frontend para producción..." -ForegroundColor Cyan

if (Test-Path "dist") {
    Write-Host "   ℹ️  Build ya existe" -ForegroundColor Cyan
    $rebuild = Read-Host "   ¿Reconstruir? (S/N)"
    if ($rebuild -eq "S" -or $rebuild -eq "s") {
        npm run build
        Write-Host "   ✅ Frontend construido" -ForegroundColor Green
    }
} else {
    npm run build
    Write-Host "   ✅ Frontend construido" -ForegroundColor Green
}

Write-Host ""

# Paso 8: Instalar serve
Write-Host "📋 PASO 8: Instalando servidor HTTP..." -ForegroundColor Cyan
$serve = Get-Command serve -ErrorAction SilentlyContinue

if ($serve) {
    Write-Host "   ✅ Serve ya está instalado" -ForegroundColor Green
} else {
    npm install -g serve --silent
    Write-Host "   ✅ Serve instalado" -ForegroundColor Green
}

Write-Host ""

# Paso 9: Instalar Bonjour
Write-Host "📋 PASO 9: Verificando Bonjour..." -ForegroundColor Cyan
$bonjour = Get-Service "Bonjour Service" -ErrorAction SilentlyContinue

if ($bonjour) {
    Write-Host "   ✅ Bonjour instalado" -ForegroundColor Green
    if ($bonjour.Status -ne "Running") {
        Start-Service "Bonjour Service"
    }
} else {
    Write-Host "   ❌ Bonjour NO está instalado" -ForegroundColor Red
    Write-Host "   Descarga desde: https://support.apple.com/kb/DL999" -ForegroundColor Yellow
    $abrir = Read-Host "   ¿Abrir página de descarga? (S/N)"
    if ($abrir -eq "S" -or $abrir -eq "s") {
        Start-Process "https://support.apple.com/kb/DL999"
    }
}

Write-Host ""

# Paso 10: Cambiar nombre de PC
Write-Host "📋 PASO 10: Configurando nombre de PC..." -ForegroundColor Cyan
$currentName = $env:COMPUTERNAME

if ($currentName -eq "coordinacion-tescha") {
    Write-Host "   ✅ Nombre de PC ya configurado" -ForegroundColor Green
} else {
    Write-Host "   Nombre actual: $currentName" -ForegroundColor White
    Write-Host "   Nombre deseado: coordinacion-tescha" -ForegroundColor White
    $cambiar = Read-Host "   ¿Cambiar nombre de PC? (S/N) [Requiere reinicio]"
    
    if ($cambiar -eq "S" -or $cambiar -eq "s") {
        Rename-Computer -NewName "coordinacion-tescha" -Force
        Write-Host "   ✅ Nombre cambiado" -ForegroundColor Green
        Write-Host "   ⚠️  DEBES REINICIAR la PC" -ForegroundColor Yellow
        $reiniciar = Read-Host "   ¿Reiniciar ahora? (S/N)"
        if ($reiniciar -eq "S" -or $reiniciar -eq "s") {
            Restart-Computer -Force
        }
    }
}

Write-Host ""

# Paso 11: Instalar Nginx
Write-Host "📋 PASO 11: Instalando Nginx..." -ForegroundColor Cyan

if (Test-Path "C:\nginx") {
    Write-Host "   ✅ Nginx ya está instalado" -ForegroundColor Green
} else {
    Write-Host "   Ejecutando instalador de Nginx..." -ForegroundColor Yellow
    cd $PSScriptRoot
    if (Test-Path "instalar-nginx.ps1") {
        & ".\instalar-nginx.ps1"
    } else {
        Write-Host "   ⚠️  Script de instalación de Nginx no encontrado" -ForegroundColor Yellow
    }
}

Write-Host ""

# Resumen final
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                                                               ║" -ForegroundColor Green
Write-Host "║   ✅ INSTALACIÓN COMPLETADA                                  ║" -ForegroundColor Green
Write-Host "║                                                               ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

Write-Host "📝 PRÓXIMOS PASOS:" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Editar archivo .env con tus credenciales:" -ForegroundColor White
Write-Host "   notepad $PSScriptRoot\backend\.env" -ForegroundColor Cyan
Write-Host ""
Write-Host "2. Crear la base de datos:" -ForegroundColor White
Write-Host "   psql -U postgres -c 'CREATE DATABASE tescha;'" -ForegroundColor Cyan
Write-Host "   psql -U postgres -d tescha -f $PSScriptRoot\backend\database\schema.sql" -ForegroundColor Cyan
Write-Host ""
Write-Host "3. Iniciar servicios:" -ForegroundColor White
Write-Host "   cd $PSScriptRoot\backend" -ForegroundColor Cyan
Write-Host "   npm run pm2:start" -ForegroundColor Cyan
Write-Host ""
Write-Host "4. Iniciar frontend:" -ForegroundColor White
Write-Host "   cd $PSScriptRoot\frontend" -ForegroundColor Cyan
Write-Host "   serve -s dist -l 3000" -ForegroundColor Cyan
Write-Host ""
Write-Host "5. Acceder a la aplicación:" -ForegroundColor White
Write-Host "   http://coordinacion-tescha.local" -ForegroundColor Yellow
Write-Host ""

pause
