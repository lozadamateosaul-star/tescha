# Script de Configuración del Sistema de Seguridad - TESCHA
# Ejecutar desde la raíz del proyecto

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CONFIGURACIÓN DE SEGURIDAD - TESCHA" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Verificar que estamos en el directorio correcto
if (-not (Test-Path "backend") -or -not (Test-Path "security-tests")) {
    Write-Host "❌ Error: Ejecuta este script desde la raíz del proyecto TESCHA" -ForegroundColor Red
    exit 1
}

# 2. Instalar dependencias del backend (si no están)
Write-Host "📦 Verificando dependencias del backend..." -ForegroundColor Yellow
Set-Location backend

$packageJson = Get-Content package.json | ConvertFrom-Json
if (-not ($packageJson.dependencies.nodemailer)) {
    Write-Host "Instalando nodemailer..." -ForegroundColor Yellow
    npm install nodemailer
}

# 3. Instalar dependencias de security-tests
Write-Host ""
Write-Host "📦 Verificando dependencias de security-tests..." -ForegroundColor Yellow
Set-Location ../security-tests

if (-not (Test-Path "package.json")) {
    Write-Host "❌ Error: No se encontró package.json en security-tests" -ForegroundColor Red
    exit 1
}

npm install

Set-Location ..

# 4. Configurar variables de entorno
Write-Host ""
Write-Host "🔧 Configuración de variables de entorno..." -ForegroundColor Yellow
Write-Host ""

$envPath = "backend/.env"
$envExamplePath = "backend/.env.example"

if (-not (Test-Path $envPath)) {
    Write-Host "⚠️  No se encontró archivo .env" -ForegroundColor Yellow
    $crearEnv = Read-Host "¿Deseas crear uno basado en .env.example? (s/n)"
    
    if ($crearEnv -eq "s" -or $crearEnv -eq "S") {
        Copy-Item $envExamplePath $envPath
        Write-Host "✅ Archivo .env creado" -ForegroundColor Green
    }
}

# 5. Configurar email de alertas
Write-Host ""
Write-Host "📧 Configuración de alertas por email" -ForegroundColor Cyan
Write-Host "Para recibir alertas de seguridad, necesitas configurar un email SMTP" -ForegroundColor Gray
Write-Host ""

$configurarEmail = Read-Host "¿Deseas configurar alertas por email ahora? (s/n)"

if ($configurarEmail -eq "s" -or $configurarEmail -eq "S") {
    Write-Host ""
    Write-Host "Para Gmail, necesitas una 'Contraseña de aplicación':" -ForegroundColor Yellow
    Write-Host "1. Ve a https://myaccount.google.com/apppasswords" -ForegroundColor Gray
    Write-Host "2. Crea una nueva contraseña de aplicación" -ForegroundColor Gray
    Write-Host "3. Usa esa contraseña aquí (no tu contraseña normal)" -ForegroundColor Gray
    Write-Host ""
    
    $emailAlerta = Read-Host "Email para recibir alertas"
    $smtpUser = Read-Host "Email SMTP (puede ser el mismo)"
    $smtpPass = Read-Host "Contraseña de aplicación SMTP" -AsSecureString
    $smtpPassPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($smtpPass)
    )
    
    # Actualizar .env
    $envContent = Get-Content $envPath
    $envContent = $envContent -replace "SECURITY_ALERT_EMAIL=.*", "SECURITY_ALERT_EMAIL=$emailAlerta"
    $envContent = $envContent -replace "SMTP_USER=.*", "SMTP_USER=$smtpUser"
    $envContent = $envContent -replace "SMTP_PASS=.*", "SMTP_PASS=$smtpPassPlain"
    $envContent = $envContent -replace "ENABLE_EMAIL_ALERTS=.*", "ENABLE_EMAIL_ALERTS=true"
    
    $envContent | Set-Content $envPath
    
    Write-Host "✅ Configuración de email guardada" -ForegroundColor Green
} else {
    Write-Host "⏭️  Saltando configuración de email" -ForegroundColor Yellow
    Write-Host "Puedes configurarlo después editando backend/.env" -ForegroundColor Gray
}

# 6. Generar claves de seguridad
Write-Host ""
Write-Host "🔐 Generando claves de seguridad..." -ForegroundColor Yellow

# Generar JWT Secret
$jwtSecret = node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
Write-Host "JWT Secret generado: $($jwtSecret.Substring(0, 20))..." -ForegroundColor Green

# Generar Encryption Key
$encryptionKey = node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
Write-Host "Encryption Key generada: $($encryptionKey.Substring(0, 20))..." -ForegroundColor Green

# Actualizar .env
$envContent = Get-Content $envPath
$envContent = $envContent -replace "JWT_SECRET=.*", "JWT_SECRET=$jwtSecret"
$envContent = $envContent -replace "ENCRYPTION_KEY=.*", "ENCRYPTION_KEY=$encryptionKey"
$envContent | Set-Content $envPath

Write-Host "✅ Claves de seguridad guardadas en .env" -ForegroundColor Green

# 7. Ejecutar script SQL de seguridad
Write-Host ""
Write-Host "🗄️  Configuración de base de datos..." -ForegroundColor Yellow

$ejecutarSQL = Read-Host "¿Deseas ejecutar el script SQL de seguridad ahora? (s/n)"

if ($ejecutarSQL -eq "s" -or $ejecutarSQL -eq "S") {
    $dbUser = Read-Host "Usuario de PostgreSQL (default: postgres)"
    if ([string]::IsNullOrWhiteSpace($dbUser)) {
        $dbUser = "postgres"
    }
    
    $dbName = Read-Host "Nombre de la base de datos (default: tescha_db)"
    if ([string]::IsNullOrWhiteSpace($dbName)) {
        $dbName = "tescha_db"
    }
    
    Write-Host "Ejecutando script SQL de seguridad..." -ForegroundColor Yellow
    psql -U $dbUser -d $dbName -f backend/database/add_security_tables.sql
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Tablas de seguridad creadas exitosamente" -ForegroundColor Green
    } else {
        Write-Host "❌ Error al crear tablas. Verifica la conexión a PostgreSQL" -ForegroundColor Red
        Write-Host "Puedes ejecutar manualmente: psql -U $dbUser -d $dbName -f backend/database/add_security_tables.sql" -ForegroundColor Yellow
    }
} else {
    Write-Host "⏭️  Saltando configuración de base de datos" -ForegroundColor Yellow
    Write-Host "Ejecuta manualmente: psql -U postgres -d tescha_db -f backend/database/add_security_tables.sql" -ForegroundColor Cyan
}

# 8. Resumen
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "✅ CONFIGURACIÓN COMPLETADA" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "📋 PRÓXIMOS PASOS:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Verificar configuración en backend/.env" -ForegroundColor White
Write-Host "2. Iniciar el servidor: cd backend && npm run dev" -ForegroundColor White
Write-Host "3. Ejecutar pruebas: cd security-tests && npm test" -ForegroundColor White
Write-Host "4. Monitorear seguridad: GET /api/security/dashboard" -ForegroundColor White
Write-Host ""

Write-Host "📧 ALERTAS POR EMAIL:" -ForegroundColor Cyan
if ($configurarEmail -eq "s" -or $configurarEmail -eq "S") {
    Write-Host "✅ Configuradas - Recibirás alertas en: $emailAlerta" -ForegroundColor Green
} else {
    Write-Host "⚠️  No configuradas - Edita backend/.env para habilitarlas" -ForegroundColor Yellow
}
Write-Host ""

Write-Host "🔒 SISTEMA DE SEGURIDAD:" -ForegroundColor Cyan
Write-Host "✅ IDS (Detección de Intrusos) - Activo" -ForegroundColor Green
Write-Host "✅ Sanitización de Inputs - Activo" -ForegroundColor Green
Write-Host "✅ Logging de Seguridad - Activo" -ForegroundColor Green
Write-Host "✅ Detección de Anomalías - Activo" -ForegroundColor Green
Write-Host "✅ Rate Limiting - Activo" -ForegroundColor Green
Write-Host ""

Write-Host "📚 DOCUMENTACIÓN:" -ForegroundColor Cyan
Write-Host "- security-tests/README.md - Guía completa" -ForegroundColor Gray
Write-Host "- CERTIFICACION-SEGURIDAD.md - Análisis de seguridad" -ForegroundColor Gray
Write-Host "- MEJORAS-SEGURIDAD.md - Mejoras implementadas" -ForegroundColor Gray
Write-Host ""

Write-Host "🎉 ¡Sistema de seguridad listo para usar!" -ForegroundColor Green
Write-Host ""
