# Script de Instalación de Mejoras para TESCHA
# Ejecutar desde la raíz del proyecto

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "TESCHA - Instalación de Mejoras" -ForegroundColor Cyan
Write-Host "Gráficas y Métricas Históricas" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Instalar dependencias del backend
Write-Host "📦 Instalando dependencias del backend..." -ForegroundColor Yellow
Set-Location backend
npm install chartjs-node-canvas
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Dependencias del backend instaladas" -ForegroundColor Green
} else {
    Write-Host "❌ Error al instalar dependencias del backend" -ForegroundColor Red
    exit 1
}

# 2. Instalar dependencias del frontend
Write-Host ""
Write-Host "📦 Instalando dependencias del frontend..." -ForegroundColor Yellow
Set-Location ../frontend
npm install recharts
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Dependencias del frontend instaladas" -ForegroundColor Green
} else {
    Write-Host "❌ Error al instalar dependencias del frontend" -ForegroundColor Red
    exit 1
}

Set-Location ..

# 3. Crear base de datos (requiere PostgreSQL)
Write-Host ""
Write-Host "🗄️  Configuración de base de datos..." -ForegroundColor Yellow
Write-Host "⚠️  IMPORTANTE: Asegúrate de que PostgreSQL esté corriendo" -ForegroundColor Magenta
Write-Host ""

$ejecutarSQL = Read-Host "¿Deseas ejecutar el script SQL ahora? (s/n)"

if ($ejecutarSQL -eq "s" -or $ejecutarSQL -eq "S") {
    $dbUser = Read-Host "Usuario de PostgreSQL (default: postgres)"
    if ([string]::IsNullOrWhiteSpace($dbUser)) {
        $dbUser = "postgres"
    }
    
    $dbName = Read-Host "Nombre de la base de datos (default: tescha_db)"
    if ([string]::IsNullOrWhiteSpace($dbName)) {
        $dbName = "tescha_db"
    }
    
    Write-Host "Ejecutando script SQL..." -ForegroundColor Yellow
    psql -U $dbUser -d $dbName -f backend/database/add_metrics_tables.sql
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Tablas de métricas creadas exitosamente" -ForegroundColor Green
    } else {
        Write-Host "❌ Error al crear tablas. Verifica la conexión a PostgreSQL" -ForegroundColor Red
        Write-Host "Puedes ejecutar manualmente: psql -U $dbUser -d $dbName -f backend/database/add_metrics_tables.sql" -ForegroundColor Yellow
    }
} else {
    Write-Host "⏭️  Saltando configuración de base de datos" -ForegroundColor Yellow
    Write-Host "Ejecuta manualmente: psql -U postgres -d tescha_db -f backend/database/add_metrics_tables.sql" -ForegroundColor Cyan
}

# 4. Actualizar server.js
Write-Host ""
Write-Host "🔧 Configuración del servidor..." -ForegroundColor Yellow
Write-Host "⚠️  Debes agregar manualmente las siguientes líneas a backend/server.js:" -ForegroundColor Magenta
Write-Host ""
Write-Host "import metricasRoutes from './routes/metricas.js';" -ForegroundColor Cyan
Write-Host "app.use('/api/metricas', metricasRoutes);" -ForegroundColor Cyan
Write-Host "app.use('/api/analisis', metricasRoutes);" -ForegroundColor Cyan
Write-Host ""

# 5. Actualizar router del frontend
Write-Host "🔧 Configuración del frontend..." -ForegroundColor Yellow
Write-Host "⚠️  Debes agregar manualmente la ruta en tu router de React:" -ForegroundColor Magenta
Write-Host ""
Write-Host "import TendenciasAvanzadas from './pages/TendenciasAvanzadas';" -ForegroundColor Cyan
Write-Host "<Route path='/tendencias' element={<TendenciasAvanzadas />} />" -ForegroundColor Cyan
Write-Host ""

# 6. Calcular métricas iniciales
Write-Host "📊 Cálculo de métricas iniciales..." -ForegroundColor Yellow
Write-Host "⚠️  Después de iniciar el servidor, ejecuta:" -ForegroundColor Magenta
Write-Host ""
Write-Host "POST http://localhost:5000/api/metricas/calcular/1" -ForegroundColor Cyan
Write-Host "POST http://localhost:5000/api/metricas/calcular/2" -ForegroundColor Cyan
Write-Host "(Para cada periodo existente)" -ForegroundColor Gray
Write-Host ""

# Resumen
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "✅ INSTALACIÓN COMPLETADA" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📋 PRÓXIMOS PASOS:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Actualizar backend/server.js con las rutas de métricas" -ForegroundColor White
Write-Host "2. Actualizar el router del frontend con TendenciasAvanzadas" -ForegroundColor White
Write-Host "3. Reiniciar el servidor backend y frontend" -ForegroundColor White
Write-Host "4. Calcular métricas para periodos existentes" -ForegroundColor White
Write-Host "5. Acceder a /tendencias en el frontend" -ForegroundColor White
Write-Host ""
Write-Host "📚 Documentación completa en: ANALISIS-MEJORAS-GRAFICAS-PDF.md" -ForegroundColor Cyan
Write-Host ""
Write-Host "🎉 ¡Listo para usar las nuevas funcionalidades!" -ForegroundColor Green
Write-Host ""
