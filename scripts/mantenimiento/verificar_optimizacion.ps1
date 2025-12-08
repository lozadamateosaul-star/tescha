# Script de verificación de optimización
# Verifica que las vistas materializadas se crearon correctamente

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "🔍 VERIFICANDO OPTIMIZACIÓN" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Verificar vistas materializadas
Write-Host "📊 Verificando vistas materializadas..." -ForegroundColor Green

$queries = @(
    @{
        Nombre = "mv_pagos_completos"
        Query = "SELECT COUNT(*) as count FROM mv_pagos_completos"
    },
    @{
        Nombre = "mv_dashboard_metricas"
        Query = "SELECT COUNT(*) as count FROM mv_dashboard_metricas"
    },
    @{
        Nombre = "mv_calificaciones_completas"
        Query = "SELECT COUNT(*) as count FROM mv_calificaciones_completas"
    },
    @{
        Nombre = "mv_asistencias_completas"
        Query = "SELECT COUNT(*) as count FROM mv_asistencias_completas"
    }
)

$allSuccess = $true

foreach ($q in $queries) {
    try {
        $result = psql -U postgres -d tescha_db -t -c $q.Query 2>&1
        if ($LASTEXITCODE -eq 0) {
            $count = $result.Trim()
            Write-Host "  ✅ $($q.Nombre): $count registros" -ForegroundColor Green
        } else {
            Write-Host "  ❌ $($q.Nombre): ERROR" -ForegroundColor Red
            $allSuccess = $false
        }
    } catch {
        Write-Host "  ❌ $($q.Nombre): ERROR - $_" -ForegroundColor Red
        $allSuccess = $false
    }
}

Write-Host ""

# Verificar que las columnas redundantes fueron eliminadas
Write-Host "🔧 Verificando normalización de tabla pagos..." -ForegroundColor Green

$checkColumns = psql -U postgres -d tescha_db -t -c "SELECT column_name FROM information_schema.columns WHERE table_name = 'pagos' AND column_name IN ('alumno_id', 'periodo_id')" 2>&1

if ($checkColumns -match "alumno_id" -or $checkColumns -match "periodo_id") {
    Write-Host "  ⚠️  ADVERTENCIA: Columnas redundantes aún existen" -ForegroundColor Yellow
    Write-Host "     La optimización SQL puede no haberse ejecutado completamente" -ForegroundColor Yellow
} else {
    Write-Host "  ✅ Columnas redundantes eliminadas correctamente" -ForegroundColor Green
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan

if ($allSuccess) {
    Write-Host "✅ OPTIMIZACIÓN VERIFICADA EXITOSAMENTE" -ForegroundColor Green
    Write-Host "   Todas las vistas materializadas están funcionando" -ForegroundColor Green
} else {
    Write-Host "⚠️  ADVERTENCIA: Algunas vistas no se encontraron" -ForegroundColor Yellow
    Write-Host "   Es posible que necesites ejecutar el script SQL nuevamente" -ForegroundColor Yellow
}

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
