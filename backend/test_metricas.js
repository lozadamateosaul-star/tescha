import pool from './config/database.js';

console.log('🧪 VERIFICANDO LÓGICA DE FECHAS - MÉTRICAS FINANCIERAS\n');

async function verificarMetricas() {
    try {
        // 1. Verificar fechas de pagos
        console.log('1️⃣ FECHAS DE PAGOS COMPLETADOS (últimos 20):');
        const fechas = await pool.query(`
            SELECT 
                DATE(fecha_pago) as fecha,
                COUNT(*) as cantidad_pagos,
                SUM(monto) as total_ingresos
            FROM pagos
            WHERE estatus = 'completado' 
              AND fecha_pago IS NOT NULL
            GROUP BY DATE(fecha_pago)
            ORDER BY fecha DESC
            LIMIT 20
        `);
        console.table(fechas.rows);

        // 2. Diagnóstico
        console.log('\n8️⃣ DIAGNÓSTICO:');
        const diagnostico = await pool.query(`
            SELECT 
                COUNT(DISTINCT DATE(fecha_pago)) as fechas_diferentes,
                MIN(DATE(fecha_pago)) as fecha_mas_antigua,
                MAX(DATE(fecha_pago)) as fecha_mas_reciente,
                COUNT(*) as total_pagos_completados
            FROM pagos
            WHERE estatus = 'completado' 
              AND fecha_pago IS NOT NULL
        `);
        console.table(diagnostico.rows);

        // 3. Resumen comparativo
        console.log('\n7️⃣ RESUMEN COMPARATIVO:');
        const resumen = await pool.query(`
            SELECT 
                (SELECT COUNT(*) FROM pagos WHERE estatus = 'completado' AND DATE(fecha_pago) = CURRENT_DATE) as pagos_hoy,
                (SELECT COUNT(*) FROM pagos WHERE estatus = 'completado' AND fecha_pago >= CURRENT_DATE - INTERVAL '7 days') as pagos_semana,
                (SELECT COUNT(*) FROM pagos WHERE estatus = 'completado' AND EXTRACT(MONTH FROM fecha_pago) = EXTRACT(MONTH FROM CURRENT_DATE) AND EXTRACT(YEAR FROM fecha_pago) = EXTRACT(YEAR FROM CURRENT_DATE)) as pagos_mes,
                (SELECT COALESCE(SUM(monto), 0) FROM pagos WHERE estatus = 'completado' AND DATE(fecha_pago) = CURRENT_DATE) as ingresos_hoy,
                (SELECT COALESCE(SUM(monto), 0) FROM pagos WHERE estatus = 'completado' AND fecha_pago >= CURRENT_DATE - INTERVAL '7 days') as ingresos_semana,
                (SELECT COALESCE(SUM(monto), 0) FROM pagos WHERE estatus = 'completado' AND EXTRACT(MONTH FROM fecha_pago) = EXTRACT(MONTH FROM CURRENT_DATE) AND EXTRACT(YEAR FROM fecha_pago) = EXTRACT(YEAR FROM CURRENT_DATE)) as ingresos_mes
        `);
        console.table(resumen.rows);

        // 4. Distribución por mes
        console.log('\n9️⃣ DISTRIBUCIÓN POR MES:');
        const distribucion = await pool.query(`
            SELECT 
                TO_CHAR(fecha_pago, 'YYYY-MM') as mes,
                COUNT(*) as cantidad_pagos,
                SUM(monto) as total_ingresos
            FROM pagos
            WHERE estatus = 'completado' 
              AND fecha_pago IS NOT NULL
            GROUP BY TO_CHAR(fecha_pago, 'YYYY-MM')
            ORDER BY mes DESC
            LIMIT 12
        `);
        console.table(distribucion.rows);

        console.log('\n✅ Verificación completada');
        process.exit(0);
    } catch (error) {
        console.error('❌ Error:', error);
        process.exit(1);
    }
}

verificarMetricas();
