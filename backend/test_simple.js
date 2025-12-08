import pool from './config/database.js';

async function verificar() {
    try {
        console.log('DIAGNOSTICO:');
        const diag = await pool.query(`
            SELECT 
                COUNT(DISTINCT DATE(fecha_pago)) as fechas_diferentes,
                MIN(DATE(fecha_pago)) as fecha_antigua,
                MAX(DATE(fecha_pago)) as fecha_reciente,
                COUNT(*) as total_pagos
            FROM pagos
            WHERE estatus = 'completado' AND fecha_pago IS NOT NULL
        `);
        console.log(JSON.stringify(diag.rows[0], null, 2));

        console.log('\nRESUMEN:');
        const res = await pool.query(`
            SELECT 
                (SELECT COUNT(*) FROM pagos WHERE estatus = 'completado' AND DATE(fecha_pago) = CURRENT_DATE) as pagos_hoy,
                (SELECT COUNT(*) FROM pagos WHERE estatus = 'completado' AND fecha_pago >= CURRENT_DATE - INTERVAL '7 days') as pagos_semana,
                (SELECT COUNT(*) FROM pagos WHERE estatus = 'completado' AND EXTRACT(MONTH FROM fecha_pago) = EXTRACT(MONTH FROM CURRENT_DATE) AND EXTRACT(YEAR FROM fecha_pago) = EXTRACT(YEAR FROM CURRENT_DATE)) as pagos_mes,
                (SELECT COALESCE(SUM(monto), 0) FROM pagos WHERE estatus = 'completado' AND DATE(fecha_pago) = CURRENT_DATE) as ingresos_hoy,
                (SELECT COALESCE(SUM(monto), 0) FROM pagos WHERE estatus = 'completado' AND fecha_pago >= CURRENT_DATE - INTERVAL '7 days') as ingresos_semana,
                (SELECT COALESCE(SUM(monto), 0) FROM pagos WHERE estatus = 'completado' AND EXTRACT(MONTH FROM fecha_pago) = EXTRACT(MONTH FROM CURRENT_DATE) AND EXTRACT(YEAR FROM fecha_pago) = EXTRACT(YEAR FROM CURRENT_DATE)) as ingresos_mes
        `);
        console.log(JSON.stringify(res.rows[0], null, 2));

        process.exit(0);
    } catch (error) {
        console.error('Error:', error.message);
        process.exit(1);
    }
}

verificar();
