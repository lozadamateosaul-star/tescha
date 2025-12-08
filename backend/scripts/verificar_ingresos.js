import pool from '../config/database.js';

async function verificarIngresos() {
  try {
    const res = await pool.query(`
      SELECT 
        SUM(monto) as total_ingresos, 
        COUNT(*) as total_pagos,
        AVG(monto) as promedio
      FROM pagos 
      WHERE estatus = 'completado' AND periodo_id = 2
    `);
    
    console.log('📊 Verificación de Ingresos:');
    console.log('====================================');
    console.log('Total de pagos completados:', res.rows[0].total_pagos);
    console.log('Total ingresos:', `$${parseFloat(res.rows[0].total_ingresos).toLocaleString('es-MX', { minimumFractionDigits: 2 })}`);
    console.log('Promedio por pago:', `$${parseFloat(res.rows[0].promedio).toLocaleString('es-MX', { minimumFractionDigits: 2 })}`);
    
    await pool.end();
  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

verificarIngresos();
