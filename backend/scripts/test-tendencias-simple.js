import pool from '../config/database.js';

async function testTendenciasSimple() {
  try {
    console.log('🔍 Probando query de tendencias...\n');
    
    const result = await pool.query(
      `SELECT 
        p.nombre as periodo,
        COALESCE(ingresos_sum.total, 0) as ingresos
      FROM periodos p
      LEFT JOIN (
        SELECT periodo_id, SUM(monto) as total
        FROM pagos
        WHERE estatus = 'completado'
        GROUP BY periodo_id
      ) ingresos_sum ON p.id = ingresos_sum.periodo_id
      ORDER BY p.fecha_inicio_clases ASC
      LIMIT 6`
    );
    
    console.log('📊 Resultados:');
    console.table(result.rows);
    console.log(`\n✅ Total de registros: ${result.rows.length}`);
    console.log('\n📝 JSON que el backend devolvería:');
    console.log(JSON.stringify(result.rows, null, 2));
    
    await pool.end();
  } catch (error) {
    console.error('❌ Error:', error.message);
    await pool.end();
  }
}

testTendenciasSimple();
