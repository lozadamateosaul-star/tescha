import pool from '../config/database.js';

async function testTendencias() {
  try {
    const result = await pool.query(
      `SELECT 
        p.nombre as periodo,
        COALESCE(alumnos_count.total, 0) as total_alumnos,
        COALESCE(grupos_count.total, 0) as total_grupos,
        COALESCE(ingresos_sum.total, 0) as ingresos
      FROM periodos p
      LEFT JOIN (
        SELECT periodo_id, COUNT(DISTINCT alumno_id) as total
        FROM inscripciones
        GROUP BY periodo_id
      ) alumnos_count ON p.id = alumnos_count.periodo_id
      LEFT JOIN (
        SELECT periodo_id, COUNT(DISTINCT id) as total
        FROM grupos
        GROUP BY periodo_id
      ) grupos_count ON p.id = grupos_count.periodo_id
      LEFT JOIN (
        SELECT periodo_id, SUM(monto) as total
        FROM pagos
        WHERE estatus = 'completado'
        GROUP BY periodo_id
      ) ingresos_sum ON p.id = ingresos_sum.periodo_id
      ORDER BY p.fecha_inicio_clases DESC
      LIMIT 6`
    );
    
    console.log('📊 Datos de tendencias:');
    console.table(result.rows);
    console.log(`\n✅ Total registros: ${result.rows.length}`);
    
    await pool.end();
  } catch (error) {
    console.error('❌ Error:', error.message);
    await pool.end();
  }
}

testTendencias();
