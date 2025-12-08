import dotenv from 'dotenv';
import pool from '../config/database.js';

dotenv.config();

async function verificarDatos() {
  try {
    console.log('🔍 Verificando datos en la base de datos...\n');
    
    // 1. Verificar alumnos
    const alumnosResult = await pool.query('SELECT COUNT(*) as total FROM alumnos');
    console.log(`👨‍🎓 Total alumnos en BD: ${alumnosResult.rows[0].total}`);
    
    // 2. Ver algunos alumnos de ejemplo
    const ejemplosResult = await pool.query('SELECT id, matricula, nombre_completo, tipo_alumno FROM alumnos LIMIT 10');
    console.log('\n📋 Ejemplos de alumnos:');
    console.table(ejemplosResult.rows);
    
    // 3. Verificar pagos
    const pagosResult = await pool.query(`
      SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE estatus = 'completado') as completados,
        COUNT(*) FILTER (WHERE estatus = 'pendiente') as pendientes,
        SUM(monto) FILTER (WHERE estatus = 'completado') as ingresos
      FROM pagos
    `);
    console.log('\n💰 Resumen de pagos:');
    console.table(pagosResult.rows);
    
    // 4. Ver pagos sin nombre de alumno
    const pagosSinNombreResult = await pool.query(`
      SELECT p.id, p.alumno_id, p.monto, p.concepto, p.estatus,
             a.nombre_completo
      FROM pagos p
      LEFT JOIN alumnos a ON p.alumno_id = a.id
      LIMIT 10
    `);
    console.log('\n🔎 Verificación de JOIN pagos-alumnos:');
    console.table(pagosSinNombreResult.rows);
    
    // 5. Verificar estructura de alumnos
    const estructuraResult = await pool.query(`
      SELECT column_name, data_type 
      FROM information_schema.columns 
      WHERE table_name = 'alumnos' 
      ORDER BY ordinal_position
    `);
    console.log('\n📊 Estructura tabla alumnos:');
    console.table(estructuraResult.rows);
    
    await pool.end();
    
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

verificarDatos();
