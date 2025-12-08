import dotenv from 'dotenv';
import pool from '../config/database.js';

dotenv.config();

async function resetDatabase() {
  const client = await pool.connect();
  
  try {
    console.log('🗑️  Iniciando limpieza de base de datos...\n');
    
    await client.query('BEGIN');
    
    // 1. Eliminar pagos
    const pagosResult = await client.query('DELETE FROM pagos');
    console.log(`✅ Eliminados ${pagosResult.rowCount} pagos`);
    
    // 2. Eliminar calificaciones
    const calificacionesResult = await client.query('DELETE FROM calificaciones');
    console.log(`✅ Eliminadas ${calificacionesResult.rowCount} calificaciones`);
    
    // 3. Eliminar asistencias
    const asistenciasResult = await client.query('DELETE FROM asistencias');
    console.log(`✅ Eliminadas ${asistenciasResult.rowCount} asistencias`);
    
    // 4. Eliminar inscripciones
    const inscripcionesResult = await client.query('DELETE FROM inscripciones');
    console.log(`✅ Eliminadas ${inscripcionesResult.rowCount} inscripciones`);
    
    // 5. Eliminar grupos
    const gruposResult = await client.query('DELETE FROM grupos');
    console.log(`✅ Eliminados ${gruposResult.rowCount} grupos`);
    
    // 5.5. Eliminar salones
    const salonesResult = await client.query('DELETE FROM salones');
    console.log(`✅ Eliminados ${salonesResult.rowCount} salones`);
    
    // 6. Eliminar alumnos
    const alumnosResult = await client.query('DELETE FROM alumnos');
    console.log(`✅ Eliminados ${alumnosResult.rowCount} alumnos`);
    
    // 7. Eliminar maestros
    const maestrosResult = await client.query('DELETE FROM maestros');
    console.log(`✅ Eliminados ${maestrosResult.rowCount} maestros`);
    
    // 8. Eliminar usuarios (excepto coordinador)
    const usuariosResult = await client.query("DELETE FROM usuarios WHERE rol IN ('maestro', 'alumno')");
    console.log(`✅ Eliminados ${usuariosResult.rowCount} usuarios (maestros y alumnos)`);
    
    // 9. Resetear secuencias
    await client.query(`
      ALTER SEQUENCE pagos_id_seq RESTART WITH 1;
      ALTER SEQUENCE calificaciones_id_seq RESTART WITH 1;
      ALTER SEQUENCE asistencias_id_seq RESTART WITH 1;
      ALTER SEQUENCE inscripciones_id_seq RESTART WITH 1;
      ALTER SEQUENCE grupos_id_seq RESTART WITH 1;
      ALTER SEQUENCE salones_id_seq RESTART WITH 1;
      ALTER SEQUENCE alumnos_id_seq RESTART WITH 1;
      ALTER SEQUENCE maestros_id_seq RESTART WITH 1;
    `);
    console.log('✅ Secuencias reseteadas\n');
    
    await client.query('COMMIT');
    
    // Verificar estado final
    console.log('📊 Estado final de la base de datos:\n');
    const verification = await client.query(`
      SELECT 'Alumnos' as tabla, COUNT(*) as registros FROM alumnos
      UNION ALL
      SELECT 'Maestros', COUNT(*) FROM maestros
      UNION ALL
      SELECT 'Grupos', COUNT(*) FROM grupos
      UNION ALL
      SELECT 'Pagos', COUNT(*) FROM pagos
      UNION ALL
      SELECT 'Usuarios', COUNT(*) FROM usuarios
      UNION ALL
      SELECT 'Coordinadores', COUNT(*) FROM usuarios WHERE rol = 'coordinador'
    `);
    
    console.table(verification.rows);
    
    console.log('\n✅ Base de datos limpiada exitosamente');
    console.log('🔑 El usuario coordinador se mantiene intacto');
    console.log('🎯 Sistema listo para registrar nuevos alumnos y maestros\n');
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Error al limpiar la base de datos:', error.message);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

resetDatabase().catch(err => {
  console.error('Error fatal:', err);
  process.exit(1);
});
