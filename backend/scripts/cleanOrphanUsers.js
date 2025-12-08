import pool from '../config/database.js';

/**
 * Script para limpiar usuarios huérfanos
 * Elimina usuarios que no tienen alumno o maestro asociado
 */
async function cleanOrphanUsers() {
  const client = await pool.connect();
  
  try {
    console.log('🧹 Iniciando limpieza de usuarios huérfanos...');
    
    // Limpiar usuarios de tipo alumno sin alumno asociado
    const alumnosResult = await client.query(`
      DELETE FROM usuarios 
      WHERE rol = 'alumno' 
      AND id NOT IN (SELECT usuario_id FROM alumnos WHERE usuario_id IS NOT NULL)
      RETURNING id, username
    `);
    
    // Limpiar usuarios de tipo maestro sin maestro asociado
    const maestrosResult = await client.query(`
      DELETE FROM usuarios 
      WHERE rol = 'maestro' 
      AND id NOT IN (SELECT usuario_id FROM maestros WHERE usuario_id IS NOT NULL)
      RETURNING id, username
    `);
    
    console.log(`✅ Eliminados ${alumnosResult.rows.length} usuarios huérfanos de alumnos`);
    if (alumnosResult.rows.length > 0) {
      console.log('   -', alumnosResult.rows.map(u => u.username).join(', '));
    }
    
    console.log(`✅ Eliminados ${maestrosResult.rows.length} usuarios huérfanos de maestros`);
    if (maestrosResult.rows.length > 0) {
      console.log('   -', maestrosResult.rows.map(u => u.username).join(', '));
    }
    
    console.log('✨ Limpieza completada exitosamente');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error durante la limpieza:', error);
    process.exit(1);
  } finally {
    client.release();
  }
}

cleanOrphanUsers();
