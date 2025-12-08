import dotenv from 'dotenv';
import pool from '../config/database.js';

dotenv.config();

async function updateMetodoPago() {
  try {
    console.log('Actualizando métodos de pago a "Formato Universal"...');
    
    const result = await pool.query(`
      UPDATE pagos 
      SET metodo_pago = 'Formato Universal'
      WHERE metodo_pago IN ('efectivo', 'tarjeta', 'transferencia', 'deposito', 'Efectivo', 'Tarjeta', 'Transferencia', 'Depósito')
      RETURNING id, metodo_pago
    `);
    
    console.log(`✅ ${result.rowCount} pagos actualizados correctamente`);
    
    // Verificar los cambios
    const verificacion = await pool.query(`
      SELECT metodo_pago, COUNT(*) as total 
      FROM pagos 
      GROUP BY metodo_pago
    `);
    
    console.log('\nMétodos de pago actuales:');
    verificacion.rows.forEach(row => {
      console.log(`  - ${row.metodo_pago}: ${row.total} pagos`);
    });
    
    await pool.end();
    console.log('\n✅ Actualización completada');
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

updateMetodoPago();
