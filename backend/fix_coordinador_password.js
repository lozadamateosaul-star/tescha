import bcrypt from 'bcryptjs';
import pool from './config/database.js';

async function fixPassword() {
  try {
    const password = 'admin123';
    const hashedPassword = await bcrypt.hash(password, 10);
    
    console.log('Hash generado:', hashedPassword);
    
    await pool.query(
      'UPDATE usuarios SET password = $1 WHERE username = $2',
      [hashedPassword, 'coordinador']
    );
    
    console.log('✅ Contraseña actualizada correctamente');
    console.log('Usuario: coordinador');
    console.log('Contraseña: admin123');
    
    process.exit(0);
  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

fixPassword();
