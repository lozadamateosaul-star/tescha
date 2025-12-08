import pkg from 'pg';
const { Pool } = pkg;

const pool = new Pool({
  host: 'localhost',
  port: 5432,
  database: 'tescha_db',
  user: 'postgres',
  password: '1234'
});

// Datos para generar alumnos realistas
const nombres = [
  'Juan', 'María', 'Pedro', 'Ana', 'Luis', 'Carmen', 'José', 'Laura', 'Miguel', 'Sofia',
  'Carlos', 'Elena', 'Roberto', 'Patricia', 'Fernando', 'Isabel', 'Diego', 'Valentina', 'Javier', 'Camila',
  'Alejandro', 'Daniela', 'Ricardo', 'Andrea', 'Francisco', 'Gabriela', 'Antonio', 'Carolina', 'Manuel', 'Adriana',
  'Rafael', 'Natalia', 'Eduardo', 'Fernanda', 'Sergio', 'Mónica', 'Alberto', 'Claudia', 'Raúl', 'Verónica'
];

const apellidosPaternos = [
  'García', 'Rodríguez', 'Martínez', 'López', 'González', 'Hernández', 'Pérez', 'Sánchez', 'Ramírez', 'Torres',
  'Flores', 'Rivera', 'Gómez', 'Díaz', 'Cruz', 'Morales', 'Reyes', 'Gutiérrez', 'Ortiz', 'Chávez',
  'Ruiz', 'Jiménez', 'Mendoza', 'Vargas', 'Castillo', 'Herrera', 'Medina', 'Silva', 'Rojas', 'Castro'
];

const apellidosMaternos = [
  'Álvarez', 'Romero', 'Vázquez', 'Moreno', 'Ramos', 'Núñez', 'Guerrero', 'Méndez', 'Delgado', 'Aguilar',
  'Navarro', 'Cortés', 'Campos', 'Lara', 'Cabrera', 'Soto', 'Ríos', 'Domínguez', 'Guzmán', 'Velázquez',
  'Carrillo', 'Acosta', 'Luna', 'Salazar', 'Parra', 'León', 'Bautista', 'Santos', 'Contreras', 'Espinoza'
];

const niveles = ['A1', 'A2', 'B1', 'B2', 'C1', 'C2'];
const carreras = ['Licenciatura en Informática', 'Ingeniería Industrial', 'Contaduría', 'Administración'];

function randomElement(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomNumber(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generarEmail(nombre, apellido) {
  const nombreLimpio = nombre.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
  const apellidoLimpio = apellido.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
  const random = randomNumber(100, 999);
  return `${nombreLimpio}.${apellidoLimpio}${random}@tescha.edu.mx`;
}

function generarTelefono() {
  return `${randomNumber(614, 656)}${randomNumber(1000000, 9999999)}`;
}

async function generarAlumnos() {
  const client = await pool.connect();
  
  try {
    console.log('🚀 Iniciando generación de 100 alumnos de prueba...\n');
    
    let insertados = 0;
    let errores = 0;
    
    for (let i = 0; i < 100; i++) {
      const nombre = randomElement(nombres);
      const apellidoPaterno = randomElement(apellidosPaternos);
      const apellidoMaterno = randomElement(apellidosMaternos);
      const nivel = randomElement(niveles);
      const semestre = randomNumber(1, 14);
      const carrera = randomElement(carreras);
      const tipoAlumno = Math.random() > 0.3 ? 'interno' : 'externo';
      const email = generarEmail(nombre, apellidoPaterno);
      const telefono = generarTelefono();
      
      // Generar matrícula única (año + número secuencial)
      const matricula = `201724${String(5000 + i).padStart(4, '0')}`;
      
      try {
        await client.query(`
          INSERT INTO alumnos 
          (matricula, nombre, apellido_paterno, apellido_materno, correo, telefono, 
           carrera, semestre, nivel_actual, tipo_alumno, estatus)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'activo')
        `, [matricula, nombre, apellidoPaterno, apellidoMaterno, email, telefono, 
            carrera, semestre, nivel, tipoAlumno]);
        
        insertados++;
        
        // Mostrar progreso cada 10 alumnos
        if ((i + 1) % 10 === 0) {
          console.log(`✅ Progreso: ${i + 1}/100 alumnos generados`);
        }
        
      } catch (error) {
        errores++;
        console.error(`❌ Error al insertar alumno ${i + 1}:`, error.message);
      }
    }
    
    // Estadísticas finales
    const stats = await client.query(`
      SELECT 
        nivel_actual, 
        COUNT(*) as cantidad,
        COUNT(*) FILTER (WHERE tipo_alumno = 'interno') as internos,
        COUNT(*) FILTER (WHERE tipo_alumno = 'externo') as externos
      FROM alumnos 
      WHERE estatus = 'activo'
      GROUP BY nivel_actual 
      ORDER BY nivel_actual
    `);
    
    console.log('\n📊 RESUMEN DE GENERACIÓN:');
    console.log('═══════════════════════════════════════════');
    console.log(`✅ Alumnos insertados: ${insertados}`);
    console.log(`❌ Errores: ${errores}`);
    console.log('\n📈 DISTRIBUCIÓN POR NIVEL:');
    console.log('───────────────────────────────────────────');
    
    stats.rows.forEach(row => {
      console.log(`${row.nivel_actual}: ${row.cantidad} alumnos (${row.internos} internos, ${row.externos} externos)`);
    });
    
    const total = await client.query('SELECT COUNT(*) as total FROM alumnos WHERE estatus = \'activo\'');
    console.log('───────────────────────────────────────────');
    console.log(`TOTAL ALUMNOS ACTIVOS: ${total.rows[0].total}`);
    console.log('═══════════════════════════════════════════\n');
    
    console.log('✨ Generación completada exitosamente!');
    
  } catch (error) {
    console.error('❌ Error fatal:', error);
  } finally {
    client.release();
    await pool.end();
  }
}

generarAlumnos();
