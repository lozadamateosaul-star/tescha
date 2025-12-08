import dotenv from 'dotenv';
import pool from '../config/database.js';
import bcrypt from 'bcryptjs';

dotenv.config();

// Nombres comunes mexicanos
const nombres = [
  'Juan', 'María', 'José', 'Ana', 'Luis', 'Carmen', 'Pedro', 'Rosa', 'Carlos', 'Laura',
  'Miguel', 'Elena', 'Fernando', 'Patricia', 'Jorge', 'Isabel', 'Ricardo', 'Sofía', 'Alejandro', 'Gabriela',
  'Roberto', 'Diana', 'Francisco', 'Verónica', 'Antonio', 'Mónica', 'Daniel', 'Andrea', 'Raúl', 'Claudia',
  'Héctor', 'Silvia', 'Eduardo', 'Martha', 'Sergio', 'Beatriz', 'Arturo', 'Cecilia', 'Manuel', 'Lidia',
  'Rafael', 'Teresa', 'Javier', 'Guadalupe', 'Alberto', 'Mariana', 'Enrique', 'Leticia', 'Alfredo', 'Cristina'
];

const apellidosPaternos = [
  'García', 'Rodríguez', 'Martínez', 'Hernández', 'López', 'González', 'Pérez', 'Sánchez', 'Ramírez', 'Torres',
  'Flores', 'Rivera', 'Gómez', 'Díaz', 'Cruz', 'Morales', 'Reyes', 'Jiménez', 'Álvarez', 'Ruiz',
  'Romero', 'Herrera', 'Mendoza', 'Castillo', 'Vargas', 'Silva', 'Vega', 'Aguilar', 'Ortiz', 'Méndez',
  'Ramos', 'Castro', 'Guerrero', 'Medina', 'Rojas', 'Santos', 'Navarro', 'Gutiérrez', 'Moreno', 'Salazar'
];

const apellidosMaternos = [
  'Navarro', 'Valdez', 'Luna', 'Ríos', 'Campos', 'Domínguez', 'Cortés', 'Santiago', 'León', 'Vázquez',
  'Cabrera', 'Estrada', 'Parra', 'Figueroa', 'Miranda', 'Carrillo', 'Delgado', 'Espinoza', 'Sandoval', 'Peña',
  'Contreras', 'Velázquez', 'Salinas', 'Ochoa', 'Valencia', 'Zamora', 'Cervantes', 'Ibarra', 'Mejía', 'Cárdenas'
];

const municipios = [
  'Chalco', 'Valle de Chalco', 'Ixtapaluca', 'Amecameca', 'Tlalmanalco', 'Cocotitlán', 'Temamatla',
  'Ayapango', 'Juchitepec', 'Tenango del Aire', 'Ozumba', 'Atlautla'
];

const carreras = [
  'Ingeniería Industrial', 'Ingeniería en Sistemas Computacionales', 'Ingeniería Mecatrónica',
  'Ingeniería Electrónica', 'Contador Público', 'Administración', 'Arquitectura',
  'Ingeniería Civil', 'Gastronomía', 'Turismo'
];

const salones = [
  { codigo: 'A-101', nombre: 'Aula 101', edificio: 'Edificio A', capacidad: 35 },
  { codigo: 'A-102', nombre: 'Aula 102', edificio: 'Edificio A', capacidad: 35 },
  { codigo: 'A-103', nombre: 'Aula 103', edificio: 'Edificio A', capacidad: 30 },
  { codigo: 'A-104', nombre: 'Aula 104', edificio: 'Edificio A', capacidad: 30 },
  { codigo: 'B-201', nombre: 'Aula 201', edificio: 'Edificio B', capacidad: 40 },
  { codigo: 'B-202', nombre: 'Aula 202', edificio: 'Edificio B', capacidad: 40 },
  { codigo: 'B-203', nombre: 'Aula 203', edificio: 'Edificio B', capacidad: 35 },
  { codigo: 'C-301', nombre: 'Lab Idiomas 1', edificio: 'Edificio C', capacidad: 25, tipo: 'laboratorio' },
  { codigo: 'C-302', nombre: 'Lab Idiomas 2', edificio: 'Edificio C', capacidad: 25, tipo: 'laboratorio' },
  { codigo: 'C-303', nombre: 'Lab Idiomas 3', edificio: 'Edificio C', capacidad: 25, tipo: 'laboratorio' },
  { codigo: 'D-401', nombre: 'Sala Multimedia 1', edificio: 'Edificio D', capacidad: 30, tipo: 'sala_multimedia' },
  { codigo: 'D-402', nombre: 'Sala Multimedia 2', edificio: 'Edificio D', capacidad: 30, tipo: 'sala_multimedia' }
];

const conceptosPagos = [
  { concepto: 'Curso de Idiomas - Celex - Estudiantes', precio: 1857.00, probabilidad: 70 },
  { concepto: 'Curso de Idiomas - Celex - Externos', precio: 2476.00, probabilidad: 15 },
  { concepto: 'Curso de Idiomas - Celex - Egresados', precio: 2103.00, probabilidad: 10 },
  { concepto: 'Examen de Colocación - Celex', precio: 187.00, probabilidad: 5 }
];

function randomItem(array) {
  return array[Math.floor(Math.random() * array.length)];
}

function randomDate(start, end) {
  return new Date(start.getTime() + Math.random() * (end.getTime() - start.getTime()));
}

function generateMatricula() {
  const year = new Date().getFullYear().toString().slice(-2);
  const random = Math.floor(Math.random() * 999999).toString().padStart(6, '0');
  return `${year}${random}`;
}

function generateEmail(nombre, apellidoPaterno) {
  const dominios = ['gmail.com', 'hotmail.com', 'outlook.com', 'yahoo.com', 'live.com'];
  const username = `${nombre.toLowerCase()}.${apellidoPaterno.toLowerCase()}${Math.floor(Math.random() * 999)}`;
  return `${username}@${randomItem(dominios)}`;
}

function getConceptoPago() {
  const rand = Math.random() * 100;
  let acumulado = 0;
  for (const item of conceptosPagos) {
    acumulado += item.probabilidad;
    if (rand <= acumulado) {
      return item;
    }
  }
  return conceptosPagos[0];
}

async function poblarSistema() {
  const client = await pool.connect();
  
  try {
    console.log('🚀 Iniciando generación de datos de prueba...\n');
    await client.query('BEGIN');

    // 1. CREAR SALONES
    console.log('📍 Creando salones...');
    for (const salon of salones) {
      await client.query(
        `INSERT INTO salones (codigo, nombre, edificio, tipo, capacidad, estatus)
         VALUES ($1, $2, $3, $4, $5, 'disponible')
         ON CONFLICT (codigo) DO NOTHING`,
        [salon.codigo, salon.nombre, salon.edificio, salon.tipo || 'aula_tradicional', salon.capacidad]
      );
    }
    console.log(`✅ ${salones.length} salones creados\n`);

    // 2. CREAR ALUMNOS
    console.log('👥 Generando 1500 alumnos...');
    const hashedPassword = await bcrypt.hash('12345', 10);
    const alumnosCreados = [];
    
    for (let i = 0; i < 1500; i++) {
      const nombre = randomItem(nombres);
      const apellidoPaterno = randomItem(apellidosPaternos);
      const apellidoMaterno = randomItem(apellidosMaternos);
      const nombreCompleto = `${nombre} ${apellidoPaterno} ${apellidoMaterno}`;
      const matricula = generateMatricula();
      const email = generateEmail(nombre, apellidoPaterno);
      const telefono = `55${Math.floor(Math.random() * 90000000) + 10000000}`;
      const tipoAlumno = Math.random() > 0.8 ? 'externo' : 'interno';
      const municipio = randomItem(municipios);
      
      let carrera = null;
      let semestre = null;
      let procedencia = null;
      
      if (tipoAlumno === 'interno') {
        carrera = randomItem(carreras);
        semestre = Math.floor(Math.random() * 8) + 1;
      } else {
        procedencia = `${randomItem(['Universidad', 'Instituto', 'Tecnológico'])} ${randomItem(apellidosPaternos)}`;
      }
      
      const nivelActual = randomItem(['A1', 'A2', 'B1', 'B2', 'C1']);
      
      // Crear usuario
      const userResult = await client.query(
        `INSERT INTO usuarios (username, password, rol, activo)
         VALUES ($1, $2, 'alumno', true)
         RETURNING id`,
        [`alumno${matricula}`, hashedPassword]
      );
      
      const usuarioId = userResult.rows[0].id;
      
      // Crear alumno
      const alumnoResult = await client.query(
        `INSERT INTO alumnos 
         (usuario_id, tipo_alumno, matricula, nombre_completo, correo, telefono, municipio, 
          carrera, semestre, procedencia, nivel_actual, estatus)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'activo')
         RETURNING id`,
        [usuarioId, tipoAlumno, matricula, nombreCompleto, email, telefono, municipio,
         carrera, semestre, procedencia, nivelActual]
      );
      
      alumnosCreados.push({
        id: alumnoResult.rows[0].id,
        nombre: nombreCompleto,
        tipo: tipoAlumno
      });
      
      if ((i + 1) % 100 === 0) {
        console.log(`   ⏳ ${i + 1}/1500 alumnos creados...`);
      }
    }
    console.log(`✅ 1500 alumnos creados exitosamente\n`);

    // 3. CREAR PAGOS
    console.log('💰 Generando pagos...');
    let pagosCompletados = 0;
    let pagosProrrogas = 0;
    
    // 80% tendrán pagos completados (1200 alumnos)
    const alumnosConPagoCompletado = alumnosCreados.slice(0, 1200);
    for (const alumno of alumnosConPagoCompletado) {
      const { concepto, precio } = getConceptoPago();
      const fechaPago = randomDate(new Date(2025, 10, 1), new Date(2025, 11, 3)); // Nov-Dic 2025
      const referencia = `97${Math.floor(Math.random() * 10000000000000000000).toString().padStart(22, '0')}`;
      
      await client.query(
        `INSERT INTO pagos 
         (alumno_id, monto, fecha_pago, estatus, metodo_pago, referencia, concepto, tiene_prorroga)
         VALUES ($1, $2, $3, 'completado', 'Formato Universal', $4, $5, false)`,
        [alumno.id, precio, fechaPago, referencia, concepto]
      );
      
      pagosCompletados++;
      
      if (pagosCompletados % 200 === 0) {
        console.log(`   ⏳ ${pagosCompletados} pagos completados generados...`);
      }
    }
    
    // 15% tendrán prórrogas activas (225 alumnos)
    const alumnosConProrroga = alumnosCreados.slice(1200, 1425);
    for (const alumno of alumnosConProrroga) {
      const { concepto, precio } = getConceptoPago();
      const fechaLimite = randomDate(new Date(2025, 11, 4), new Date(2025, 11, 31)); // Dic 2025
      
      await client.query(
        `INSERT INTO pagos 
         (alumno_id, monto, fecha_pago, estatus, metodo_pago, concepto, tiene_prorroga, fecha_limite_prorroga)
         VALUES ($1, $2, CURRENT_DATE, 'pendiente', 'Formato Universal', $3, true, $4)`,
        [alumno.id, precio, concepto, fechaLimite]
      );
      
      pagosProrrogas++;
    }
    
    console.log(`✅ ${pagosCompletados} pagos completados`);
    console.log(`✅ ${pagosProrrogas} pagos con prórroga\n`);

    await client.query('COMMIT');

    // RESUMEN FINAL
    console.log('📊 RESUMEN DE DATOS GENERADOS:\n');
    
    const resumen = await client.query(`
      SELECT 
        'Salones' as tipo, COUNT(*) as total FROM salones
      UNION ALL
      SELECT 'Alumnos Internos', COUNT(*) FROM alumnos WHERE tipo_alumno = 'interno'
      UNION ALL
      SELECT 'Alumnos Externos', COUNT(*) FROM alumnos WHERE tipo_alumno = 'externo'
      UNION ALL
      SELECT 'Total Alumnos', COUNT(*) FROM alumnos
      UNION ALL
      SELECT 'Pagos Completados', COUNT(*) FROM pagos WHERE estatus = 'completado'
      UNION ALL
      SELECT 'Pagos con Prórroga', COUNT(*) FROM pagos WHERE estatus = 'pendiente' AND tiene_prorroga = true
      UNION ALL
      SELECT 'Total Pagos', COUNT(*) FROM pagos
    `);
    
    console.table(resumen.rows);
    
    // Cálculos financieros
    const finanzas = await client.query(`
      SELECT 
        SUM(monto) FILTER (WHERE estatus = 'completado') as ingresos_totales,
        SUM(monto) FILTER (WHERE estatus = 'pendiente') as por_cobrar
      FROM pagos
    `);
    
    const { ingresos_totales, por_cobrar } = finanzas.rows[0];
    console.log('\n💵 RESUMEN FINANCIERO:');
    console.log(`   Ingresos Totales: $${parseFloat(ingresos_totales || 0).toLocaleString('es-MX', { minimumFractionDigits: 2 })}`);
    console.log(`   Por Cobrar: $${parseFloat(por_cobrar || 0).toLocaleString('es-MX', { minimumFractionDigits: 2 })}`);
    console.log(`   Total Proyectado: $${(parseFloat(ingresos_totales || 0) + parseFloat(por_cobrar || 0)).toLocaleString('es-MX', { minimumFractionDigits: 2 })}\n`);
    
    console.log('✅ Sistema poblado exitosamente');
    console.log('🎯 Listo para probar la lógica de pagos y salones\n');
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Error al poblar el sistema:', error.message);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

poblarSistema().catch(err => {
  console.error('Error fatal:', err);
  process.exit(1);
});
