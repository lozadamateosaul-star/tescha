import dotenv from 'dotenv';
import pool from '../config/database.js';

dotenv.config();

// Datos realistas
const NOMBRES = [
  'Juan', 'María', 'José', 'Ana', 'Luis', 'Carmen', 'Carlos', 'Laura', 'Miguel', 'Elena',
  'Francisco', 'Isabel', 'Antonio', 'Patricia', 'Manuel', 'Rosa', 'Pedro', 'Sofía', 'Javier', 'Lucía',
  'Diego', 'Marta', 'Raúl', 'Andrea', 'Fernando', 'Cristina', 'Alberto', 'Paula', 'Roberto', 'Beatriz',
  'Jorge', 'Silvia', 'Ángel', 'Natalia', 'Sergio', 'Teresa', 'Daniel', 'Verónica', 'Pablo', 'Gabriela',
  'Ricardo', 'Mónica', 'Alejandro', 'Claudia', 'Víctor', 'Diana', 'Adrián', 'Alicia', 'Eduardo', 'Valeria'
];

const APELLIDOS = [
  'García', 'Rodríguez', 'Martínez', 'López', 'González', 'Hernández', 'Pérez', 'Sánchez', 'Ramírez', 'Torres',
  'Flores', 'Rivera', 'Gómez', 'Díaz', 'Cruz', 'Morales', 'Reyes', 'Jiménez', 'Álvarez', 'Romero',
  'Vargas', 'Castro', 'Ruiz', 'Ortiz', 'Mendoza', 'Silva', 'Castillo', 'Vega', 'Aguilar', 'Guerrero',
  'Medina', 'Cortés', 'León', 'Ramos', 'Gutiérrez', 'Navarro', 'Campos', 'Lozano', 'Mendez', 'Moreno',
  'Velázquez', 'Delgado', 'Ríos', 'Cabrera', 'Sandoval', 'Rojas', 'Salazar', 'Valencia', 'Contreras', 'Mejía'
];

const CARRERAS = [
  'Ingeniería Electromecánica',
  'Ingeniería Electrónica',
  'Ingeniería Industrial',
  'Ingeniería Informática',
  'Ingeniería en Sistemas Computacionales',
  'Ingeniería en Administración'
];

const MUNICIPIOS = [
  'Chalco', 'Ixtapaluca', 'Valle de Chalco', 'Amecameca', 'Tlalmanalco', 
  'Cocotitlán', 'Temamatla', 'Ayapango', 'Tenango del Aire', 'Juchitepec',
  'Ozumba', 'Tepetlixpa', 'Atlautla'
];

const CONCEPTOS_PRECIOS = {
  'Constancia de Inglés - Celex': 40.00,
  'Credencial para Alumnos Externos - Celex': 93.00,
  'Curso de Idiomas - Celex - Cónyuge e hijos de Docentes y Administrativos': 2227.00,
  'Curso de Idiomas - Celex - Docentes y Administrativos': 1238.00,
  'Curso de Idiomas - Celex - Egresados': 2103.00,
  'Curso de Idiomas - Celex - Estudiantes': 1857.00,
  'Curso de Idiomas - Celex - Externos': 2476.00,
  'Curso de Idiomas - Celex - Sector con convenio con el TESCHA': 2227.00,
  'Examen Escrito para Acreditación - Celex': 914.00,
  'Examen de Colocación - Celex': 187.00
};

const NIVELES = ['A1', 'A2', 'B1', 'B2', 'C1', 'C2'];

// Funciones auxiliares
function randomItem(array) {
  return array[Math.floor(Math.random() * array.length)];
}

function randomNumber(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generarMatricula(año, numero) {
  return `${año}${String(numero).padStart(6, '0')}`;
}

function generarLineaCaptura() {
  let linea = '970000';
  for (let i = 0; i < 21; i++) {
    linea += Math.floor(Math.random() * 10);
  }
  return linea;
}

function generarEmail(nombre, apellido, numero) {
  return `${nombre.toLowerCase()}.${apellido.toLowerCase()}${numero}@tescha.edu.mx`;
}

function generarTelefono() {
  return `55${randomNumber(1000, 9999)}${randomNumber(1000, 9999)}`;
}

async function poblarSistema() {
  const client = await pool.connect();
  
  try {
    console.log('🚀 Iniciando población del sistema con 1500 alumnos...\n');
    
    await client.query('BEGIN');
    
    // Obtener periodo activo
    const periodoResult = await client.query('SELECT id FROM periodos WHERE activo = true LIMIT 1');
    const periodoActivo = periodoResult.rows[0];
    
    if (!periodoActivo) {
      throw new Error('No hay un periodo activo. Ejecuta el script de inicialización primero.');
    }
    
    console.log(`📅 Usando periodo activo ID: ${periodoActivo.id}\n`);
    
    // ========================================
    // 1. CREAR SALONES (20 salones)
    // ========================================
    console.log('📍 Creando salones...');
    const salones = [];
    const edificios = ['A', 'B', 'C', 'D'];
    const tipos = ['aula_tradicional', 'laboratorio', 'sala_multimedia'];
    
    for (let i = 1; i <= 20; i++) {
      const edificio = randomItem(edificios);
      const numero = String(i).padStart(2, '0');
      const codigo = `${edificio}-${numero}`;
      const capacidad = randomItem([25, 30, 35, 40]);
      const tipo = i <= 5 ? 'laboratorio' : i <= 8 ? 'sala_multimedia' : 'aula_tradicional';
      
      const result = await client.query(
        `INSERT INTO salones (codigo, nombre, edificio, tipo, capacidad, estatus)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
        [codigo, `Salón ${codigo}`, `Edificio ${edificio}`, tipo, capacidad, 'disponible']
      );
      
      salones.push({ id: result.rows[0].id, codigo, capacidad });
    }
    console.log(`✅ ${salones.length} salones creados\n`);
    
    // ========================================
    // 2. CREAR MAESTROS (10 maestros)
    // ========================================
    console.log('👨‍🏫 Creando maestros...');
    const maestros = [];
    
    for (let i = 1; i <= 10; i++) {
      const nombre = randomItem(NOMBRES);
      const apellidoPaterno = randomItem(APELLIDOS);
      const apellidoMaterno = randomItem(APELLIDOS);
      const nombreCompleto = `${nombre} ${apellidoPaterno} ${apellidoMaterno}`;
      const correo = `maestro${i}@tescha.edu.mx`;
      const username = `maestro${i}`;
      
      // Crear usuario (sin bcrypt, password simple para pruebas)
      const userResult = await client.query(
        `INSERT INTO usuarios (username, password, rol, activo)
         VALUES ($1, $2, $3, $4) RETURNING id`,
        [username, 'password123', 'maestro', true]
      );
      
      // Crear maestro
      const maestroResult = await client.query(
        `INSERT INTO maestros (usuario_id, nombre, apellido_paterno, apellido_materno, nombre_completo, correo, telefono, activo)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
        [userResult.rows[0].id, nombre, apellidoPaterno, apellidoMaterno, nombreCompleto, correo, generarTelefono(), true]
      );
      
      maestros.push({ id: maestroResult.rows[0].id, nombre: nombreCompleto });
    }
    console.log(`✅ ${maestros.length} maestros creados\n`);
    
    // ========================================
    // 3. CREAR 1500 ALUMNOS
    // ========================================
    console.log('👨‍🎓 Creando 1500 alumnos...');
    const alumnos = [];
    const añoActual = new Date().getFullYear();
    
    for (let i = 1; i <= 1500; i++) {
      const nombre = randomItem(NOMBRES);
      const apellidoPaterno = randomItem(APELLIDOS);
      const apellidoMaterno = randomItem(APELLIDOS);
      const nombreCompleto = `${nombre} ${apellidoPaterno} ${apellidoMaterno}`;
      const matricula = generarMatricula(añoActual - randomNumber(0, 4), i);
      const correo = generarEmail(nombre, apellidoPaterno, i);
      const telefono = generarTelefono();
      const tipoAlumno = i <= 1200 ? 'interno' : 'externo'; // 80% internos, 20% externos
      const carrera = tipoAlumno === 'interno' ? randomItem(CARRERAS) : null;
      const semestre = tipoAlumno === 'interno' ? randomNumber(1, 10) : null;
      const procedencia = tipoAlumno === 'externo' ? `Empresa ${i}` : null;
      const nivelActual = randomItem(NIVELES);
      const municipio = randomItem(MUNICIPIOS);
      
      const result = await client.query(
        `INSERT INTO alumnos (tipo_alumno, matricula, nombre_completo, correo, telefono, municipio, carrera, semestre, procedencia, nivel_actual, estatus)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
        [tipoAlumno, matricula, nombreCompleto, correo, telefono, municipio, carrera, semestre, procedencia, nivelActual, 'activo']
      );
      
      alumnos.push({ 
        id: result.rows[0].id, 
        nombre: nombreCompleto, 
        matricula,
        tipo: tipoAlumno
      });
      
      if (i % 200 === 0) {
        console.log(`   📝 ${i} alumnos creados...`);
      }
    }
    console.log(`✅ ${alumnos.length} alumnos creados\n`);
    
    // ========================================
    // 4. CREAR GRUPOS (30 grupos)
    // ========================================
    console.log('📚 Creando grupos...');
    const grupos = [];
    const horarios = ['07:00-09:00', '09:00-11:00', '11:00-13:00', '13:00-15:00', '15:00-17:00', '17:00-19:00'];
    const dias = [
      'Lunes y Miércoles',
      'Martes y Jueves',
      'Miércoles y Viernes',
      'Lunes, Miércoles y Viernes',
      'Martes y Jueves'
    ];
    
    let grupoCounter = 1;
    for (let i = 0; i < 30; i++) {
      const nivel = randomItem(NIVELES);
      const codigo = `${nivel}-G${grupoCounter}`;
      grupoCounter++;
      const maestro = randomItem(maestros);
      const salon = randomItem(salones);
      const horario = randomItem(horarios);
      const diasClase = randomItem(dias);
      const cupoMaximo = salon.capacidad;
      
      const horarioJSON = { descripcion: `${diasClase} ${horario}` };
      
      const result = await client.query(
        `INSERT INTO grupos (codigo, nivel, periodo_id, maestro_id, salon_id, horario, cupo_maximo, activo)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
        [codigo, nivel, periodoActivo.id, maestro.id, salon.id, JSON.stringify(horarioJSON), cupoMaximo, true]
      );
      
      grupos.push({ 
        id: result.rows[0].id, 
        codigo, 
        nivel,
        cupo: cupoMaximo,
        inscritos: 0
      });
    }
    console.log(`✅ ${grupos.length} grupos creados\n`);
    
    // ========================================
    // 5. INSCRIBIR ALUMNOS EN GRUPOS
    // ========================================
    console.log('📋 Inscribiendo alumnos en grupos...');
    let inscripcionesCount = 0;
    
    for (const alumno of alumnos) {
      // Buscar grupo del nivel del alumno
      const gruposDisponibles = grupos.filter(g => g.inscritos < g.cupo);
      if (gruposDisponibles.length > 0) {
        const grupo = randomItem(gruposDisponibles);
        
        await client.query(
          `INSERT INTO inscripciones (alumno_id, grupo_id, estatus)
           VALUES ($1, $2, $3)`,
          [alumno.id, grupo.id, 'activo']
        );
        
        grupo.inscritos++;
        inscripcionesCount++;
      }
    }
    console.log(`✅ ${inscripcionesCount} inscripciones creadas\n`);
    
    // ========================================
    // 6. CREAR PAGOS (90% completados, 10% en prórroga)
    // ========================================
    console.log('💰 Creando pagos...');
    const conceptos = Object.keys(CONCEPTOS_PRECIOS);
    let pagosCompletados = 0;
    let pagosProrrogados = 0;
    
    for (const alumno of alumnos) {
      const esProrroga = Math.random() < 0.10; // 10% con prórroga
      const concepto = alumno.tipo === 'interno' 
        ? 'Curso de Idiomas - Celex - Estudiantes'
        : 'Curso de Idiomas - Celex - Externos';
      const monto = CONCEPTOS_PRECIOS[concepto];
      const estatus = esProrroga ? 'pendiente' : 'completado';
      const referencia = esProrroga ? null : generarLineaCaptura();
      const tieneProrroga = esProrroga;
      
      let fechaLimite = null;
      if (esProrroga) {
        const diasAdelante = randomNumber(5, 30);
        fechaLimite = new Date();
        fechaLimite.setDate(fechaLimite.getDate() + diasAdelante);
      }
      
      await client.query(
        `INSERT INTO pagos (alumno_id, periodo_id, monto, fecha_pago, estatus, metodo_pago, referencia, concepto, tiene_prorroga, fecha_limite_prorroga)
         VALUES ($1, $2, $3, CURRENT_DATE, $4, $5, $6, $7, $8, $9)`,
        [alumno.id, periodoActivo.id, monto, estatus, 'Formato Universal', referencia, concepto, tieneProrroga, fechaLimite]
      );
      
      if (esProrroga) {
        pagosProrrogados++;
      } else {
        pagosCompletados++;
      }
    }
    
    console.log(`✅ ${pagosCompletados} pagos completados`);
    console.log(`✅ ${pagosProrrogados} pagos en prórroga\n`);
    
    await client.query('COMMIT');
    
    // ========================================
    // RESUMEN FINAL
    // ========================================
    console.log('📊 RESUMEN DEL SISTEMA:\n');
    console.log('═══════════════════════════════════════');
    console.log(`👨‍🎓 Alumnos:              ${alumnos.length}`);
    console.log(`   - Internos:           ${alumnos.filter(a => a.tipo === 'interno').length}`);
    console.log(`   - Externos:           ${alumnos.filter(a => a.tipo === 'externo').length}`);
    console.log(`👨‍🏫 Maestros:             ${maestros.length}`);
    console.log(`📍 Salones:              ${salones.length}`);
    console.log(`📚 Grupos:               ${grupos.length}`);
    console.log(`📋 Inscripciones:        ${inscripcionesCount}`);
    console.log(`💰 Pagos:                ${pagosCompletados + pagosProrrogados}`);
    console.log(`   - Completados:       ${pagosCompletados}`);
    console.log(`   - En prórroga:       ${pagosProrrogados}`);
    console.log('═══════════════════════════════════════\n');
    
    // Calcular ingresos
    const totalIngresos = pagosCompletados * CONCEPTOS_PRECIOS['Curso de Idiomas - Celex - Estudiantes'];
    console.log(`💵 Ingresos totales:     $${totalIngresos.toLocaleString('es-MX', { minimumFractionDigits: 2 })}`);
    console.log(`⏳ Por cobrar (prórrogas): $${(pagosProrrogados * CONCEPTOS_PRECIOS['Curso de Idiomas - Celex - Estudiantes']).toLocaleString('es-MX', { minimumFractionDigits: 2 })}\n`);
    
    console.log('✅ Sistema poblado exitosamente');
    console.log('🎯 Listo para probar la lógica de pagos y reportes\n');
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Error al poblar el sistema:', error);
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
