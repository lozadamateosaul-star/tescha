import pkg from 'pg';
const { Pool } = pkg;

const pool = new Pool({
  host: 'localhost',
  port: 5432,
  database: 'tescha_db',
  user: 'postgres',
  password: '1234'
});

const conceptos = ['Colegiatura', 'Inscripción', 'Reinscripción', 'Examen'];
const metodosPago = ['efectivo', 'transferencia', 'tarjeta'];
const estatus = ['completado', 'pendiente', 'cancelado'];

function randomElement(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomNumber(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generarMonto(concepto) {
  switch(concepto) {
    case 'Colegiatura':
      return randomNumber(1800, 2500); // $1,800 - $2,500
    case 'Inscripción':
      return randomNumber(3000, 4500); // $3,000 - $4,500
    case 'Reinscripción':
      return randomNumber(2000, 3000); // $2,000 - $3,000
    case 'Examen':
      return randomNumber(500, 800); // $500 - $800
    default:
      return 2000;
  }
}

function generarReferencia(metodoPago) {
  if (metodoPago === 'efectivo') return null;
  return `${randomNumber(100000, 999999)}`;
}

function generarFechaPago() {
  // Generar fechas en diciembre 2025
  const dia = randomNumber(1, 2); // 1 o 2 de diciembre
  return `2025-12-0${dia}`;
}

async function generarPagos() {
  const client = await pool.connect();
  
  try {
    console.log('🚀 Iniciando generación de pagos para 100 alumnos...\n');
    
    // Obtener periodo activo
    const periodoResult = await client.query('SELECT id FROM periodos WHERE activo = true LIMIT 1');
    const periodoId = periodoResult.rows[0]?.id;
    
    if (!periodoId) {
      console.error('❌ No hay período activo');
      return;
    }
    
    // Obtener todos los alumnos activos
    const alumnosResult = await client.query(`
      SELECT id, nombre, apellido_paterno 
      FROM alumnos 
      WHERE estatus = 'activo' 
      ORDER BY id
    `);
    
    const alumnos = alumnosResult.rows;
    console.log(`📋 Encontrados ${alumnos.length} alumnos activos\n`);
    
    let completados = 0;
    let pendientes = 0;
    let cancelados = 0;
    let totalIngresos = 0;
    let totalPorCobrar = 0;
    
    for (let i = 0; i < alumnos.length; i++) {
      const alumno = alumnos[i];
      const concepto = randomElement(conceptos);
      const metodoPago = randomElement(metodosPago);
      const monto = generarMonto(concepto);
      const referencia = generarReferencia(metodoPago);
      const fechaPago = generarFechaPago();
      
      // 70% completados, 25% pendientes, 5% cancelados
      const random = Math.random();
      let estatusPago;
      let tieneProrroga = false;
      let fechaLimiteProrroga = null;
      
      if (random < 0.70) {
        estatusPago = 'completado';
        completados++;
        totalIngresos += monto;
      } else if (random < 0.95) {
        estatusPago = 'pendiente';
        pendientes++;
        totalPorCobrar += monto;
        // 50% de los pendientes tienen prórroga
        if (Math.random() < 0.5) {
          tieneProrroga = true;
          // Prórroga entre 1 y 15 días en el futuro
          const diasProrroga = randomNumber(1, 15);
          const fecha = new Date();
          fecha.setDate(fecha.getDate() + diasProrroga);
          fechaLimiteProrroga = fecha.toISOString().split('T')[0];
        }
      } else {
        estatusPago = 'cancelado';
        cancelados++;
      }
      
      try {
        await client.query(`
          INSERT INTO pagos 
          (alumno_id, periodo_id, monto, fecha_pago, estatus, metodo_pago, referencia, concepto, 
           tiene_prorroga, fecha_limite_prorroga)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        `, [alumno.id, periodoId, monto, fechaPago, estatusPago, metodoPago, referencia, concepto,
            tieneProrroga, fechaLimiteProrroga]);
        
        // Mostrar progreso cada 20 pagos
        if ((i + 1) % 20 === 0) {
          console.log(`✅ Progreso: ${i + 1}/${alumnos.length} pagos generados`);
        }
        
      } catch (error) {
        console.error(`❌ Error al insertar pago para alumno ${alumno.nombre}:`, error.message);
      }
    }
    
    console.log('\n📊 RESUMEN DE PAGOS GENERADOS:');
    console.log('═══════════════════════════════════════════');
    console.log(`✅ Completados: ${completados} pagos`);
    console.log(`   💰 Ingresos totales: $${totalIngresos.toLocaleString('es-MX', {minimumFractionDigits: 2})}`);
    console.log(`⏳ Pendientes: ${pendientes} pagos`);
    console.log(`   💵 Por cobrar: $${totalPorCobrar.toLocaleString('es-MX', {minimumFractionDigits: 2})}`);
    console.log(`❌ Cancelados: ${cancelados} pagos`);
    console.log('───────────────────────────────────────────');
    console.log(`TOTAL PAGOS: ${completados + pendientes + cancelados}`);
    
    // Estadísticas de prórrogas
    const prorrogasResult = await client.query(`
      SELECT COUNT(*) as total 
      FROM pagos 
      WHERE tiene_prorroga = true AND estatus = 'pendiente'
    `);
    
    console.log(`\n🔔 Prórrogas activas: ${prorrogasResult.rows[0].total}`);
    
    // Estadísticas por concepto
    const conceptosStats = await client.query(`
      SELECT 
        concepto, 
        COUNT(*) as cantidad,
        SUM(monto) FILTER (WHERE estatus = 'completado') as ingresos
      FROM pagos 
      GROUP BY concepto 
      ORDER BY ingresos DESC NULLS LAST
    `);
    
    console.log('\n📈 INGRESOS POR CONCEPTO:');
    console.log('───────────────────────────────────────────');
    conceptosStats.rows.forEach(row => {
      const ingresos = row.ingresos || 0;
      console.log(`${row.concepto}: ${row.cantidad} pagos → $${parseFloat(ingresos).toLocaleString('es-MX', {minimumFractionDigits: 2})}`);
    });
    
    console.log('═══════════════════════════════════════════\n');
    console.log('✨ Generación de pagos completada exitosamente!');
    
  } catch (error) {
    console.error('❌ Error fatal:', error);
  } finally {
    client.release();
    await pool.end();
  }
}

generarPagos();
