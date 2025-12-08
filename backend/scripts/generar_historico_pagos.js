import dotenv from 'dotenv';
import pool from '../config/database.js';

dotenv.config();

function generarLineaCaptura() {
  let linea = '970000';
  for (let i = 0; i < 21; i++) {
    linea += Math.floor(Math.random() * 10);
  }
  return linea;
}

function randomNumber(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

async function generarHistoricoPagos() {
  const client = await pool.connect();
  
  try {
    console.log('📊 Generando histórico de pagos para periodos pasados...\n');
    
    await client.query('BEGIN');
    
    // Obtener todos los periodos excepto el actual
    const periodosResult = await client.query(`
      SELECT id, nombre 
      FROM periodos 
      WHERE activo = false 
      ORDER BY fecha_inicio_clases DESC
    `);
    
    const periodos = periodosResult.rows;
    console.log(`📅 Encontrados ${periodos.length} periodos históricos\n`);
    
    // Obtener alumnos
    const alumnosResult = await client.query(`
      SELECT id, tipo_alumno 
      FROM alumnos 
      ORDER BY id
    `);
    const alumnos = alumnosResult.rows;
    
    const CONCEPTOS_PRECIOS = {
      'Curso de Idiomas - Celex - Estudiantes': 1857.00,
      'Curso de Idiomas - Celex - Externos': 2476.00
    };
    
    let totalPagosCreados = 0;
    
    // Para cada periodo pasado
    for (const periodo of periodos) {
      console.log(`📝 Generando pagos para periodo: ${periodo.nombre}`);
      
      // Calcular porcentaje de alumnos que tuvieron pagos en ese periodo
      // Más reciente = más alumnos, más antiguo = menos alumnos
      const indicePeriodo = periodos.indexOf(periodo);
      const porcentajeAlumnos = Math.max(20, 90 - (indicePeriodo * 15)); // Entre 90% y 20%
      
      let pagosEnPeriodo = 0;
      
      for (const alumno of alumnos) {
        // Decidir si este alumno tuvo pago en este periodo
        if (Math.random() * 100 < porcentajeAlumnos) {
          const concepto = alumno.tipo_alumno === 'interno' 
            ? 'Curso de Idiomas - Celex - Estudiantes'
            : 'Curso de Idiomas - Celex - Externos';
          const monto = CONCEPTOS_PRECIOS[concepto];
          const referencia = generarLineaCaptura();
          
          // Generar fecha dentro del periodo (simulada)
          const fechaPago = new Date(2023, indicePeriodo * 6, randomNumber(1, 28));
          
          await client.query(
            `INSERT INTO pagos (alumno_id, periodo_id, monto, fecha_pago, estatus, metodo_pago, referencia, concepto, tiene_prorroga, fecha_limite_prorroga)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
            [alumno.id, periodo.id, monto, fechaPago, 'completado', 'Formato Universal', referencia, concepto, false, null]
          );
          
          pagosEnPeriodo++;
          totalPagosCreados++;
        }
      }
      
      const ingresosPeriodo = pagosEnPeriodo * 1857; // Promedio aproximado
      console.log(`   ✅ ${pagosEnPeriodo} pagos creados (~$${ingresosPeriodo.toLocaleString('es-MX')})`);
    }
    
    await client.query('COMMIT');
    
    console.log('\n═══════════════════════════════════════');
    console.log(`✅ ${totalPagosCreados} pagos históricos creados`);
    console.log('🎯 Ahora el dashboard mostrará tendencias reales\n');
    
    // Verificar totales por periodo
    const verificacion = await client.query(`
      SELECT 
        per.nombre as periodo,
        COUNT(p.id) as total_pagos,
        SUM(p.monto) as ingresos_totales
      FROM periodos per
      LEFT JOIN pagos p ON per.id = p.periodo_id AND p.estatus = 'completado'
      GROUP BY per.id, per.nombre
      ORDER BY per.fecha_inicio_clases DESC
    `);
    
    console.log('📊 Resumen por periodo:\n');
    verificacion.rows.forEach(row => {
      console.log(`${row.periodo}: ${row.total_pagos} pagos = $${parseFloat(row.ingresos_totales || 0).toLocaleString('es-MX', { minimumFractionDigits: 2 })}`);
    });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Error:', error);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

generarHistoricoPagos().catch(err => {
  console.error('Error fatal:', err);
  process.exit(1);
});
