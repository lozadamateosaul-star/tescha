import express from 'express';
import pool from '../config/database.js';
import { auth, checkRole } from '../middleware/auth.js';
import xlsx from 'xlsx';
import PDFDocument from 'pdfkit';

const router = express.Router();

// Reporte de reprobación
router.get('/reprobacion', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const { periodo_id, nivel, carrera } = req.query;

    let query = `
      SELECT 
        g.codigo as grupo,
        g.nivel,
        m.nombre_completo as maestro,
        COUNT(DISTINCT i.alumno_id) as total_alumnos,
        COUNT(DISTINCT i.alumno_id) FILTER (
          WHERE (
            SELECT AVG(c.calificacion) 
            FROM calificaciones c 
            WHERE c.inscripcion_id = i.id
          ) < 70
        ) as reprobados,
        ROUND(
          COUNT(DISTINCT i.alumno_id) FILTER (
            WHERE (
              SELECT AVG(c.calificacion) 
              FROM calificaciones c 
              WHERE c.inscripcion_id = i.id
            ) < 70
          ) * 100.0 / NULLIF(COUNT(DISTINCT i.alumno_id), 0), 
          2
        ) as tasa_reprobacion
      FROM grupos g
      LEFT JOIN inscripciones i ON g.id = i.grupo_id
      LEFT JOIN maestros m ON g.maestro_id = m.id
      WHERE 1=1
    `;

    const params = [];
    let paramCount = 1;

    if (periodo_id) {
      query += ` AND g.periodo_id = $${paramCount++}`;
      params.push(periodo_id);
    }

    if (nivel) {
      query += ` AND g.nivel = $${paramCount++}`;
      params.push(nivel);
    }

    query += ' GROUP BY g.id, g.codigo, g.nivel, m.nombre_completo ORDER BY tasa_reprobacion DESC';

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Reporte de deserción
router.get('/desercion', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const { periodo_id } = req.query;

    let query = `
      SELECT 
        g.codigo as grupo,
        g.nivel,
        COUNT(*) FILTER (WHERE i.estatus = 'activo') as activos,
        COUNT(*) FILTER (WHERE i.estatus = 'desercion') as deserciones,
        ROUND(
          COUNT(*) FILTER (WHERE i.estatus = 'desercion') * 100.0 / 
          NULLIF(COUNT(*), 0), 
          2
        ) as tasa_desercion
      FROM grupos g
      LEFT JOIN inscripciones i ON g.id = i.grupo_id
      WHERE 1=1
    `;

    const params = [];

    if (periodo_id) {
      query += ' AND g.periodo_id = $1';
      params.push(periodo_id);
    }

    query += ' GROUP BY g.id ORDER BY tasa_desercion DESC';

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Reporte de ocupación de salones
router.get('/salones/ocupacion', auth, async (req, res) => {
  try {
    const { dia, periodo_id } = req.query;

    let query = `
      SELECT 
        s.codigo as salon,
        s.edificio,
        s.capacidad,
        COUNT(DISTINCT g.id) as grupos_asignados,
        COUNT(DISTINCT gh.id) as horas_ocupadas
      FROM salones s
      LEFT JOIN grupos g ON s.id = g.salon_id AND g.activo = true
      LEFT JOIN grupos_horarios gh ON g.id = gh.grupo_id
    `;

    const params = [];
    let paramCount = 1;

    if (dia) {
      query += ` AND gh.dia = $${paramCount++}`;
      params.push(dia);
    }

    if (periodo_id) {
      query += ` AND g.periodo_id = $${paramCount++}`;
      params.push(periodo_id);
    }

    query += ' GROUP BY s.id ORDER BY grupos_asignados DESC';

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Reporte de alumnos próximos a egresar sin inglés
router.get('/alumnos/sin-requisito', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        a.id,
        a.matricula,
        a.nombre_completo,
        a.carrera,
        a.semestre,
        a.nivel_actual,
        a.correo,
        a.telefono
      FROM alumnos a
      WHERE a.tipo_alumno = 'interno'
        AND a.semestre >= 8
        AND (a.nivel_actual < 'B1' OR a.nivel_actual IS NULL)
        AND a.estatus = 'activo'
      ORDER BY a.semestre DESC, a.carrera, a.nombre_completo`
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Reporte de carga horaria de maestros
router.get('/maestros/carga', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        m.id,
        m.nombre_completo,
        COUNT(DISTINCT g.id) as grupos_asignados,
        COUNT(DISTINCT gh.id) as horas_semanales
      FROM maestros m
      LEFT JOIN grupos g ON m.id = g.maestro_id AND g.activo = true
      LEFT JOIN grupos_horarios gh ON g.id = gh.grupo_id
      WHERE m.activo = true
      GROUP BY m.id
      ORDER BY horas_semanales DESC`
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Reporte de eficiencia terminal
router.get('/eficiencia-terminal', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const query = `
      SELECT 
        a.nivel_actual as nivel,
        COUNT(DISTINCT a.id) as inscritos,
        COUNT(DISTINCT a.id) FILTER (
          WHERE EXISTS (
            SELECT 1 FROM inscripciones i2
            JOIN grupos g2 ON i2.grupo_id = g2.id
            JOIN periodos p2 ON g2.periodo_id = p2.id
            WHERE i2.alumno_id = a.id
              AND i2.estatus = 'aprobado'
              AND p2.activo = true
          )
        ) as aprobados,
        ROUND(
          COUNT(DISTINCT a.id) FILTER (
            WHERE EXISTS (
              SELECT 1 FROM inscripciones i2
              JOIN grupos g2 ON i2.grupo_id = g2.id
              JOIN periodos p2 ON g2.periodo_id = p2.id
              WHERE i2.alumno_id = a.id
                AND i2.estatus = 'aprobado'
                AND p2.activo = true
            )
          ) * 100.0 / NULLIF(COUNT(DISTINCT a.id), 0),
          2
        ) as eficiencia
      FROM alumnos a
      WHERE a.nivel_actual IS NOT NULL
      GROUP BY a.nivel_actual
      ORDER BY a.nivel_actual
    `;

    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Exportar datos (simplificado - en producción usar librerías específicas)
router.get('/exportar/:tipo', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const { tipo } = req.params;
    const { periodo_id, formato } = req.query;

    let result;

    switch (tipo) {
      case 'reprobacion':
        result = await pool.query(`
          SELECT 
            g.codigo as grupo,
            g.nivel,
            m.nombre_completo as maestro,
            COUNT(DISTINCT i.alumno_id) as total_alumnos,
            COUNT(DISTINCT i.alumno_id) FILTER (
              WHERE (SELECT AVG(c.calificacion) FROM calificaciones c WHERE c.inscripcion_id = i.id) < 70
            ) as reprobados
          FROM grupos g
          LEFT JOIN inscripciones i ON g.id = i.grupo_id
          LEFT JOIN maestros m ON g.maestro_id = m.id
          GROUP BY g.id, g.codigo, g.nivel, m.nombre_completo
        `);
        break;

      case 'desercion':
        result = await pool.query(`
          SELECT 
            g.codigo as grupo,
            g.nivel,
            COUNT(*) FILTER (WHERE i.estatus = 'activo') as activos,
            COUNT(*) FILTER (WHERE i.estatus = 'desercion') as deserciones
          FROM grupos g
          LEFT JOIN inscripciones i ON g.id = i.grupo_id
          GROUP BY g.id
        `);
        break;

      case 'ocupacion-salones':
        result = await pool.query(`
          SELECT 
            s.codigo as salon,
            s.edificio,
            s.capacidad,
            COUNT(DISTINCT g.id) as grupos_asignados
          FROM salones s
          LEFT JOIN grupos g ON s.id = g.salon_id AND g.activo = true
          GROUP BY s.id
        `);
        break;

      case 'sin-requisito':
        result = await pool.query(`
          SELECT 
            a.matricula,
            a.nombre_completo,
            a.carrera,
            a.semestre,
            a.nivel_actual
          FROM alumnos a
          WHERE a.tipo_alumno = 'interno'
            AND a.semestre >= 8
            AND (a.nivel_actual < 'B1' OR a.nivel_actual IS NULL)
            AND a.estatus = 'activo'
        `);
        break;

      case 'carga-maestros':
        result = await pool.query(`
          SELECT 
            m.nombre_completo,
            COUNT(DISTINCT g.id) as grupos_asignados,
            COUNT(DISTINCT gh.id) as horas_semanales
          FROM maestros m
          LEFT JOIN grupos g ON m.id = g.maestro_id AND g.activo = true
          LEFT JOIN grupos_horarios gh ON g.id = gh.grupo_id
          WHERE m.activo = true
          GROUP BY m.id
        `);
        break;

      case 'eficiencia-terminal':
        result = await pool.query(`
          SELECT 
            a.nivel_actual as nivel,
            COUNT(DISTINCT a.id) as inscritos,
            COUNT(DISTINCT a.id) FILTER (
              WHERE EXISTS (
                SELECT 1 FROM inscripciones i2
                JOIN grupos g2 ON i2.grupo_id = g2.id
                JOIN periodos p2 ON g2.periodo_id = p2.id
                WHERE i2.alumno_id = a.id
                  AND i2.estatus = 'aprobado'
                  AND p2.activo = true
              )
            ) as aprobados
          FROM alumnos a
          WHERE a.nivel_actual IS NOT NULL
          GROUP BY a.nivel_actual
          ORDER BY a.nivel_actual
        `);
        break;

      case 'ingresos':
        result = await pool.query(`
          SELECT 
            p.concepto,
            COUNT(*) as total_pagos,
            SUM(monto) as monto_total,
            p.estatus
          FROM pagos p
          GROUP BY p.concepto, p.estatus
        `);
        break;

      case 'prorrogas-activas':
        result = await pool.query(`
          SELECT 
            COALESCE(
              a.nombre_completo,
              CONCAT(a.nombre, ' ', a.apellido_paterno, ' ', COALESCE(a.apellido_materno, ''))
            ) as nombre_completo,
            a.matricula,
            p.monto,
            p.fecha_limite_prorroga,
            CASE 
              WHEN p.fecha_limite_prorroga < CURRENT_DATE THEN 'vencida'
              WHEN p.fecha_limite_prorroga BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '3 days' THEN 'por_vencer'
              ELSE 'activa'
            END as estado
          FROM pagos p
          JOIN alumnos a ON p.alumno_id = a.id
          WHERE p.tiene_prorroga = true AND p.estatus = 'pendiente'
        `);
        break;

      case 'adeudos-criticos':
        result = await pool.query(`
          SELECT 
            COALESCE(
              a.nombre_completo,
              CONCAT(a.nombre, ' ', a.apellido_paterno, ' ', COALESCE(a.apellido_materno, ''))
            ) as nombre_completo,
            a.matricula,
            COUNT(p.id) as total_adeudos,
            SUM(p.monto) as monto_total
          FROM alumnos a
          JOIN pagos p ON a.id = p.alumno_id
          WHERE p.estatus IN ('pendiente', 'adeudo')
          GROUP BY a.id, a.nombre_completo, a.matricula
        `);
        break;

      default:
        return res.status(400).json({ error: 'Tipo de reporte no válido' });
    }

    // Generar archivo según formato
    if (formato === 'excel') {
      // Generar Excel
      const ws = xlsx.utils.json_to_sheet(result.rows);
      const wb = xlsx.utils.book_new();
      xlsx.utils.book_append_sheet(wb, ws, 'Reporte');

      const excelBuffer = xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' });

      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename=reporte_${tipo}_${new Date().toISOString().split('T')[0]}.xlsx`);
      res.send(excelBuffer);
    } else if (formato === 'pdf') {
      // Generar PDF mejorado
      const doc = new PDFDocument({
        margin: 40,
        size: 'LETTER',
        bufferPages: true
      });

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename=reporte_${tipo}_${new Date().toISOString().split('T')[0]}.pdf`);

      doc.pipe(res);

      // Encabezado con logo/título
      doc.rect(0, 0, doc.page.width, 80).fill('#0369a1');
      doc.fillColor('#ffffff')
        .fontSize(24)
        .font('Helvetica-Bold')
        .text('TESCHA', 50, 25);
      doc.fontSize(12)
        .font('Helvetica')
        .text('Tecnológico de Estudios Superiores de Chalco', 50, 50);

      doc.fillColor('#000000');
      doc.moveDown(3);

      // Título del reporte
      const tituloReporte = tipo.replace(/-/g, ' ').split(' ').map(word =>
        word.charAt(0).toUpperCase() + word.slice(1)
      ).join(' ');

      doc.fontSize(18)
        .font('Helvetica-Bold')
        .text(tituloReporte, { align: 'center' });
      doc.moveDown(0.5);
      doc.fontSize(10)
        .font('Helvetica')
        .text(`Fecha de generación: ${new Date().toLocaleDateString('es-MX', {
          weekday: 'long',
          year: 'numeric',
          month: 'long',
          day: 'numeric'
        })}`, { align: 'center' });
      doc.moveDown(2);

      // Tabla de datos
      if (result.rows.length > 0) {
        const headers = Object.keys(result.rows[0]);
        const tableTop = doc.y;
        const itemHeight = 25;
        const maxWidth = doc.page.width - 80;
        const colWidth = maxWidth / headers.length;

        // Función para traducir nombres de columnas
        const traducirColumna = (col) => {
          const traducciones = {
            'nombre_completo': 'Nombre Completo',
            'matricula': 'Matrícula',
            'monto': 'Monto',
            'fecha_limite_prorroga': 'Fecha Límite',
            'estado': 'Estado',
            'total_adeudos': 'Total Adeudos',
            'monto_total': 'Monto Total',
            'grupo': 'Grupo',
            'nivel': 'Nivel',
            'maestro': 'Maestro',
            'total_alumnos': 'Total Alumnos',
            'reprobados': 'Reprobados',
            'activos': 'Activos',
            'deserciones': 'Deserciones',
            'salon': 'Salón',
            'edificio': 'Edificio',
            'capacidad': 'Capacidad',
            'grupos_asignados': 'Grupos',
            'horas_semanales': 'Horas/Sem',
            'inscritos': 'Inscritos',
            'aprobados': 'Aprobados',
            'concepto': 'Concepto',
            'total_pagos': 'Pagos',
            'estatus': 'Estatus',
            'carrera': 'Carrera',
            'semestre': 'Semestre',
            'nivel_actual': 'Nivel Actual',
            'correo': 'Correo',
            'telefono': 'Teléfono'
          };
          return traducciones[col] || col.replace(/_/g, ' ').toUpperCase();
        };

        // Encabezados con fondo
        doc.rect(40, tableTop, maxWidth, itemHeight).fill('#e5e7eb');
        doc.fillColor('#000000');

        let xPos = 50;
        doc.fontSize(9).font('Helvetica-Bold');
        headers.forEach(header => {
          doc.text(traducirColumna(header), xPos, tableTop + 8, {
            width: colWidth - 10,
            align: 'left',
            lineBreak: false,
            ellipsis: true
          });
          xPos += colWidth;
        });

        doc.moveDown();
        let yPos = tableTop + itemHeight;

        // Datos con líneas alternas
        doc.font('Helvetica').fontSize(8);
        result.rows.forEach((row, index) => {
          if (yPos > doc.page.height - 100) {
            doc.addPage();
            yPos = 50;

            // Re-dibujar encabezados en nueva página
            doc.rect(40, yPos, maxWidth, itemHeight).fill('#e5e7eb');
            doc.fillColor('#000000');
            xPos = 50;
            doc.fontSize(9).font('Helvetica-Bold');
            headers.forEach(header => {
              doc.text(traducirColumna(header), xPos, yPos + 8, {
                width: colWidth - 10,
                align: 'left',
                lineBreak: false,
                ellipsis: true
              });
              xPos += colWidth;
            });
            yPos += itemHeight;
            doc.font('Helvetica').fontSize(8);
          }

          // Fondo alternado
          if (index % 2 === 0) {
            doc.rect(40, yPos, maxWidth, itemHeight).fill('#f9fafb');
          }
          doc.fillColor('#000000');

          xPos = 50;
          headers.forEach(header => {
            let value = row[header];

            // Formatear valores especiales
            if (value === null || value === undefined) {
              value = '-';
            } else if (header.includes('monto') || header.includes('precio')) {
              value = `$${parseFloat(value).toFixed(2)}`;
            } else if (header.includes('fecha')) {
              value = new Date(value).toLocaleDateString('es-MX');
            } else if (typeof value === 'boolean') {
              value = value ? 'Sí' : 'No';
            } else {
              value = String(value);
            }

            doc.text(value, xPos, yPos + 8, {
              width: colWidth - 10,
              align: 'left',
              lineBreak: false,
              ellipsis: true
            });
            xPos += colWidth;
          });

          yPos += itemHeight;
        });
      } else {
        doc.fontSize(12)
          .fillColor('#6b7280')
          .text('No hay datos disponibles para este reporte', { align: 'center' });
      }

      // Footer con línea y totales
      const pages = doc.bufferedPageRange();
      for (let i = 0; i < pages.count; i++) {
        doc.switchToPage(i);

        const bottom = doc.page.height - 50;
        doc.moveTo(40, bottom - 10)
          .lineTo(doc.page.width - 40, bottom - 10)
          .stroke('#0369a1');

        doc.fontSize(8)
          .fillColor('#6b7280')
          .text(
            `TESCHA - Sistema de Coordinación de Inglés | Total de registros: ${result.rows.length}`,
            40,
            bottom,
            { align: 'center', width: doc.page.width - 80 }
          );

        doc.text(
          `Página ${i + 1} de ${pages.count}`,
          40,
          bottom + 12,
          { align: 'center', width: doc.page.width - 80 }
        );
      }

      doc.end();
    } else {
      // Formato JSON por defecto
      res.json({
        data: result.rows,
        tipo: tipo,
        total: result.rows.length
      });
    }
  } catch (error) {
    console.error('Error al generar reporte:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
