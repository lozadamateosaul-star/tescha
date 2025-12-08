import express from 'express';
import pool from '../config/database.js';
import { auth, checkRole } from '../middleware/auth.js';

const router = express.Router();

// Registrar asistencia
router.post('/', auth, checkRole('coordinador', 'maestro'), async (req, res) => {
  try {
    const { inscripcion_id, alumno_id, grupo_id, salon_id, fecha, presente, justificada, observaciones } = req.body;
    
    const result = await pool.query(
      `INSERT INTO asistencias (inscripcion_id, alumno_id, grupo_id, salon_id, fecha, presente, justificada, observaciones)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (inscripcion_id, fecha)
       DO UPDATE SET presente = $6, justificada = $7, observaciones = $8
       RETURNING *`,
      [inscripcion_id, alumno_id, grupo_id, salon_id, fecha, presente, justificada, observaciones]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Registrar asistencias masivas (lista completa del grupo)
router.post('/masivo', auth, checkRole('coordinador', 'maestro'), async (req, res) => {
  const client = await pool.connect();
  try {
    const { grupo_id, fecha, asistencias } = req.body;
    
    await client.query('BEGIN');
    
    for (const asist of asistencias) {
      // Convertir estatus string a booleanos
      const presente = asist.estatus === 'Asistencia' || asist.estatus === 'Retardo';
      const justificada = asist.estatus === 'Justificada';
      
      await client.query(
        `INSERT INTO asistencias (inscripcion_id, alumno_id, grupo_id, fecha, presente, justificada, observaciones)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (inscripcion_id, fecha)
         DO UPDATE SET presente = $5, justificada = $6, observaciones = $7`,
        [asist.inscripcion_id, asist.alumno_id, grupo_id, fecha, presente, justificada, asist.observaciones || '']
      );
    }
    
    await client.query('COMMIT');
    res.json({ message: 'Asistencias registradas exitosamente' });
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// Obtener asistencias de un grupo en una fecha
router.get('/grupo/:grupo_id', auth, async (req, res) => {
  try {
    const { fecha } = req.query;
    
    let query = `
      SELECT 
        a.id,
        CONCAT(a.nombre, ' ', a.apellido_paterno, ' ', COALESCE(a.apellido_materno, '')) as nombre_completo,
        a.matricula,
        i.id as inscripcion_id,
        asist.presente,
        asist.justificada,
        asist.observaciones
      FROM inscripciones i
      JOIN alumnos a ON i.alumno_id = a.id
      LEFT JOIN asistencias asist ON i.id = asist.inscripcion_id AND asist.fecha = $2
      WHERE i.grupo_id = $1 AND i.estatus = 'activo'
      ORDER BY a.nombre, a.apellido_paterno
    `;
    
    const result = await pool.query(query, [req.params.grupo_id, fecha]);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Reporte de asistencias de un alumno
router.get('/alumno/:alumno_id', auth, async (req, res) => {
  try {
    const { grupo_id } = req.query;
    
    let query = `
      SELECT 
        asist.*,
        g.codigo as grupo,
        s.codigo as salon
      FROM asistencias asist
      JOIN grupos g ON asist.grupo_id = g.id
      LEFT JOIN salones s ON asist.salon_id = s.id
      WHERE asist.alumno_id = $1
    `;
    
    const params = [req.params.alumno_id];
    
    if (grupo_id) {
      query += ' AND asist.grupo_id = $2';
      params.push(grupo_id);
    }
    
    query += ' ORDER BY asist.fecha DESC';
    
    const result = await pool.query(query, params);
    
    // Calcular porcentaje
    const totalResult = await pool.query(
      'SELECT COUNT(*) as total FROM asistencias WHERE alumno_id = $1' + (grupo_id ? ' AND grupo_id = $2' : ''),
      grupo_id ? [req.params.alumno_id, grupo_id] : [req.params.alumno_id]
    );
    
    const presentesResult = await pool.query(
      'SELECT COUNT(*) as presentes FROM asistencias WHERE alumno_id = $1 AND presente = true' + (grupo_id ? ' AND grupo_id = $2' : ''),
      grupo_id ? [req.params.alumno_id, grupo_id] : [req.params.alumno_id]
    );
    
    const total = parseInt(totalResult.rows[0].total);
    const presentes = parseInt(presentesResult.rows[0].presentes);
    const porcentaje = total > 0 ? (presentes / total) * 100 : 0;
    
    res.json({
      asistencias: result.rows,
      estadisticas: {
        total,
        presentes,
        ausencias: total - presentes,
        porcentaje: porcentaje.toFixed(2)
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Alumnos en riesgo por faltas
router.get('/grupo/:grupo_id/riesgo', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        a.id,
        CONCAT(a.nombre, ' ', a.apellido_paterno, ' ', COALESCE(a.apellido_materno, '')) as nombre_completo,
        a.matricula,
        COUNT(*) FILTER (WHERE asist.presente = false AND asist.justificada = false) as faltas,
        COUNT(*) as total_clases,
        ROUND((COUNT(*) FILTER (WHERE asist.presente = true)::numeric / COUNT(*)::numeric) * 100, 2) as porcentaje_asistencia
      FROM inscripciones i
      JOIN alumnos a ON i.alumno_id = a.id
      LEFT JOIN asistencias asist ON i.id = asist.inscripcion_id
      WHERE i.grupo_id = $1
      GROUP BY a.id, a.nombre, a.apellido_paterno, a.apellido_materno
      HAVING ROUND((COUNT(*) FILTER (WHERE asist.presente = true)::numeric / COUNT(*)::numeric) * 100, 2) < 80
      ORDER BY porcentaje_asistencia ASC`,
      [req.params.grupo_id]
    );
    
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
