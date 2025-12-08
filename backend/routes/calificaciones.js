import express from 'express';
import pool from '../config/database.js';
import { auth, checkRole } from '../middleware/auth.js';

const router = express.Router();

// Obtener calificaciones de un grupo
router.get('/grupo/:grupo_id', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        i.id as inscripcion_id,
        a.id as alumno_id,
        CONCAT(a.nombre, ' ', a.apellido_paterno, ' ', COALESCE(a.apellido_materno, '')) as nombre_completo,
        a.matricula,
        json_agg(
          json_build_object(
            'parcial', c.parcial,
            'calificacion', c.calificacion,
            'observaciones', c.observaciones
          ) ORDER BY c.parcial
        ) FILTER (WHERE c.id IS NOT NULL) as calificaciones
      FROM inscripciones i
      JOIN alumnos a ON i.alumno_id = a.id
      LEFT JOIN calificaciones c ON i.id = c.inscripcion_id
      WHERE i.grupo_id = $1
      GROUP BY i.id, a.id, a.nombre, a.apellido_paterno, a.apellido_materno
      ORDER BY a.nombre, a.apellido_paterno`,
      [req.params.grupo_id]
    );
    
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Capturar/actualizar calificación
router.post('/', auth, checkRole('coordinador', 'maestro'), async (req, res) => {
  try {
    const { inscripcion_id, alumno_id, grupo_id, parcial, calificacion } = req.body;
    
    const result = await pool.query(
      `INSERT INTO calificaciones (inscripcion_id, alumno_id, grupo_id, parcial, calificacion)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (inscripcion_id, parcial) 
       DO UPDATE SET calificacion = $5
       RETURNING *`,
      [inscripcion_id, alumno_id, grupo_id, parcial, calificacion]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Captura masiva de calificaciones
router.post('/masivo', auth, checkRole('coordinador', 'maestro'), async (req, res) => {
  try {
    const { calificaciones } = req.body; // Array de objetos
    
    const client = await pool.connect();
    await client.query('BEGIN');
    
    for (const cal of calificaciones) {
      await client.query(
        `INSERT INTO calificaciones (inscripcion_id, alumno_id, grupo_id, parcial, calificacion, observaciones)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (inscripcion_id, parcial) 
         DO UPDATE SET calificacion = $5, observaciones = $6`,
        [cal.inscripcion_id, cal.alumno_id, cal.grupo_id, cal.parcial, cal.calificacion, cal.observaciones || '']
      );
    }
    
    await client.query('COMMIT');
    client.release();
    
    res.json({ message: 'Calificaciones capturadas exitosamente' });
  } catch (error) {
    await client.query('ROLLBACK');
    client.release();
    res.status(500).json({ error: error.message });
  }
});

// Obtener historial de calificaciones de un alumno
router.get('/alumno/:alumno_id', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        c.*,
        g.codigo as grupo,
        g.nivel,
        p.nombre as periodo
      FROM calificaciones c
      JOIN grupos g ON c.grupo_id = g.id
      LEFT JOIN periodos p ON g.periodo_id = p.id
      WHERE c.alumno_id = $1
      ORDER BY c.created_at DESC`,
      [req.params.alumno_id]
    );
    
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Alumnos reprobados en un grupo
router.get('/grupo/:grupo_id/reprobados', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        a.id,
        CONCAT(a.nombre, ' ', a.apellido_paterno, ' ', COALESCE(a.apellido_materno, '')) as nombre_completo,
        a.matricula,
        AVG(c.calificacion) as promedio
      FROM inscripciones i
      JOIN alumnos a ON i.alumno_id = a.id
      LEFT JOIN calificaciones c ON i.id = c.inscripcion_id
      WHERE i.grupo_id = $1
      GROUP BY a.id, a.nombre, a.apellido_paterno, a.apellido_materno, a.matricula
      HAVING AVG(c.calificacion) < 70 OR AVG(c.calificacion) IS NULL
      ORDER BY a.nombre, a.apellido_paterno`,
      [req.params.grupo_id]
    );
    
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
