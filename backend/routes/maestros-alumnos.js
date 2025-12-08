import express from 'express';
import pool from '../config/database.js';
import { auth, checkRole } from '../middleware/auth.js';

const router = express.Router();

// Obtener grupos de un maestro con sus alumnos inscritos
router.get('/:maestroId/grupos-alumnos', auth, checkRole('coordinador', 'administrativo'), async (req, res) => {
  try {
    const { maestroId } = req.params;
    
    // Obtener grupos del maestro
    const grupos = await pool.query(
      `SELECT g.id, g.codigo, g.nivel, g.horario, g.salon_id, g.activo,
              s.nombre as salon_nombre,
              COUNT(DISTINCT i.alumno_id) as total_alumnos
       FROM grupos g
       LEFT JOIN salones s ON g.salon_id = s.id
       LEFT JOIN inscripciones i ON g.id = i.grupo_id AND i.estatus = 'activo'
       WHERE g.maestro_id = $1
       GROUP BY g.id, s.nombre
       ORDER BY g.activo DESC, g.nivel, g.codigo`,
      [maestroId]
    );
    
    res.json(grupos.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Obtener alumnos de un grupo específico
router.get('/:maestroId/grupos/:grupoId/alumnos', auth, checkRole('coordinador', 'administrativo'), async (req, res) => {
  try {
    const { grupoId } = req.params;
    
    const alumnos = await pool.query(
      `SELECT a.id, a.matricula, 
              CONCAT(a.nombre, ' ', a.apellido_paterno, ' ', COALESCE(a.apellido_materno, '')) as nombre_completo,
              a.nivel_actual, a.tipo_alumno, i.id as inscripcion_id, i.estatus as inscripcion_estatus
       FROM inscripciones i
       JOIN alumnos a ON i.alumno_id = a.id
       WHERE i.grupo_id = $1 AND i.estatus = 'activo'
       ORDER BY a.nombre, a.apellido_paterno`,
      [grupoId]
    );
    
    res.json(alumnos.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Obtener alumnos disponibles para inscribir (no inscritos en el grupo)
router.get('/:maestroId/grupos/:grupoId/disponibles', auth, checkRole('coordinador', 'administrativo'), async (req, res) => {
  try {
    const { grupoId } = req.params;
    
    // Obtener nivel del grupo
    const grupo = await pool.query('SELECT nivel FROM grupos WHERE id = $1', [grupoId]);
    const nivelGrupo = grupo.rows[0]?.nivel;
    
    const alumnosDisponibles = await pool.query(
      `SELECT a.id, a.matricula, 
              CONCAT(a.nombre, ' ', a.apellido_paterno, ' ', COALESCE(a.apellido_materno, '')) as nombre_completo,
              a.nivel_actual, a.tipo_alumno, a.semestre
       FROM alumnos a
       WHERE a.estatus = 'activo' 
       AND a.nivel_actual = $1
       AND NOT EXISTS (
         SELECT 1 FROM inscripciones i 
         WHERE i.alumno_id = a.id 
         AND i.grupo_id = $2 
         AND i.estatus = 'activo'
       )
       ORDER BY a.nombre, a.apellido_paterno
       LIMIT 100`,
      [nivelGrupo, grupoId]
    );
    
    res.json(alumnosDisponibles.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Inscribir alumno a un grupo (SÚPER FÁCIL)
router.post('/:maestroId/grupos/:grupoId/inscribir', auth, checkRole('coordinador', 'administrativo'), async (req, res) => {
  try {
    const { grupoId } = req.params;
    const { alumnoId } = req.body;
    
    // Obtener periodo activo
    const periodo = await pool.query('SELECT id FROM periodos WHERE activo = true LIMIT 1');
    const periodoId = periodo.rows[0]?.id;
    
    if (!periodoId) {
      return res.status(400).json({ error: 'No hay período activo' });
    }
    
    // Verificar si ya está inscrito
    const yaInscrito = await pool.query(
      'SELECT id FROM inscripciones WHERE alumno_id = $1 AND grupo_id = $2 AND estatus = \'activo\'',
      [alumnoId, grupoId]
    );
    
    if (yaInscrito.rows.length > 0) {
      return res.status(400).json({ error: 'El alumno ya está inscrito en este grupo' });
    }
    
    // Inscribir
    const result = await pool.query(
      `INSERT INTO inscripciones (alumno_id, grupo_id, periodo_id, estatus, fecha_inscripcion)
       VALUES ($1, $2, $3, 'activo', CURRENT_DATE)
       RETURNING *`,
      [alumnoId, grupoId, periodoId]
    );
    
    res.json({ message: 'Alumno inscrito exitosamente', inscripcion: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Remover alumno de un grupo
router.delete('/:maestroId/grupos/:grupoId/alumnos/:inscripcionId', auth, checkRole('coordinador', 'administrativo'), async (req, res) => {
  try {
    const { inscripcionId } = req.params;
    
    await pool.query(
      'UPDATE inscripciones SET estatus = \'baja\' WHERE id = $1',
      [inscripcionId]
    );
    
    res.json({ message: 'Alumno removido del grupo' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
