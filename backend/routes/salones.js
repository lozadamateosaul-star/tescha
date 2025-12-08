import express from 'express';
import pool from '../config/database.js';
import { auth, checkRole } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';

const router = express.Router();

// Obtener todos los salones
router.get('/', auth, async (req, res) => {
  try {
    const { estatus, tipo, edificio } = req.query;
    
    let query = 'SELECT * FROM salones WHERE 1=1';
    const params = [];
    let paramCount = 1;
    
    if (estatus) {
      query += ` AND estatus = $${paramCount++}`;
      params.push(estatus);
    }
    
    if (tipo) {
      query += ` AND tipo = $${paramCount++}`;
      params.push(tipo);
    }
    
    if (edificio) {
      query += ` AND edificio = $${paramCount++}`;
      params.push(edificio);
    }
    
    query += ' ORDER BY codigo ASC';
    
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Obtener salón por ID
router.get('/:id', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM salones WHERE id = $1', [req.params.id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Salón no encontrado' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Verificar disponibilidad de salón en un horario específico
router.post('/verificar-disponibilidad', auth, async (req, res) => {
  try {
    const { salon_id, dia, hora_inicio, hora_fin, grupo_id_excluir } = req.body;
    
    let query = `
      SELECT g.id, g.codigo, g.nivel, m.nombre_completo as maestro
      FROM grupos g
      JOIN grupos_horarios gh ON g.id = gh.grupo_id
      LEFT JOIN maestros m ON g.maestro_id = m.id
      WHERE g.salon_id = $1 
        AND gh.dia = $2
        AND g.activo = true
        AND (
          (gh.hora_inicio <= $3 AND gh.hora_fin > $3)
          OR (gh.hora_inicio < $4 AND gh.hora_fin >= $4)
          OR (gh.hora_inicio >= $3 AND gh.hora_fin <= $4)
        )
    `;
    
    const params = [salon_id, dia, hora_inicio, hora_fin];
    
    if (grupo_id_excluir) {
      query += ` AND g.id != $5`;
      params.push(grupo_id_excluir);
    }
    
    const result = await pool.query(query, params);
    
    res.json({
      disponible: result.rows.length === 0,
      conflictos: result.rows
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Obtener horario completo de un salón (Lunes a Sábado)
router.get('/:id/horario', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        gh.dia,
        gh.hora_inicio,
        gh.hora_fin,
        g.codigo as grupo_codigo,
        g.nivel,
        m.nombre_completo as maestro
      FROM grupos_horarios gh
      JOIN grupos g ON gh.grupo_id = g.id
      LEFT JOIN maestros m ON g.maestro_id = m.id
      WHERE g.salon_id = $1 AND g.activo = true
      ORDER BY 
        CASE gh.dia
          WHEN 'lunes' THEN 1
          WHEN 'martes' THEN 2
          WHEN 'miercoles' THEN 3
          WHEN 'jueves' THEN 4
          WHEN 'viernes' THEN 5
          WHEN 'sabado' THEN 6
        END,
        gh.hora_inicio`,
      [req.params.id]
    );
    
    // Organizar por día
    const horarioPorDia = {
      lunes: [],
      martes: [],
      miercoles: [],
      jueves: [],
      viernes: [],
      sabado: []
    };
    
    result.rows.forEach(row => {
      horarioPorDia[row.dia].push({
        hora_inicio: row.hora_inicio,
        hora_fin: row.hora_fin,
        grupo_codigo: row.grupo_codigo,
        nivel: row.nivel,
        maestro: row.maestro
      });
    });
    
    res.json(horarioPorDia);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Sugerir salones disponibles para un horario
router.post('/sugerir', auth, async (req, res) => {
  try {
    const { dia, hora_inicio, hora_fin, capacidad_minima } = req.body;
    
    // Obtener todos los salones disponibles
    const salonesResult = await pool.query(
      `SELECT * FROM salones 
       WHERE estatus = 'disponible' 
       AND capacidad >= $1
       ORDER BY capacidad ASC`,
      [capacidad_minima || 0]
    );
    
    const sugerencias = [];
    
    for (const salon of salonesResult.rows) {
      // Verificar si está ocupado en ese horario
      const conflictoResult = await pool.query(
        `SELECT COUNT(*) as count
         FROM grupos g
         JOIN grupos_horarios gh ON g.id = gh.grupo_id
         WHERE g.salon_id = $1 
           AND gh.dia = $2
           AND g.activo = true
           AND (
             (gh.hora_inicio <= $3 AND gh.hora_fin > $3)
             OR (gh.hora_inicio < $4 AND gh.hora_fin >= $4)
             OR (gh.hora_inicio >= $3 AND gh.hora_fin <= $4)
           )`,
        [salon.id, dia, hora_inicio, hora_fin]
      );
      
      if (parseInt(conflictoResult.rows[0].count) === 0) {
        sugerencias.push(salon);
      }
    }
    
    res.json(sugerencias);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Crear salón
router.post('/', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const { codigo, nombre, edificio, tipo, capacidad, foto_url, descripcion } = req.body;
    
    const result = await pool.query(
      `INSERT INTO salones (codigo, nombre, edificio, tipo, capacidad, foto_url, descripcion)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [codigo, nombre, edificio, tipo, capacidad, foto_url, descripcion]
    );
    
    await logAudit(req.user.id, 'CREATE', 'salones', result.rows[0].id, null, result.rows[0], req.ip);
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    if (error.code === '23505') {
      return res.status(400).json({ error: 'El código del salón ya existe' });
    }
    res.status(500).json({ error: error.message });
  }
});

// Actualizar salón
router.put('/:id', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const { id } = req.params;
    
    // WHITELIST de campos permitidos (SEGURIDAD SQL)
    const CAMPOS_PERMITIDOS = [
      'codigo', 'nombre', 'edificio', 'tipo', 'capacidad',
      'estatus', 'foto_url', 'descripcion'
    ];
    
    const fields = {};
    Object.keys(req.body).forEach(key => {
      if (CAMPOS_PERMITIDOS.includes(key)) {
        fields[key] = req.body[key];
      }
    });
    
    if (Object.keys(fields).length === 0) {
      return res.status(400).json({ error: 'No se proporcionaron campos válidos para actualizar' });
    }
    
    const oldData = await pool.query('SELECT * FROM salones WHERE id = $1', [id]);
    
    if (oldData.rows.length === 0) {
      return res.status(404).json({ error: 'Salón no encontrado' });
    }
    
    const keys = Object.keys(fields);
    const values = Object.values(fields);
    const setClause = keys.map((key, idx) => `${key} = $${idx + 1}`).join(', ');
    
    const result = await pool.query(
      `UPDATE salones SET ${setClause} WHERE id = $${keys.length + 1} RETURNING *`,
      [...values, id]
    );
    
    await logAudit(req.user.id, 'UPDATE', 'salones', id, oldData.rows[0], result.rows[0], req.ip);
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Eliminar salón
router.delete('/:id', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const { id } = req.params;
    
    // Verificar si hay grupos usando este salón
    const gruposResult = await pool.query(
      'SELECT COUNT(*) as count FROM grupos WHERE salon_id = $1 AND activo = true',
      [id]
    );
    
    if (parseInt(gruposResult.rows[0].count) > 0) {
      return res.status(400).json({ 
        error: 'No se puede eliminar el salón porque tiene grupos activos asignados' 
      });
    }
    
    const oldData = await pool.query('SELECT * FROM salones WHERE id = $1', [id]);
    
    if (oldData.rows.length === 0) {
      return res.status(404).json({ error: 'Salón no encontrado' });
    }
    
    await pool.query('DELETE FROM salones WHERE id = $1', [id]);
    
    await logAudit(req.user.id, 'DELETE', 'salones', id, oldData.rows[0], null, req.ip);
    
    res.json({ message: 'Salón eliminado exitosamente' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Historial de cambios de salón
router.get('/:id/historial', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        hs.*,
        g.codigo as grupo_codigo,
        sa.codigo as salon_anterior_codigo,
        sn.codigo as salon_nuevo_codigo,
        u.username as realizado_por_username
      FROM historial_salones hs
      LEFT JOIN grupos g ON hs.grupo_id = g.id
      LEFT JOIN salones sa ON hs.salon_anterior_id = sa.id
      LEFT JOIN salones sn ON hs.salon_nuevo_id = sn.id
      LEFT JOIN usuarios u ON hs.realizado_por = u.id
      WHERE hs.salon_anterior_id = $1 OR hs.salon_nuevo_id = $1
      ORDER BY hs.fecha_cambio DESC`,
      [req.params.id]
    );
    
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Registrar mantenimiento de salón
router.post('/:id/mantenimiento', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const { id } = req.params;
    const { fecha_inicio, fecha_fin, tipo_mantenimiento, descripcion, costo, realizado_por } = req.body;
    
    const result = await pool.query(
      `INSERT INTO mantenimientos_salones 
       (salon_id, fecha_inicio, fecha_fin, tipo_mantenimiento, descripcion, costo, realizado_por)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [id, fecha_inicio, fecha_fin, tipo_mantenimiento, descripcion, costo, realizado_por]
    );
    
    // Actualizar estatus del salón a mantenimiento
    await pool.query(
      'UPDATE salones SET estatus = $1 WHERE id = $2',
      ['mantenimiento', id]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Obtener todos los mantenimientos de un salón
router.get('/:id/mantenimientos', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM mantenimientos_salones WHERE salon_id = $1 ORDER BY created_at DESC',
      [req.params.id]
    );
    
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mapa de ocupación de todos los salones por horario
router.get('/mapa/ocupacion', auth, async (req, res) => {
  try {
    const { dia, periodo_id } = req.query;
    
    let query = `
      SELECT 
        s.id,
        s.codigo,
        s.nombre,
        s.edificio,
        s.capacidad,
        s.estatus,
        json_agg(
          json_build_object(
            'dia', gh.dia,
            'hora_inicio', gh.hora_inicio,
            'hora_fin', gh.hora_fin,
            'grupo_codigo', g.codigo,
            'nivel', g.nivel,
            'maestro', m.nombre_completo
          ) ORDER BY gh.hora_inicio
        ) FILTER (WHERE gh.id IS NOT NULL) as horarios_ocupados
      FROM salones s
      LEFT JOIN grupos g ON s.id = g.salon_id AND g.activo = true
      LEFT JOIN grupos_horarios gh ON g.id = gh.grupo_id
      LEFT JOIN maestros m ON g.maestro_id = m.id
    `;
    
    const params = [];
    let paramCount = 1;
    
    if (dia) {
      query += ` WHERE gh.dia = $${paramCount++}`;
      params.push(dia);
    }
    
    if (periodo_id) {
      query += params.length > 0 ? ' AND' : ' WHERE';
      query += ` g.periodo_id = $${paramCount++}`;
      params.push(periodo_id);
    }
    
    query += ' GROUP BY s.id ORDER BY s.codigo';
    
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
