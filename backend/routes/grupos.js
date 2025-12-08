import express from 'express';
import pool from '../config/database.js';
import { auth, checkRole } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';

const router = express.Router();

// Obtener todos los grupos con filtros
router.get('/', auth, async (req, res) => {
  try {
    const { periodo_id, nivel, maestro_id, activo } = req.query;
    
    let query = `
      SELECT 
        g.*,
        p.nombre as periodo_nombre,
        CONCAT(m.nombre, ' ', m.apellido_paterno, ' ', COALESCE(m.apellido_materno, '')) as maestro_nombre,
        s.codigo as salon_codigo,
        s.capacidad as salon_capacidad,
        (SELECT COUNT(*) FROM inscripciones WHERE grupo_id = g.id AND estatus = 'activo') as inscritos_count
      FROM grupos g
      LEFT JOIN periodos p ON g.periodo_id = p.id
      LEFT JOIN maestros m ON g.maestro_id = m.id
      LEFT JOIN salones s ON g.salon_id = s.id
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
    
    if (maestro_id) {
      query += ` AND g.maestro_id = $${paramCount++}`;
      params.push(maestro_id);
    }
    
    if (activo !== undefined) {
      query += ` AND g.activo = $${paramCount++}`;
      params.push(activo === 'true');
    }
    
    query += ' ORDER BY g.codigo ASC';
    
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Obtener grupo por ID con detalles completos
router.get('/:id', auth, async (req, res) => {
  try {
    const grupoResult = await pool.query(
      `SELECT 
        g.*,
        p.nombre as periodo_nombre,
        CONCAT(m.nombre, ' ', m.apellido_paterno, ' ', COALESCE(m.apellido_materno, '')) as maestro_nombre,
        m.correo as maestro_correo,
        s.codigo as salon_codigo,
        s.nombre as salon_nombre,
        s.capacidad as salon_capacidad
      FROM grupos g
      LEFT JOIN periodos p ON g.periodo_id = p.id
      LEFT JOIN maestros m ON g.maestro_id = m.id
      LEFT JOIN salones s ON g.salon_id = s.id
      WHERE g.id = $1`,
      [req.params.id]
    );
    
    if (grupoResult.rows.length === 0) {
      return res.status(404).json({ error: 'Grupo no encontrado' });
    }
    
    // Obtener horarios
    const horariosResult = await pool.query(
      'SELECT * FROM grupos_horarios WHERE grupo_id = $1 ORDER BY dia, hora_inicio',
      [req.params.id]
    );
    
    // Obtener alumnos inscritos
    const alumnosResult = await pool.query(
      `SELECT 
        a.*,
        CONCAT(a.nombre, ' ', a.apellido_paterno, ' ', COALESCE(a.apellido_materno, '')) as nombre_completo,
        i.estatus as inscripcion_estatus,
        p.estatus as pago_estatus
      FROM inscripciones i
      JOIN alumnos a ON i.alumno_id = a.id
      LEFT JOIN pagos p ON i.id = p.inscripcion_id
      WHERE i.grupo_id = $1
      ORDER BY a.nombre, a.apellido_paterno`,
      [req.params.id]
    );
    
    const grupo = {
      ...grupoResult.rows[0],
      horarios: horariosResult.rows,
      alumnos: alumnosResult.rows
    };
    
    res.json(grupo);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Crear grupo
router.post('/', auth, checkRole('coordinador'), async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const {
      codigo_grupo,
      periodo_id,
      nivel,
      maestro_id,
      salon_id,
      modalidad,
      cupo_maximo,
      horarios // String o Array: [{dia, hora_inicio, hora_fin}]
    } = req.body;
    
    // Crear grupo
    const grupoResult = await client.query(
      `INSERT INTO grupos (codigo_grupo, periodo_id, nivel, maestro_id, salon_id, cupo_maximo, horarios)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [codigo_grupo, periodo_id, nivel, maestro_id, salon_id, cupo_maximo, typeof horarios === 'string' ? horarios : null]
    );
    
    const grupoId = grupoResult.rows[0].id;
    
    await logAudit(req.user.id, 'CREATE', 'grupos', grupoId, null, grupoResult.rows[0], req.ip);
    
    await client.query('COMMIT');
    res.status(201).json(grupoResult.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    if (error.code === '23505') {
      return res.status(400).json({ error: 'El código del grupo ya existe' });
    }
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// Actualizar grupo
router.put('/:id', auth, checkRole('coordinador'), async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const { id } = req.params;
    const { horarios, ...allFields } = req.body;
    
    // WHITELIST de campos permitidos (SEGURIDAD SQL)
    const CAMPOS_PERMITIDOS = [
      'codigo_grupo', 'nivel', 'periodo_id', 'maestro_id', 'salon_id',
      'cupo_maximo', 'activo'
    ];
    
    // Filtrar solo campos permitidos
    const fields = {};
    Object.keys(allFields).forEach(key => {
      if (CAMPOS_PERMITIDOS.includes(key)) {
        fields[key] = allFields[key];
      }
    });
    
    const oldData = await client.query('SELECT * FROM grupos WHERE id = $1', [id]);
    
    if (oldData.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Grupo no encontrado' });
    }
    
    // Si se actualiza el salón, validar disponibilidad
    if (fields.salon_id && fields.salon_id !== oldData.rows[0].salon_id) {
      const horariosActuales = await client.query(
        'SELECT * FROM grupos_horarios WHERE grupo_id = $1',
        [id]
      );
      
      for (const horario of horariosActuales.rows) {
        const conflictoResult = await client.query(
          `SELECT COUNT(*) as count
           FROM grupos g
           JOIN grupos_horarios gh ON g.id = gh.grupo_id
           WHERE g.salon_id = $1 
             AND gh.dia = $2
             AND g.id != $3
             AND g.activo = true
             AND (
               (gh.hora_inicio <= $4 AND gh.hora_fin > $4)
               OR (gh.hora_inicio < $5 AND gh.hora_fin >= $5)
               OR (gh.hora_inicio >= $4 AND gh.hora_fin <= $5)
             )`,
          [fields.salon_id, horario.dia, id, horario.hora_inicio, horario.hora_fin]
        );
        
        if (parseInt(conflictoResult.rows[0].count) > 0) {
          await client.query('ROLLBACK');
          return res.status(400).json({ 
            error: `Conflicto de horario: El nuevo salón ya está ocupado en ese horario` 
          });
        }
      }
      
      // Registrar cambio de salón en historial
      await client.query(
        'INSERT INTO historial_salones (grupo_id, salon_anterior_id, salon_nuevo_id, realizado_por) VALUES ($1, $2, $3, $4)',
        [id, oldData.rows[0].salon_id, fields.salon_id, req.user.id]
      );
    }
    
    // Actualizar grupo
    const keys = Object.keys(fields);
    const values = Object.values(fields);
    const setClause = keys.map((key, idx) => `${key} = $${idx + 1}`).join(', ');
    
    const result = await client.query(
      `UPDATE grupos SET ${setClause} WHERE id = $${keys.length + 1} RETURNING *`,
      [...values, id]
    );
    
    // Actualizar horarios si se proporcionan
    if (horarios) {
      await client.query('DELETE FROM grupos_horarios WHERE grupo_id = $1', [id]);
      
      for (const horario of horarios) {
        await client.query(
          'INSERT INTO grupos_horarios (grupo_id, dia, hora_inicio, hora_fin) VALUES ($1, $2, $3, $4)',
          [id, horario.dia, horario.hora_inicio, horario.hora_fin]
        );
      }
    }
    
    await logAudit(req.user.id, 'UPDATE', 'grupos', id, oldData.rows[0], result.rows[0], req.ip);
    
    await client.query('COMMIT');
    res.json(result.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// Eliminar grupo
router.delete('/:id', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const { id } = req.params;
    
    const oldData = await pool.query('SELECT * FROM grupos WHERE id = $1', [id]);
    
    if (oldData.rows.length === 0) {
      return res.status(404).json({ error: 'Grupo no encontrado' });
    }
    
    await pool.query('DELETE FROM grupos WHERE id = $1', [id]);
    
    await logAudit(req.user.id, 'DELETE', 'grupos', id, oldData.rows[0], null, req.ip);
    
    res.json({ message: 'Grupo eliminado exitosamente' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Inscribir alumnos al grupo
router.post('/:id/inscribir', auth, checkRole('coordinador', 'administrativo'), async (req, res) => {
  try {
    const { id } = req.params;
    const { alumno_ids } = req.body; // Array de IDs de alumnos
    
    const grupoResult = await pool.query('SELECT * FROM grupos WHERE id = $1', [id]);
    
    if (grupoResult.rows.length === 0) {
      return res.status(404).json({ error: 'Grupo no encontrado' });
    }
    
    const grupo = grupoResult.rows[0];
    
    // Verificar cupo
    const inscritosResult = await pool.query(
      'SELECT COUNT(*) as count FROM inscripciones WHERE grupo_id = $1 AND estatus = $2',
      [id, 'activo']
    );
    
    const inscritosActuales = parseInt(inscritosResult.rows[0].count);
    
    if (inscritosActuales + alumno_ids.length > grupo.cupo_maximo) {
      return res.status(400).json({ error: 'No hay suficiente cupo en el grupo' });
    }
    
    const resultados = {
      exitosos: 0,
      errores: []
    };
    
    for (const alumno_id of alumno_ids) {
      try {
        await pool.query(
          'INSERT INTO inscripciones (alumno_id, grupo_id, periodo_id) VALUES ($1, $2, $3)',
          [alumno_id, id, grupo.periodo_id]
        );
        resultados.exitosos++;
      } catch (error) {
        resultados.errores.push({
          alumno_id,
          error: error.message
        });
      }
    }
    
    res.json(resultados);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Obtener lista de alumnos del grupo con estatus de pago
router.get('/:id/alumnos', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        a.*,
        CONCAT(a.nombre, ' ', a.apellido_paterno, ' ', COALESCE(a.apellido_materno, '')) as nombre_completo,
        i.estatus as inscripcion_estatus,
        i.es_recursador,
        p.estatus as pago_estatus,
        p.monto as pago_monto,
        p.fecha_pago
      FROM inscripciones i
      JOIN alumnos a ON i.alumno_id = a.id
      LEFT JOIN pagos p ON i.id = p.inscripcion_id
      WHERE i.grupo_id = $1
      ORDER BY a.nombre, a.apellido_paterno`,
      [req.params.id]
    );
    
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
