import express from 'express';
import bcrypt from 'bcryptjs';
import pool from '../config/database.js';
import { auth, checkRole } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';

const router = express.Router();

// Obtener todos los alumnos con filtros
router.get('/', auth, async (req, res) => {
  try {
    const { tipo, nivel, carrera, estatus, search, page = 1, limit = 10000 } = req.query;

    let query = `SELECT DISTINCT a.*, 
      CASE 
        WHEN a.nombre_completo IS NOT NULL AND a.nombre_completo != '' THEN a.nombre_completo
        ELSE CONCAT(a.nombre, ' ', a.apellido_paterno, ' ', COALESCE(a.apellido_materno, ''))
      END as nombre_completo 
      FROM alumnos a`;

    // Si es maestro, solo mostrar alumnos de sus grupos
    if (req.user.rol === 'maestro') {
      query += ` 
        INNER JOIN inscripciones i ON a.id = i.alumno_id
        INNER JOIN grupos g ON i.grupo_id = g.id
        INNER JOIN maestros m ON g.maestro_id = m.id
        WHERE m.usuario_id = $1`;
      var params = [req.user.id];
      var paramCount = 2;
    } else {
      query += ' WHERE 1=1';
      var params = [];
      var paramCount = 1;
    }

    if (tipo) {
      query += ` AND tipo_alumno = $${paramCount++}`;
      params.push(tipo);
    }

    if (nivel) {
      query += ` AND nivel_actual = $${paramCount++}`;
      params.push(nivel);
    }

    if (carrera) {
      query += ` AND carrera = $${paramCount++}`;
      params.push(carrera);
    }

    if (estatus) {
      query += ` AND estatus = $${paramCount++}`;
      params.push(estatus);
    }

    if (search) {
      query += ` AND (nombre ILIKE $${paramCount} OR apellido_paterno ILIKE $${paramCount} OR apellido_materno ILIKE $${paramCount} OR nombre_completo ILIKE $${paramCount} OR matricula ILIKE $${paramCount} OR correo ILIKE $${paramCount})`;
      params.push(`%${search}%`);
      paramCount++;
    }

    query += ' ORDER BY created_at DESC';

    const offset = (page - 1) * limit;
    query += ` LIMIT $${paramCount++} OFFSET $${paramCount}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    // Contar total
    const countQuery = query.split('LIMIT')[0];
    const countResult = await pool.query(`SELECT COUNT(*) FROM (${countQuery}) AS total`, params.slice(0, -2));

    res.json({
      alumnos: result.rows,
      total: parseInt(countResult.rows[0].count),
      page: parseInt(page),
      pages: Math.ceil(countResult.rows[0].count / limit)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Obtener alumno por ID
router.get('/:id', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM alumnos WHERE id = $1', [req.params.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Alumno no encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Crear alumno
router.post('/', auth, checkRole('coordinador', 'administrativo'), async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const {
      tipo_alumno,
      matricula,
      nombre_completo,
      correo,
      telefono,
      municipio,
      carrera,
      semestre,
      procedencia,
      nivel_actual,
      es_nuevo_ingreso,
      fecha_ingreso
    } = req.body;

    // VALIDACIÓN 1: Verificar si la matrícula ya existe (antes de crear usuario)
    if (matricula) {
      const matriculaCheck = await client.query(
        'SELECT id FROM alumnos WHERE matricula = $1',
        [matricula]
      );
      if (matriculaCheck.rows.length > 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'La matrícula ya existe' });
      }
    }

    // VALIDACIÓN 2: Verificar si el correo ya existe (antes de crear usuario)
    if (correo) {
      const correoCheck = await client.query(
        'SELECT id FROM alumnos WHERE correo = $1',
        [correo]
      );
      if (correoCheck.rows.length > 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'El correo ya existe' });
      }
    }

    // Crear usuario si es necesario
    let usuarioId = null;
    if (correo) {
      const username = correo.split('@')[0];

      // VALIDACIÓN 3: Verificar si el username ya existe
      const usernameCheck = await client.query(
        'SELECT id FROM usuarios WHERE username = $1',
        [username]
      );

      if (usernameCheck.rows.length > 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'El correo ya está registrado en el sistema' });
      }

      const password = await bcrypt.hash('alumno123', 10);

      const userResult = await client.query(
        'INSERT INTO usuarios (username, password, rol) VALUES ($1, $2, $3) RETURNING id',
        [username, password, 'alumno']
      );
      usuarioId = userResult.rows[0].id;
    }

    const result = await client.query(
      `INSERT INTO alumnos 
       (usuario_id, tipo_alumno, matricula, nombre, apellido_paterno, apellido_materno, nombre_completo, correo, telefono, municipio, carrera, semestre, procedencia, nivel_actual, es_nuevo_ingreso, fecha_ingreso) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) 
       RETURNING *`,
      [usuarioId, tipo_alumno, matricula, req.body.nombre, req.body.apellido_paterno, req.body.apellido_materno, nombre_completo, correo, telefono, municipio, carrera, semestre, procedencia, nivel_actual, es_nuevo_ingreso, fecha_ingreso]
    );

    await logAudit(req.user.id, 'CREATE', 'alumnos', result.rows[0].id, null, result.rows[0], req.ip);

    await client.query('COMMIT');
    res.status(201).json(result.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');

    // Manejo específico de errores
    if (error.code === '23505') {
      // Constraint de unicidad violado
      if (error.constraint && error.constraint.includes('matricula')) {
        return res.status(400).json({ error: 'La matrícula ya existe' });
      }
      if (error.constraint && error.constraint.includes('correo')) {
        return res.status(400).json({ error: 'El correo ya existe' });
      }
      return res.status(400).json({ error: 'Ya existe un registro con esos datos' });
    }

    if (error.code === '23503') {
      // Constraint de llave foránea
      return res.status(400).json({ error: 'Error de referencia en la base de datos' });
    }

    if (error.code === '23514') {
      // Constraint de validación (CHECK)
      return res.status(400).json({ error: 'Valor inválido en algún campo. Verifica tipo de alumno, nivel o estatus' });
    }

    console.error('Error al crear alumno:', error);
    res.status(500).json({ error: 'Error al crear alumno: ' + error.message });
  } finally {
    client.release();
  }
});

// Actualizar alumno
router.put('/:id', auth, checkRole('coordinador', 'administrativo'), async (req, res) => {
  try {
    const { id } = req.params;

    // WHITELIST de campos permitidos (SEGURIDAD SQL)
    const CAMPOS_PERMITIDOS = [
      'nombre', 'apellido_paterno', 'apellido_materno', 'fecha_nacimiento',
      'correo', 'telefono', 'municipio', 'carrera', 'semestre', 'nivel_actual',
      'tipo_alumno', 'estatus', 'es_nuevo_ingreso', 'tutor_nombre',
      'tutor_telefono', 'tutor_correo', 'observaciones', 'foto_url', 'matricula'
    ];

    // Filtrar solo campos permitidos
    const fields = {};
    Object.keys(req.body).forEach(key => {
      if (CAMPOS_PERMITIDOS.includes(key)) {
        fields[key] = req.body[key];
      }
    });

    if (Object.keys(fields).length === 0) {
      return res.status(400).json({ error: 'No se proporcionaron campos válidos para actualizar' });
    }

    const oldData = await pool.query('SELECT * FROM alumnos WHERE id = $1', [id]);

    if (oldData.rows.length === 0) {
      return res.status(404).json({ error: 'Alumno no encontrado' });
    }

    const keys = Object.keys(fields);
    const values = Object.values(fields);
    const setClause = keys.map((key, idx) => `${key} = $${idx + 1}`).join(', ');

    const result = await pool.query(
      `UPDATE alumnos SET ${setClause} WHERE id = $${keys.length + 1} RETURNING *`,
      [...values, id]
    );

    await logAudit(req.user.id, 'UPDATE', 'alumnos', id, oldData.rows[0], result.rows[0], req.ip);

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Eliminar alumno
router.delete('/:id', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const { id } = req.params;

    const oldData = await pool.query('SELECT * FROM alumnos WHERE id = $1', [id]);

    if (oldData.rows.length === 0) {
      return res.status(404).json({ error: 'Alumno no encontrado' });
    }

    await pool.query('DELETE FROM alumnos WHERE id = $1', [id]);

    await logAudit(req.user.id, 'DELETE', 'alumnos', id, oldData.rows[0], null, req.ip);

    res.json({ message: 'Alumno eliminado exitosamente' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Historial académico del alumno
router.get('/:id/historial', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        i.id, i.fecha_inscripcion, i.estatus,
        g.codigo as grupo_codigo, g.nivel,
        p.nombre as periodo,
        m.nombre_completo as maestro,
        (SELECT AVG(c.calificacion) FROM calificaciones c WHERE c.inscripcion_id = i.id) as promedio
      FROM inscripciones i
      JOIN grupos g ON i.grupo_id = g.id
      JOIN periodos p ON i.periodo_id = p.id
      LEFT JOIN maestros m ON g.maestro_id = m.id
      WHERE i.alumno_id = $1
      ORDER BY i.fecha_inscripcion DESC`,
      [req.params.id]
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Importar alumnos desde Excel (carga masiva)
router.post('/import', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const { alumnos } = req.body; // Array de objetos con datos de alumnos

    const client = await pool.connect();
    await client.query('BEGIN');

    const resultados = {
      exitosos: 0,
      errores: []
    };

    for (const alumno of alumnos) {
      try {
        await client.query(
          `INSERT INTO alumnos 
           (tipo_alumno, matricula, nombre_completo, correo, telefono, carrera, semestre, nivel_actual) 
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
          [
            alumno.tipo_alumno,
            alumno.matricula,
            alumno.nombre_completo,
            alumno.correo,
            alumno.telefono,
            alumno.carrera,
            alumno.semestre,
            alumno.nivel_actual
          ]
        );
        resultados.exitosos++;
      } catch (error) {
        resultados.errores.push({
          alumno: alumno.nombre_completo,
          error: error.message
        });
      }
    }

    await client.query('COMMIT');
    client.release();

    res.json(resultados);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
