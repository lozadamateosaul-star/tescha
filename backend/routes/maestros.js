import express from 'express';
import pool from '../config/database.js';
import { auth, checkRole } from '../middleware/auth.js';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

const router = express.Router();

// Función para generar contraseña segura
const generarPasswordSegura = () => {
  const mayusculas = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const minusculas = 'abcdefghijklmnopqrstuvwxyz';
  const numeros = '0123456789';
  const especiales = '!@#$%&*';
  
  let password = '';
  
  // Asegurar al menos un carácter de cada tipo
  password += mayusculas[crypto.randomInt(mayusculas.length)];
  password += minusculas[crypto.randomInt(minusculas.length)];
  password += numeros[crypto.randomInt(numeros.length)];
  password += especiales[crypto.randomInt(especiales.length)];
  
  // Completar hasta 12 caracteres con caracteres aleatorios
  const todosCaracteres = mayusculas + minusculas + numeros + especiales;
  for (let i = 4; i < 12; i++) {
    password += todosCaracteres[crypto.randomInt(todosCaracteres.length)];
  }
  
  // Mezclar los caracteres
  return password.split('').sort(() => crypto.randomInt(-1, 2)).join('');
};

// Obtener todos los maestros (activos e inactivos)
router.get('/', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT m.*,
       CONCAT(m.nombre, ' ', m.apellido_paterno, ' ', COALESCE(m.apellido_materno, '')) as nombre_completo,
       array_agg(DISTINCT mn.nivel) FILTER (WHERE mn.nivel IS NOT NULL) as niveles
       FROM maestros m
       LEFT JOIN maestros_niveles mn ON m.id = mn.maestro_id
       GROUP BY m.id, m.nombre, m.apellido_paterno, m.apellido_materno
       ORDER BY m.activo DESC, m.nombre, m.apellido_paterno`
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Obtener maestro por ID con sus grupos
router.get('/:id', auth, async (req, res) => {
  try {
    const maestroResult = await pool.query('SELECT * FROM maestros WHERE id = $1', [req.params.id]);
    
    if (maestroResult.rows.length === 0) {
      return res.status(404).json({ error: 'Maestro no encontrado' });
    }
    
    const nivelesResult = await pool.query(
      'SELECT nivel FROM maestros_niveles WHERE maestro_id = $1',
      [req.params.id]
    );
    
    const gruposResult = await pool.query(
      `SELECT g.*, p.nombre as periodo_nombre, s.codigo as salon_codigo
       FROM grupos g
       LEFT JOIN periodos p ON g.periodo_id = p.id
       LEFT JOIN salones s ON g.salon_id = s.id
       WHERE g.maestro_id = $1 AND g.activo = true`,
      [req.params.id]
    );
    
    res.json({
      ...maestroResult.rows[0],
      niveles: nivelesResult.rows.map(r => r.nivel),
      grupos: gruposResult.rows
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Crear maestro
router.post('/', auth, checkRole('coordinador'), async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const { nombre, apellido_paterno, apellido_materno, rfc, correo, telefono, niveles } = req.body;
    
    // Insertar maestro
    const result = await client.query(
      'INSERT INTO maestros (nombre, apellido_paterno, apellido_materno, rfc, correo, telefono) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [nombre, apellido_paterno, apellido_materno || null, rfc, correo, telefono]
    );
    
    const maestroId = result.rows[0].id;
    
    // Crear usuario automáticamente
    // Username: primer nombre + apellido_paterno (lowercase, sin espacios, sin acentos)
    const primerNombre = nombre.trim().split(' ')[0].toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/\s+/g, '');
    const apellidoLimpio = apellido_paterno.trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/\s+/g, '');
    const username = `${primerNombre}.${apellidoLimpio}`;
    
    // Generar contraseña temporal segura
    const passwordTemporal = generarPasswordSegura();
    const hashedPassword = await bcrypt.hash(passwordTemporal, 10);
    
    // Verificar si el usuario ya existe
    const userCheck = await client.query('SELECT id FROM usuarios WHERE username = $1', [username]);
    
    let usuarioId;
    if (userCheck.rows.length === 0) {
      const userResult = await client.query(
        'INSERT INTO usuarios (username, password, rol, activo, cambio_password_requerido) VALUES ($1, $2, $3, true, true) RETURNING id',
        [username, hashedPassword, 'maestro']
      );
      usuarioId = userResult.rows[0].id;
    } else {
      // Actualizar contraseña si el usuario ya existe
      await client.query(
        'UPDATE usuarios SET password = $1, cambio_password_requerido = true WHERE id = $2',
        [hashedPassword, userCheck.rows[0].id]
      );
      usuarioId = userCheck.rows[0].id;
    }
    
    // Actualizar maestro con usuario_id
    await client.query('UPDATE maestros SET usuario_id = $1 WHERE id = $2', [usuarioId, maestroId]);
    
    // Insertar niveles
    if (niveles && niveles.length > 0) {
      for (const nivel of niveles) {
        await client.query(
          'INSERT INTO maestros_niveles (maestro_id, nivel) VALUES ($1, $2)',
          [maestroId, nivel]
        );
      }
    }
    
    await client.query('COMMIT');
    
    res.status(201).json({
      ...result.rows[0],
      usuario_creado: {
        username,
        password_temporal: passwordTemporal,
        mensaje: 'Usuario creado. El maestro debe cambiar su contraseña en el primer acceso.'
      }
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error al crear maestro:', error);
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// Actualizar maestro
router.put('/:id', auth, checkRole('coordinador'), async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const { id } = req.params;
    const { niveles, ...allFields } = req.body;
    
    // WHITELIST de campos permitidos (SEGURIDAD SQL)
    const CAMPOS_PERMITIDOS = [
      'nombre', 'apellido_paterno', 'apellido_materno', 'rfc',
      'correo', 'telefono', 'activo'
    ];
    
    const fields = {};
    Object.keys(allFields).forEach(key => {
      if (CAMPOS_PERMITIDOS.includes(key)) {
        fields[key] = allFields[key];
      }
    });
    
    if (Object.keys(fields).length === 0 && !niveles) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'No se proporcionaron campos válidos para actualizar' });
    }
    
    let result;
    if (Object.keys(fields).length > 0) {
      const keys = Object.keys(fields);
      const values = Object.values(fields);
      const setClause = keys.map((key, idx) => `${key} = $${idx + 1}`).join(', ');
      
      result = await client.query(
        `UPDATE maestros SET ${setClause} WHERE id = $${keys.length + 1} RETURNING *`,
        [...values, id]
      );
    } else {
      result = await client.query('SELECT * FROM maestros WHERE id = $1', [id]);
    }
    
    if (niveles) {
      await client.query('DELETE FROM maestros_niveles WHERE maestro_id = $1', [id]);
      for (const nivel of niveles) {
        await client.query(
          'INSERT INTO maestros_niveles (maestro_id, nivel) VALUES ($1, $2)',
          [id, nivel]
        );
      }
    }
    
    await client.query('COMMIT');
    res.json(result.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// Desactivar/Activar maestro
router.patch('/:id/toggle-status', auth, checkRole('coordinador'), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { id } = req.params;
    
    // Obtener estado actual y usuario_id
    const maestroResult = await client.query(
      'SELECT activo, usuario_id FROM maestros WHERE id = $1',
      [id]
    );
    
    if (maestroResult.rows.length === 0) {
      return res.status(404).json({ error: 'Maestro no encontrado' });
    }
    
    const { activo, usuario_id } = maestroResult.rows[0];
    const nuevoEstado = !activo;
    
    // Actualizar maestro
    await client.query(
      'UPDATE maestros SET activo = $1 WHERE id = $2',
      [nuevoEstado, id]
    );
    
    // Actualizar usuario asociado
    if (usuario_id) {
      await client.query(
        'UPDATE usuarios SET activo = $1 WHERE id = $2',
        [nuevoEstado, usuario_id]
      );
    }
    
    await client.query('COMMIT');
    res.json({ 
      message: `Maestro ${nuevoEstado ? 'activado' : 'desactivado'} correctamente`,
      activo: nuevoEstado
    });
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// Restablecer contraseña del maestro
router.post('/:id/reset-password', auth, checkRole('coordinador'), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { id } = req.params;
    
    // Obtener información del maestro
    const maestroResult = await client.query(
      'SELECT apellido_paterno, usuario_id FROM maestros WHERE id = $1',
      [id]
    );
    
    if (maestroResult.rows.length === 0) {
      return res.status(404).json({ error: 'Maestro no encontrado' });
    }
    
    const { apellido_paterno, usuario_id } = maestroResult.rows[0];
    
    if (!usuario_id) {
      return res.status(400).json({ error: 'Este maestro no tiene usuario asociado' });
    }
    
    // Generar nueva contraseña temporal segura
    const nuevaPassword = generarPasswordSegura();
    const hashedPassword = await bcrypt.hash(nuevaPassword, 10);
    
    // Actualizar contraseña y marcar como cambio requerido
    await client.query(
      'UPDATE usuarios SET password = $1, cambio_password_requerido = true WHERE id = $2',
      [hashedPassword, usuario_id]
    );
    
    await client.query('COMMIT');
    res.json({ 
      message: 'Contraseña restablecida correctamente',
      nueva_password: nuevaPassword
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error al restablecer contraseña:', error);
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// Eliminar maestro
router.delete('/:id', auth, checkRole('coordinador'), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { id } = req.params;
    
    // Verificar si el maestro tiene grupos asignados
    const gruposResult = await client.query(
      'SELECT COUNT(*) as total FROM grupos WHERE maestro_id = $1',
      [id]
    );
    
    if (parseInt(gruposResult.rows[0].total) > 0) {
      return res.status(400).json({ 
        error: 'No se puede eliminar el maestro porque tiene grupos asignados. Primero debes reasignar o eliminar los grupos.' 
      });
    }
    
    // Obtener usuario_id antes de eliminar
    const maestroResult = await client.query(
      'SELECT usuario_id FROM maestros WHERE id = $1',
      [id]
    );
    
    if (maestroResult.rows.length === 0) {
      return res.status(404).json({ error: 'Maestro no encontrado' });
    }
    
    const { usuario_id } = maestroResult.rows[0];
    
    // Eliminar niveles del maestro
    await client.query('DELETE FROM maestros_niveles WHERE maestro_id = $1', [id]);
    
    // Eliminar maestro
    await client.query('DELETE FROM maestros WHERE id = $1', [id]);
    
    // Eliminar usuario asociado
    if (usuario_id) {
      await client.query('DELETE FROM usuarios WHERE id = $1', [usuario_id]);
    }
    
    await client.query('COMMIT');
    res.json({ message: 'Maestro eliminado correctamente' });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error al eliminar maestro:', error);
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// Horarios del maestro
router.get('/:id/horarios', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        g.codigo as grupo,
        g.nivel,
        gh.dia,
        gh.hora_inicio,
        gh.hora_fin,
        s.codigo as salon
      FROM grupos g
      JOIN grupos_horarios gh ON g.id = gh.grupo_id
      LEFT JOIN salones s ON g.salon_id = s.id
      WHERE g.maestro_id = $1 AND g.activo = true
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
    
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
