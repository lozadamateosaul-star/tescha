import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pool from '../config/database.js';
import { auth } from '../middleware/auth.js';
import { validate, loginSchema, changePasswordSchema } from '../middleware/validation.js';
import { trackLoginAttempts, recordFailedLogin, clearLoginAttempts } from '../middleware/security.js';

const router = express.Router();

// 🔒 SEGURIDAD: Delay constante para prevenir timing attacks (300ms mínimo)
const constantTimeDelay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
const MIN_RESPONSE_TIME = 300; // 300ms para todos los casos

// Login con validación y protección contra fuerza bruta
router.post('/login', validate(loginSchema), trackLoginAttempts, async (req, res) => {
  const startTime = Date.now();

  try {
    const { username, password } = req.body;

    console.log('🔍 Login attempt:', { username, passwordLength: password?.length });

    const result = await pool.query(
      'SELECT * FROM usuarios WHERE username = $1 AND activo = true',
      [username]
    );

    console.log('📊 Users found:', result.rows.length);

    if (result.rows.length === 0) {
      console.log('❌ User not found:', username);
      // Registrar intento fallido
      await recordFailedLogin(username, req.ip);
      // Delay constante antes de responder
      const elapsed = Date.now() - startTime;
      if (elapsed < MIN_RESPONSE_TIME) await constantTimeDelay(MIN_RESPONSE_TIME - elapsed);
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const usuario = result.rows[0];
    console.log('👤 User from DB:', {
      id: usuario.id,
      username: usuario.username,
      rol: usuario.rol,
      hasPassword: !!usuario.password,
      passwordLength: usuario.password?.length
    });

    const isValidPassword = await bcrypt.compare(password, usuario.password);
    console.log('🔐 Password comparison result:', isValidPassword);

    if (!isValidPassword) {
      console.log('❌ Invalid password for user:', username);
      // Registrar intento fallido
      await recordFailedLogin(username, req.ip);
      // Delay constante antes de responder
      const elapsed = Date.now() - startTime;
      if (elapsed < MIN_RESPONSE_TIME) await constantTimeDelay(MIN_RESPONSE_TIME - elapsed);
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    // Login exitoso - limpiar intentos fallidos
    await clearLoginAttempts(username, req.ip);

    // Si es maestro, obtener maestro_id
    let maestroId = null;
    if (usuario.rol === 'maestro') {
      const maestroResult = await pool.query(
        'SELECT id FROM maestros WHERE usuario_id = $1',
        [usuario.id]
      );
      if (maestroResult.rows.length > 0) {
        maestroId = maestroResult.rows[0].id;
      }
    }

    const token = jwt.sign(
      {
        id: usuario.id,
        username: usuario.username,
        rol: usuario.rol,
        maestro_id: maestroId
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    // Delay constante antes de responder (timing attack prevention)
    const elapsed = Date.now() - startTime;
    if (elapsed < MIN_RESPONSE_TIME) await constantTimeDelay(MIN_RESPONSE_TIME - elapsed);

    res.json({
      token,
      usuario: {
        id: usuario.id,
        username: usuario.username,
        rol: usuario.rol,
        maestro_id: maestroId
      },
      cambio_password_requerido: usuario.cambio_password_requerido || false
    });
  } catch (error) {
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Registro de usuario
router.post('/register', auth, async (req, res) => {
  try {
    const { username, password, rol } = req.body;

    // Solo coordinadores pueden crear usuarios
    if (req.user.rol !== 'coordinador') {
      return res.status(403).json({ error: 'No autorizado' });
    }

    // 🔒 VALIDACIÓN DE SEGURIDAD: Username
    if (!username || typeof username !== 'string') {
      return res.status(400).json({ error: 'Username es requerido' });
    }

    // Solo alfanuméricos, guiones, guiones bajos y puntos (3-30 caracteres)
    if (!/^[a-zA-Z0-9._-]{3,30}$/.test(username)) {
      return res.status(400).json({
        error: 'Username inválido. Solo letras, números, puntos, guiones y guiones bajos (3-30 caracteres)'
      });
    }

    // Prevenir usernames reservados o peligrosos
    const reservedUsernames = ['admin', 'root', 'system', 'administrator', 'superuser', 'sa', 'postgres'];
    if (reservedUsernames.includes(username.toLowerCase())) {
      return res.status(400).json({ error: 'Username no permitido' });
    }

    // 🔒 VALIDACIÓN DE SEGURIDAD: Password
    if (!password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ error: 'Password debe tener al menos 6 caracteres' });
    }

    // 🔒 VALIDACIÓN DE SEGURIDAD: Rol
    const rolesPermitidos = ['coordinador', 'maestro', 'administrativo', 'alumno'];
    if (!rol || !rolesPermitidos.includes(rol)) {
      return res.status(400).json({ error: 'Rol inválido' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO usuarios (username, password, rol) VALUES ($1, $2, $3) RETURNING id, username, rol',
      [username, hashedPassword, rol]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    if (error.code === '23505') {
      return res.status(400).json({ error: 'El usuario ya existe' });
    }
    res.status(500).json({ error: error.message });
  }
});

// Obtener perfil del usuario autenticado
router.get('/me', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, rol, activo FROM usuarios WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Cambiar contraseña
router.put('/change-password', auth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 8 caracteres' });
    }

    const result = await pool.query(
      'SELECT password FROM usuarios WHERE id = $1',
      [req.user.id]
    );

    const isValid = await bcrypt.compare(oldPassword, result.rows[0].password);
    if (!isValid) {
      return res.status(400).json({ error: 'Contraseña actual incorrecta' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query(
      'UPDATE usuarios SET password = $1, cambio_password_requerido = false WHERE id = $2',
      [hashedPassword, req.user.id]
    );

    res.json({ message: 'Contraseña actualizada exitosamente' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
