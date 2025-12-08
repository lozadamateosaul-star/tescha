import express from 'express';
import pool from '../config/database.js';
import { auth, checkRole } from '../middleware/auth.js';

const router = express.Router();

// Obtener todos los libros
router.get('/', auth, async (req, res) => {
  try {
    const { nivel } = req.query;
    
    let query = 'SELECT * FROM libros WHERE 1=1';
    const params = [];
    
    if (nivel) {
      query += ' AND nivel = $1';
      params.push(nivel);
    }
    
    query += ' ORDER BY nivel, titulo';
    
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Crear libro
router.post('/', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const { titulo, nivel, precio, stock, editorial, isbn } = req.body;
    
    const result = await pool.query(
      'INSERT INTO libros (titulo, nivel, precio, stock, editorial, isbn) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [titulo, nivel, precio, stock, editorial, isbn]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Actualizar libro
router.put('/:id', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const { id } = req.params;
    
    // WHITELIST de campos permitidos (SEGURIDAD SQL)
    const CAMPOS_PERMITIDOS = ['titulo', 'nivel', 'precio', 'stock', 'editorial', 'isbn', 'descripcion'];
    
    const fields = {};
    Object.keys(req.body).forEach(key => {
      if (CAMPOS_PERMITIDOS.includes(key)) {
        fields[key] = req.body[key];
      }
    });
    
    if (Object.keys(fields).length === 0) {
      return res.status(400).json({ error: 'No se proporcionaron campos válidos para actualizar' });
    }
    
    const keys = Object.keys(fields);
    const values = Object.values(fields);
    const setClause = keys.map((key, idx) => `${key} = $${idx + 1}`).join(', ');
    
    const result = await pool.query(
      `UPDATE libros SET ${setClause} WHERE id = $${keys.length + 1} RETURNING *`,
      [...values, id]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Eliminar libro
router.delete('/:id', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const { id } = req.params;
    
    // Verificar si tiene ventas registradas
    const ventasResult = await pool.query(
      'SELECT COUNT(*) as total FROM ventas_libros WHERE libro_id = $1',
      [id]
    );
    
    if (parseInt(ventasResult.rows[0].total) > 0) {
      return res.status(400).json({ 
        error: 'No se puede eliminar el libro porque tiene ventas registradas' 
      });
    }
    
    await pool.query('DELETE FROM libros WHERE id = $1', [id]);
    res.json({ message: 'Libro eliminado correctamente' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Registrar venta de libro
router.post('/ventas', auth, checkRole('coordinador', 'administrativo'), async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const { alumno_id, libro_id, cantidad, precio_venta } = req.body;
    
    // Verificar stock
    const libroResult = await client.query('SELECT stock FROM libros WHERE id = $1', [libro_id]);
    
    if (libroResult.rows[0].stock < cantidad) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Stock insuficiente' });
    }
    
    // Registrar venta
    const ventaResult = await client.query(
      'INSERT INTO ventas_libros (alumno_id, libro_id, cantidad, precio_venta) VALUES ($1, $2, $3, $4) RETURNING *',
      [alumno_id, libro_id, cantidad, precio_venta]
    );
    
    // Actualizar stock
    await client.query(
      'UPDATE libros SET stock = stock - $1 WHERE id = $2',
      [cantidad, libro_id]
    );
    
    await client.query('COMMIT');
    res.status(201).json(ventaResult.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// Historial de ventas
router.get('/ventas', auth, async (req, res) => {
  try {
    const { alumno_id, fecha_inicio, fecha_fin } = req.query;
    
    let query = `
      SELECT 
        v.*,
        a.nombre_completo as alumno_nombre,
        a.matricula,
        l.titulo as libro_titulo,
        l.nivel as libro_nivel
      FROM ventas_libros v
      JOIN alumnos a ON v.alumno_id = a.id
      JOIN libros l ON v.libro_id = l.id
      WHERE 1=1
    `;
    
    const params = [];
    let paramCount = 1;
    
    if (alumno_id) {
      query += ` AND v.alumno_id = $${paramCount++}`;
      params.push(alumno_id);
    }
    
    if (fecha_inicio) {
      query += ` AND v.fecha_venta >= $${paramCount++}`;
      params.push(fecha_inicio);
    }
    
    if (fecha_fin) {
      query += ` AND v.fecha_venta <= $${paramCount++}`;
      params.push(fecha_fin);
    }
    
    query += ' ORDER BY v.fecha_venta DESC';
    
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Reporte de ventas por período
router.get('/reportes/ventas', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const { fecha_inicio, fecha_fin } = req.query;
    
    let query = `
      SELECT 
        l.titulo,
        l.nivel,
        COUNT(v.id) as cantidad_vendida,
        SUM(v.precio_venta * v.cantidad) as ingresos_total
      FROM ventas_libros v
      JOIN libros l ON v.libro_id = l.id
      WHERE 1=1
    `;
    
    const params = [];
    let paramCount = 1;
    
    if (fecha_inicio) {
      query += ` AND v.fecha_venta >= $${paramCount++}`;
      params.push(fecha_inicio);
    }
    
    if (fecha_fin) {
      query += ` AND v.fecha_venta <= $${paramCount++}`;
      params.push(fecha_fin);
    }
    
    query += ' GROUP BY l.id, l.titulo, l.nivel ORDER BY ingresos_total DESC';
    
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
