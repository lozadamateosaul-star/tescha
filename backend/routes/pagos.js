import express from 'express';
import pool from '../config/database.js';
import { auth, checkRole } from '../middleware/auth.js';

const router = express.Router();

// =============================================
// OBTENER PAGOS CON FILTROS - OPTIMIZADO
// =============================================
// ⚡ Usa vista materializada mv_pagos_completos para consultas ultra rápidas

router.get('/', auth, async (req, res) => {
    try {
        const { estatus, periodo_id, alumno_id, limit = 500, offset = 0, todos } = req.query;

        // ⚡ OPTIMIZACIÓN: Usar vista materializada en lugar de JOINs
        let query = `
      SELECT 
        id,
        inscripcion_id,
        monto,
        concepto,
        fecha_pago,
        estatus,
        metodo_pago,
        referencia,
        notas,
        tiene_prorroga,
        fecha_limite_prorroga,
        created_at,
        updated_at,
        alumno_id,
        alumno_nombre,
        alumno_matricula as matricula,
        periodo_id,
        periodo_nombre,
        dias_atraso,
        dias_restantes_prorroga,
        estado_prorroga
      FROM mv_pagos_completos
      WHERE 1=1
    `;

        const params = [];
        let paramCount = 1;

        // Filtro de periodo
        if (!todos) {
            if (periodo_id) {
                query += ` AND periodo_id = $${paramCount++}`;
                params.push(periodo_id);
            } else {
                query += ` AND periodo_activo = true`;
            }
        }

        if (estatus) {
            query += ` AND estatus = $${paramCount++}`;
            params.push(estatus);
        }

        if (alumno_id) {
            query += ` AND alumno_id = $${paramCount++}`;
            params.push(alumno_id);
        }

        // Filtro por prórroga
        if (req.query.tiene_prorroga === 'true') {
            query += ` AND tiene_prorroga = true`;
        }

        // Filtro de búsqueda múltiple
        if (req.query.search) {
            console.log('🔍 Búsqueda múltiple:', req.query.search);
            const searchTerms = req.query.search.split('|');
            const searchConditions = [];

            searchTerms.forEach(term => {
                const trimmedTerm = term.trim();
                if (trimmedTerm) {
                    params.push(`%${trimmedTerm}%`);
                    searchConditions.push(`alumno_nombre ILIKE $${paramCount++}`);
                }
            });

            if (searchConditions.length > 0) {
                query += ` AND (${searchConditions.join(' OR ')})`;
            }
            console.log('📝 Query:', query);
            console.log('📊 Params:', params);
        }

        query += ' ORDER BY created_at DESC';

        // Paginación
        query += ` LIMIT $${paramCount++} OFFSET $${paramCount++}`;
        params.push(parseInt(limit), parseInt(offset));

        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (error) {
        console.error('Error al obtener pagos:', error);
        res.status(500).json({ error: error.message });
    }
});

// =============================================
// REGISTRAR PAGO - ACTUALIZADO
// =============================================
// Ahora solo usa inscripcion_id (normalizado)

router.post('/', auth, checkRole('coordinador', 'administrativo'), async (req, res) => {
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        let {
            inscripcion_id,  // ⚡ CAMBIO: Ahora usamos inscripcion_id en lugar de alumno_id
            alumno_id,       // Mantener por compatibilidad temporal
            monto,
            concepto,
            metodo_pago,
            referencia,
            notas,
            tiene_prorroga,
            fecha_limite_prorroga
        } = req.body;

        // Si no viene inscripcion_id pero sí alumno_id, buscar la inscripción activa
        if (!inscripcion_id && alumno_id) {
            const inscripcionResult = await client.query(
                `SELECT i.id 
         FROM inscripciones i
         JOIN periodos p ON i.periodo_id = p.id
         WHERE i.alumno_id = $1 AND p.activo = true AND i.estatus = 'activo'
         LIMIT 1`,
                [alumno_id]
            );

            if (inscripcionResult.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(400).json({
                    error: 'No se encontró una inscripción activa para este alumno'
                });
            }

            inscripcion_id = inscripcionResult.rows[0].id;
        }

        // Validar que existe la inscripción
        if (!inscripcion_id) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                error: 'Se requiere inscripcion_id o alumno_id'
            });
        }

        // LÓGICA CONTABLE
        let estatus = tiene_prorroga && fecha_limite_prorroga ? 'pendiente' : 'completado';

        // Validación: pagos completados deben tener referencia
        if (estatus === 'completado' && !referencia) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                error: 'La referencia (línea de captura) es obligatoria para pagos completados'
            });
        }

        const fechaProrroga = tiene_prorroga && fecha_limite_prorroga ? fecha_limite_prorroga : null;

        // ⚡ CAMBIO: Ahora solo insertamos inscripcion_id (normalizado)
        const result = await client.query(
            `INSERT INTO pagos 
       (inscripcion_id, monto, fecha_pago, estatus, metodo_pago, referencia, concepto, notas, tiene_prorroga, fecha_limite_prorroga)
       VALUES ($1, $2, CURRENT_DATE, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
            [inscripcion_id, monto, estatus, metodo_pago, referencia, concepto, notas, tiene_prorroga || false, fechaProrroga]
        );

        await client.query('COMMIT');

        // ⚡ Refrescar vista materializada de pagos
        await pool.query('SELECT refresh_pagos_view()');

        res.status(201).json(result.rows[0]);
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error al crear pago:', error);
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

// =============================================
// ACTUALIZAR PAGO - ACTUALIZADO
// =============================================

router.put('/:id', auth, checkRole('coordinador', 'administrativo'), async (req, res) => {
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        const { id } = req.params;
        let { monto, metodo_pago, concepto, referencia, notas, tiene_prorroga, fecha_limite_prorroga, estatus } = req.body;

        // LÓGICA CONTABLE
        if (tiene_prorroga && fecha_limite_prorroga) {
            estatus = 'pendiente';
        }

        if (estatus === 'completado' && !referencia) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                error: 'La referencia (línea de captura) es obligatoria para pagos completados'
            });
        }

        if (estatus === 'completado' || estatus === 'cancelado') {
            tiene_prorroga = false;
            fecha_limite_prorroga = null;
        }

        const fechaProrroga = tiene_prorroga && fecha_limite_prorroga ? fecha_limite_prorroga : null;

        // ⚡ CAMBIO: Ya no actualizamos alumno_id ni periodo_id (no existen)
        const result = await client.query(
            `UPDATE pagos SET 
        monto = $1, 
        metodo_pago = $2, 
        concepto = $3, 
        referencia = $4, 
        notas = $5,
        tiene_prorroga = $6,
        fecha_limite_prorroga = $7,
        estatus = $8
       WHERE id = $9 RETURNING *`,
            [monto, metodo_pago, concepto, referencia, notas, tiene_prorroga, fechaProrroga, estatus, id]
        );

        await client.query('COMMIT');

        // ⚡ Refrescar vista materializada
        await pool.query('SELECT refresh_pagos_view()');

        res.json(result.rows[0]);
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error al actualizar pago:', error);
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

// =============================================
// ACTUALIZAR ESTATUS DE PAGO
// =============================================

router.put('/:id/estatus', auth, checkRole('coordinador', 'administrativo'), async (req, res) => {
    try {
        const { id } = req.params;
        const { estatus } = req.body;

        const result = await pool.query(
            'UPDATE pagos SET estatus = $1 WHERE id = $2 RETURNING *',
            [estatus, id]
        );

        // ⚡ Refrescar vista materializada
        await pool.query('SELECT refresh_pagos_view()');

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error al actualizar estatus:', error);
        res.status(500).json({ error: error.message });
    }
});

// =============================================
// REPORTES OPTIMIZADOS
// =============================================

// Reporte de alumnos con adeudo - OPTIMIZADO
router.get('/reportes/adeudos', auth, checkRole('coordinador', 'administrativo'), async (req, res) => {
    try {
        const { periodo_id } = req.query;

        // ⚡ Usar vista materializada
        let query = `
      SELECT 
        alumno_id as id,
        alumno_nombre as nombre_completo,
        alumno_matricula as matricula,
        alumno_correo as correo,
        alumno_telefono as telefono,
        monto,
        estatus,
        periodo_nombre as periodo,
        dias_atraso
      FROM mv_pagos_completos
      WHERE estatus IN ('pendiente', 'adeudo')
    `;

        const params = [];
        if (periodo_id) {
            query += ' AND periodo_id = $1';
            params.push(periodo_id);
        } else {
            query += ' AND periodo_activo = true';
        }

        query += ' ORDER BY alumno_nombre';

        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (error) {
        console.error('Error en reporte de adeudos:', error);
        res.status(500).json({ error: error.message });
    }
});

// Reporte financiero de ingresos - OPTIMIZADO
router.get('/reportes/ingresos', auth, checkRole('coordinador'), async (req, res) => {
    try {
        const { periodo_id } = req.query;

        // ⚡ Usar vista materializada
        let query = `
      SELECT 
        COUNT(*) FILTER (WHERE estatus = 'completado') as total_pagados,
        COUNT(*) FILTER (WHERE estatus = 'pendiente') as total_pendientes,
        COUNT(*) FILTER (WHERE estatus = 'prorroga') as total_prorrogas,
        COUNT(*) FILTER (WHERE estatus = 'adeudo') as total_adeudos,
        SUM(monto) FILTER (WHERE estatus = 'completado') as monto_cobrado,
        SUM(monto) FILTER (WHERE estatus != 'completado') as monto_por_cobrar,
        SUM(monto) as monto_total
      FROM mv_pagos_completos
      WHERE 1=1
    `;

        const params = [];
        if (periodo_id) {
            query += ' AND periodo_id = $1';
            params.push(periodo_id);
        } else {
            query += ' AND periodo_activo = true';
        }

        const result = await pool.query(query, params);
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error en reporte de ingresos:', error);
        res.status(500).json({ error: error.message });
    }
});

// Reporte de prórrogas activas - OPTIMIZADO
router.get('/reportes/prorrogas-activas', auth, checkRole('coordinador', 'administrativo'), async (req, res) => {
    try {
        // ⚡ Usar vista materializada con cálculos pre-hechos
        const result = await pool.query(
            `SELECT 
        id,
        alumno_nombre as nombre_completo,
        alumno_matricula as matricula,
        alumno_correo as correo,
        alumno_telefono as telefono,
        monto,
        concepto,
        fecha_limite_prorroga,
        estado_prorroga,
        dias_restantes_prorroga as dias_restantes
      FROM mv_pagos_completos
      WHERE tiene_prorroga = true 
        AND estatus = 'pendiente'
        AND periodo_activo = true
      ORDER BY fecha_limite_prorroga ASC`
        );

        res.json(result.rows);
    } catch (error) {
        console.error('Error en reporte de prórrogas:', error);
        res.status(500).json({ error: error.message });
    }
});

// Reporte de adeudos críticos - OPTIMIZADO
router.get('/reportes/adeudos-criticos', auth, checkRole('coordinador', 'administrativo'), async (req, res) => {
    try {
        // ⚡ Usar vista materializada
        const result = await pool.query(
            `SELECT 
        alumno_id as id,
        alumno_nombre as nombre_completo,
        alumno_matricula as matricula,
        alumno_correo as correo,
        alumno_telefono as telefono,
        tipo_alumno,
        COUNT(*) as total_adeudos,
        SUM(monto) as monto_total,
        MIN(fecha_pago) as primer_adeudo,
        MAX(fecha_limite_prorroga) as ultima_prorroga
      FROM mv_pagos_completos
      WHERE estatus IN ('pendiente', 'adeudo')
        AND periodo_activo = true
      GROUP BY alumno_id, alumno_nombre, alumno_matricula, alumno_correo, alumno_telefono, tipo_alumno
      HAVING COUNT(*) > 0
      ORDER BY SUM(monto) DESC`
        );

        res.json(result.rows);
    } catch (error) {
        console.error('Error en reporte de adeudos críticos:', error);
        res.status(500).json({ error: error.message });
    }
});

// Endpoint para reportes históricos completos - OPTIMIZADO
router.get('/historico', auth, checkRole('coordinador', 'administrativo'), async (req, res) => {
    try {
        const { desde, hasta, estatus, tipo_alumno } = req.query;

        // ⚡ Usar vista materializada
        let query = `
      SELECT 
        id,
        monto,
        fecha_pago,
        estatus,
        concepto,
        metodo_pago,
        referencia,
        alumno_nombre,
        alumno_matricula as matricula,
        tipo_alumno,
        periodo_nombre,
        EXTRACT(YEAR FROM fecha_pago) as anio,
        TO_CHAR(fecha_pago, 'YYYY-MM') as periodo_mes
      FROM mv_pagos_completos
      WHERE 1=1
    `;

        const params = [];
        let paramCount = 1;

        if (desde) {
            query += ` AND fecha_pago >= $${paramCount++}`;
            params.push(desde);
        }

        if (hasta) {
            query += ` AND fecha_pago <= $${paramCount++}`;
            params.push(hasta);
        }

        if (estatus) {
            query += ` AND estatus = $${paramCount++}`;
            params.push(estatus);
        }

        if (tipo_alumno) {
            query += ` AND tipo_alumno = $${paramCount++}`;
            params.push(tipo_alumno);
        }

        query += ' ORDER BY fecha_pago DESC LIMIT 10000';

        const result = await pool.query(query, params);

        // Calcular resumen
        const resumen = {
            total_registros: result.rows.length,
            total_ingresos: result.rows
                .filter(r => r.estatus === 'completado')
                .reduce((sum, r) => sum + parseFloat(r.monto), 0),
            total_pendiente: result.rows
                .filter(r => r.estatus === 'pendiente')
                .reduce((sum, r) => sum + parseFloat(r.monto), 0)
        };

        res.json({
            resumen,
            datos: result.rows
        });
    } catch (error) {
        console.error('Error en reporte histórico:', error);
        res.status(500).json({ error: error.message });
    }
});

// =============================================
// SOLICITAR PRÓRROGA
// =============================================

router.post('/prorrogas', auth, async (req, res) => {
    try {
        const { pago_id, alumno_id, motivo, fecha_limite } = req.body;

        const result = await pool.query(
            `INSERT INTO prorrogas (pago_id, alumno_id, motivo, fecha_solicitada, fecha_limite)
       VALUES ($1, $2, $3, CURRENT_DATE, $4) RETURNING *`,
            [pago_id, alumno_id, motivo, fecha_limite]
        );

        // Actualizar estatus del pago a prórroga
        await pool.query(
            'UPDATE pagos SET estatus = $1 WHERE id = $2',
            ['prorroga', pago_id]
        );

        // ⚡ Refrescar vista materializada
        await pool.query('SELECT refresh_pagos_view()');

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Error al solicitar prórroga:', error);
        res.status(500).json({ error: error.message });
    }
});

// =============================================
// APROBAR/RECHAZAR PRÓRROGA
// =============================================

router.put('/prorrogas/:id', auth, checkRole('coordinador', 'administrativo'), async (req, res) => {
    try {
        const { id } = req.params;
        const { estatus, observaciones } = req.body;

        const result = await pool.query(
            `UPDATE prorrogas 
       SET estatus = $1, observaciones = $2, aprobada_por = $3, fecha_aprobacion = CURRENT_TIMESTAMP
       WHERE id = $4 RETURNING *`,
            [estatus, observaciones, req.user.id, id]
        );

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error al aprobar/rechazar prórroga:', error);
        res.status(500).json({ error: error.message });
    }
});

// =============================================
// LISTAR PRÓRROGAS
// =============================================

router.get('/prorrogas', auth, async (req, res) => {
    try {
        const { estatus } = req.query;

        let query = `
      SELECT 
        pr.*,
        a.nombre_completo as alumno_nombre,
        a.matricula,
        p.monto,
        u.username as aprobada_por_username
      FROM prorrogas pr
      JOIN alumnos a ON pr.alumno_id = a.id
      LEFT JOIN pagos p ON pr.pago_id = p.id
      LEFT JOIN usuarios u ON pr.aprobada_por = u.id
      WHERE 1=1
    `;

        if (estatus) {
            query += ` AND pr.estatus = $1 ORDER BY pr.created_at DESC`;
            const result = await pool.query(query, [estatus]);
            return res.json(result.rows);
        }

        query += ' ORDER BY pr.created_at DESC';
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (error) {
        console.error('Error al listar prórrogas:', error);
        res.status(500).json({ error: error.message });
    }
});

export default router;
