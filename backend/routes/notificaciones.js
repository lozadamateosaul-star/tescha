import express from 'express';
import pool from '../config/database.js';
import { auth, checkRole } from '../middleware/auth.js';
import {
  obtenerProrrogasPorVencer,
  obtenerProrrogasVencidas,
  procesarNotificaciones
} from '../services/notificacionesService.js';

const router = express.Router();

// Obtener prórrogas por vencer (próximos 3 días)
router.get('/prorrogas-por-vencer', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const dias = req.query.dias || 3;
    const prorrogas = await obtenerProrrogasPorVencer(dias);

    res.json({
      count: prorrogas.length,
      prorrogas
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Obtener prórrogas vencidas
router.get('/prorrogas-vencidas', auth, checkRole('coordinador'), async (req, res) => {
  try {
    const prorrogas = await obtenerProrrogasVencidas();

    res.json({
      count: prorrogas.length,
      prorrogas
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ⚠️ NOTA: Las notificaciones se envían AUTOMÁTICAMENTE todos los días a las 9:00 AM
// No hay endpoints manuales para prevenir uso indebido

export default router;
