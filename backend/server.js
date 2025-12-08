import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import logger from './utils/logger.js';
import {
  errorHandler,
  notFoundHandler,
  setupUncaughtHandlers,
  requestLogger,
  healthCheck
} from './middleware/errorHandler.js';
import { iniciarCronNotificaciones, inicializarTablaNotificaciones, procesarNotificaciones } from './services/notificacionesService.js';

// Importar rutas
import authRoutes from './routes/auth.js';
import alumnosRoutes from './routes/alumnos.js';
import maestrosRoutes from './routes/maestros.js';
import gruposRoutes from './routes/grupos.js';
import salonesRoutes from './routes/salones.js';
import periodosRoutes from './routes/periodos.js';
import pagosRoutes from './routes/pagos.js';
import calificacionesRoutes from './routes/calificaciones.js';
import asistenciasRoutes from './routes/asistencias.js';
import librosRoutes from './routes/libros.js';
import reportesRoutes from './routes/reportes.js';
import dashboardRoutes from './routes/dashboard.js';
import maestrosDashboardRoutes from './routes/maestros-dashboard.js';
import maestrosAlumnosRoutes from './routes/maestros-alumnos.js';
import uploadRoutes from './routes/upload.js';
import notificacionesRoutes from './routes/notificaciones.js';
import metricasRoutes from './routes/metricas.js';
import metricsScheduler from './services/metricsScheduler.js';

// Importar middlewares de seguridad
import {
  sanitizeInput,
  securityLogger,
  securityHeaders,
  detectAnomalies
} from './middleware/security.js';

// Importar sistema de detección de intrusos
import { intrusionDetectionMiddleware } from './services/intrusionDetection.js';

// Importar dashboard de seguridad
import securityDashboardRoutes from './routes/security-dashboard.js';
import securityTestRoutes from './routes/security-test.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// 🛡️ SEGURIDAD: Rate Limiting - Prevenir ataques de fuerza bruta
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 1000, // Máximo 1000 requests por IP en 15 minutos (aumentado para desarrollo)
  message: 'Demasiadas solicitudes desde esta IP, intenta de nuevo en 15 minutos',
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiter específico para login (más restrictivo)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // Máximo 5 intentos de login en 15 minutos
  message: 'Demasiados intentos de inicio de sesión, intenta de nuevo en 15 minutos',
  skipSuccessfulRequests: true, // No contar requests exitosos
});

// Middlewares
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));
app.use(cors({
  origin: function (origin, callback) {
    // Permitir requests sin origin (como mobile apps o curl)
    if (!origin) return callback(null, true);

    // Lista de orígenes permitidos
    const allowedOrigins = [
      'http://localhost:3000',
      'http://127.0.0.1:3000',
      'http://coordinacion-tescha.local',
      'http://192.168.1.132',          // IP en WiFi compartido
      'http://192.168.1.132:3000',
      'http://192.168.137.1',          // IP en Hotspot (compartir internet)
      'http://192.168.137.1:3000',
      process.env.FRONTEND_URL
    ].filter(Boolean); // Filtrar valores undefined

    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(null, true); // En desarrollo, permitir todos los orígenes
    }
  },
  credentials: true
}));
app.use(morgan('dev'));
app.use(requestLogger); // 📝 Logging de todas las requests
app.use(express.json({ limit: '10mb' })); // Limitar tamaño de payload
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 🔒 SEGURIDAD: Prevenir Parameter Pollution
// Si hay parámetros duplicados, solo usar el primero
app.use((req, res, next) => {
  if (req.query) {
    Object.keys(req.query).forEach(key => {
      if (Array.isArray(req.query[key])) {
        req.query[key] = req.query[key][0]; // Solo el primer valor
      }
    });
  }
  next();
});

app.use(limiter); // Aplicar rate limiting global

// 🛡️ SEGURIDAD AVANZADA: Middlewares de protección
app.use(sanitizeInput);      // Sanitizar todos los inputs (XSS protection)
app.use(securityLogger);     // Logging de eventos de seguridad
app.use(securityHeaders);    // Headers de seguridad adicionales
app.use(detectAnomalies);    // Detección de comportamiento sospechoso
app.use(intrusionDetectionMiddleware); // 🚨 Sistema de Detección de Intrusos (IDS)

// Rutas públicas
app.get('/', (req, res) => {
  res.json({
    message: 'API TESCHA - Sistema de Coordinación de Inglés',
    version: '1.0.0'
  });
});

// Health check endpoint
app.get('/health', healthCheck);

// Rutas de la API
// Login con rate limiting más restrictivo
app.use('/api/auth/login', loginLimiter);
app.use('/api/auth', authRoutes);
app.use('/api/alumnos', alumnosRoutes);
app.use('/api/maestros', maestrosRoutes);
app.use('/api/grupos', gruposRoutes);
app.use('/api/salones', salonesRoutes);
app.use('/api/periodos', periodosRoutes);
app.use('/api/pagos', pagosRoutes);
app.use('/api/calificaciones', calificacionesRoutes);
app.use('/api/asistencias', asistenciasRoutes);
app.use('/api/libros', librosRoutes);
app.use('/api/reportes', reportesRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/maestros-dashboard', maestrosDashboardRoutes);
app.use('/api/maestros-alumnos', maestrosAlumnosRoutes);
app.use('/api/upload', uploadRoutes);
app.use('/api/notificaciones', notificacionesRoutes);
app.use('/api/metricas', metricasRoutes);
app.use('/api/analisis', metricasRoutes); // Usa el mismo router para análisis
app.use('/api/security', securityDashboardRoutes); // 🔒 Dashboard de Seguridad
app.use('/api/security-test', securityTestRoutes); // 🧪 Pruebas de Seguridad

// Manejar rutas no encontradas
app.use(notFoundHandler);

// Manejo de errores
app.use(errorHandler);

// Configurar manejadores de errores no capturados
setupUncaughtHandlers();

// Iniciar servidor
app.listen(PORT, async () => {
  logger.info(`Servidor iniciado en puerto ${PORT}`);
  logger.info(`Ambiente: ${process.env.NODE_ENV || 'development'}`);

  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  console.log(`📍 Ambiente: ${process.env.NODE_ENV || 'development'}`);

  // Inicializar sistema de notificaciones
  await inicializarTablaNotificaciones();
  iniciarCronNotificaciones();

  logger.info('Sistema de notificaciones automáticas activo');
  console.log('📲 Sistema de notificaciones automáticas activo');

  // Inicializar scheduler de métricas
  metricsScheduler.start();
  logger.info('Sistema de métricas automáticas activo');
  console.log('📊 Sistema de métricas automáticas activo');

  logger.info('✅ Sistema TESCHA completamente inicializado');
});

export default app;
