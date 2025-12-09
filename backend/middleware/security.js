import crypto from 'crypto';
import pool from '../config/database.js';

/**
 * Middleware de seguridad avanzado
 * Incluye protección CSRF, sanitización, rate limiting por usuario, etc.
 */

// =============================================
// PROTECCIÓN CSRF (Cross-Site Request Forgery)
// =============================================

const csrfTokens = new Map(); // En producción, usar Redis

export const generateCsrfToken = (req, res, next) => {
    const token = crypto.randomBytes(32).toString('hex');
    const userId = req.user?.id || req.ip;

    csrfTokens.set(userId, {
        token,
        expires: Date.now() + 3600000 // 1 hora
    });

    res.locals.csrfToken = token;
    next();
};

export const verifyCsrfToken = (req, res, next) => {
    // Solo verificar en métodos que modifican datos
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }

    const token = req.header('X-CSRF-Token') || req.body._csrf;
    const userId = req.user?.id || req.ip;

    const storedToken = csrfTokens.get(userId);

    if (!storedToken || storedToken.expires < Date.now()) {
        csrfTokens.delete(userId);
        return res.status(403).json({ error: 'Token CSRF expirado o inválido' });
    }

    if (storedToken.token !== token) {
        return res.status(403).json({ error: 'Token CSRF inválido' });
    }

    next();
};

// =============================================
// SANITIZACIÓN DE INPUTS
// =============================================

export const sanitizeInput = (req, res, next) => {
    const sanitize = (obj) => {
        if (typeof obj !== 'object' || obj === null) {
            if (typeof obj === 'string') {
                // Remover caracteres peligrosos
                return obj
                    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
                    .replace(/javascript:/gi, '')
                    .replace(/on\w+\s*=/gi, '')
                    .trim();
            }
            return obj;
        }

        const sanitized = Array.isArray(obj) ? [] : {};
        for (const key in obj) {
            sanitized[key] = sanitize(obj[key]);
        }
        return sanitized;
    };

    req.body = sanitize(req.body);
    req.query = sanitize(req.query);
    req.params = sanitize(req.params);

    next();
};

// =============================================
// LOGGING DE SEGURIDAD
// =============================================

export const securityLogger = async (req, res, next) => {
    const originalSend = res.send;

    res.send = function (data) {
        // Loggear eventos de seguridad importantes
        if (res.statusCode === 401 || res.statusCode === 403) {
            logSecurityEvent({
                type: res.statusCode === 401 ? 'UNAUTHORIZED_ACCESS' : 'FORBIDDEN_ACCESS',
                userId: req.user?.id || null,
                ip: req.ip,
                path: req.path,
                method: req.method,
                userAgent: req.get('user-agent'),
                timestamp: new Date()
            });
        }

        originalSend.call(this, data);
    };

    next();
};

async function logSecurityEvent(event) {
    try {
        // Log to console instead of database for now
        console.log('🔒 Security Event:', {
            type: event.type,
            userId: event.userId,
            ip: event.ip,
            path: event.path,
            method: event.method,
            timestamp: event.timestamp
        });
    } catch (error) {
        console.error('Error logging security event:', error);
    }
}

// =============================================
// BLOQUEO DE CUENTA POR INTENTOS FALLIDOS
// =============================================

const loginAttempts = new Map(); // Usar memoria en lugar de BD

export const trackLoginAttempts = async (req, res, next) => {
    const { username } = req.body;
    const ip = req.ip;
    const key = `${username}:${ip}`;

    // Verificar intentos en memoria
    try {
        const now = Date.now();
        const attempts = loginAttempts.get(key) || [];

        // Limpiar intentos antiguos (más de 1 hora)
        const recentAttempts = attempts.filter(time => now - time < 3600000);

        if (recentAttempts.length >= 10) {
            return res.status(429).json({
                error: 'Cuenta bloqueada temporalmente por múltiples intentos fallidos. Intenta en 1 hora.'
            });
        }

        req.loginAttempts = recentAttempts.length;
        next();
    } catch (error) {
        console.error('Error tracking login attempts:', error);
        next();
    }
};

export const recordFailedLogin = async (username, ip) => {
    try {
        const key = `${username}:${ip}`;
        const attempts = loginAttempts.get(key) || [];
        attempts.push(Date.now());
        loginAttempts.set(key, attempts);

        console.log(`⚠️ Failed login attempt for ${username} from ${ip}`);
    } catch (error) {
        console.error('Error recording failed login:', error);
    }
};

export const clearLoginAttempts = async (username, ip) => {
    try {
        const key = `${username}:${ip}`;
        loginAttempts.delete(key);
        console.log(`✅ Cleared login attempts for ${username} from ${ip}`);
    } catch (error) {
        console.error('Error clearing login attempts:', error);
    }
};

// =============================================
// VALIDACIÓN DE PROPIEDAD DE RECURSOS (IDOR Protection)
// =============================================

export const validateResourceOwnership = (resourceType) => {
    return async (req, res, next) => {
        const resourceId = req.params.id;
        const userId = req.user.id;
        const userRole = req.user.rol;

        // Coordinadores tienen acceso a todo
        if (userRole === 'coordinador') {
            return next();
        }

        try {
            let isOwner = false;

            switch (resourceType) {
                case 'alumno':
                    const alumnoResult = await pool.query(
                        'SELECT usuario_id FROM alumnos WHERE id = $1',
                        [resourceId]
                    );
                    isOwner = alumnoResult.rows[0]?.usuario_id === userId;
                    break;

                case 'maestro':
                    const maestroResult = await pool.query(
                        'SELECT usuario_id FROM maestros WHERE id = $1',
                        [resourceId]
                    );
                    isOwner = maestroResult.rows[0]?.usuario_id === userId;
                    break;

                case 'grupo':
                    if (userRole === 'maestro') {
                        const grupoResult = await pool.query(
                            `SELECT g.id FROM grupos g
               JOIN maestros m ON g.maestro_id = m.id
               WHERE g.id = $1 AND m.usuario_id = $2`,
                            [resourceId, userId]
                        );
                        isOwner = grupoResult.rows.length > 0;
                    }
                    break;

                default:
                    return res.status(400).json({ error: 'Tipo de recurso no válido' });
            }

            if (!isOwner) {
                return res.status(403).json({
                    error: 'No tienes permiso para acceder a este recurso'
                });
            }

            next();
        } catch (error) {
            console.error('Error validating resource ownership:', error);
            res.status(500).json({ error: 'Error al validar permisos' });
        }
    };
};

// =============================================
// HEADERS DE SEGURIDAD ADICIONALES
// =============================================

export const securityHeaders = (req, res, next) => {
    // Prevenir clickjacking
    res.setHeader('X-Frame-Options', 'DENY');

    // Prevenir MIME sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // XSS Protection (legacy pero útil)
    res.setHeader('X-XSS-Protection', '1; mode=block');

    // Referrer Policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Permissions Policy
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

    next();
};

// =============================================
// DETECCIÓN DE ANOMALÍAS
// =============================================

const requestPatterns = new Map(); // En producción, usar Redis

export const detectAnomalies = (req, res, next) => {
    const userId = req.user?.id || req.ip;
    const now = Date.now();
    const windowMs = 60000; // 1 minuto

    if (!requestPatterns.has(userId)) {
        requestPatterns.set(userId, []);
    }

    const patterns = requestPatterns.get(userId);

    // Limpiar patrones antiguos
    const recentPatterns = patterns.filter(p => now - p.timestamp < windowMs);

    // Agregar nuevo patrón
    recentPatterns.push({
        path: req.path,
        method: req.method,
        timestamp: now
    });

    requestPatterns.set(userId, recentPatterns);

    // Detectar comportamiento sospechoso
    if (recentPatterns.length > 50) {
        console.warn(`⚠️ Comportamiento sospechoso detectado: ${userId} - ${recentPatterns.length} requests en 1 minuto`);

        logSecurityEvent({
            type: 'SUSPICIOUS_ACTIVITY',
            userId: req.user?.id || null,
            ip: req.ip,
            path: req.path,
            method: req.method,
            userAgent: req.get('user-agent'),
            timestamp: new Date()
        });
    }

    next();
};

// =============================================
// ENCRIPTACIÓN DE DATOS SENSIBLES
// =============================================

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32);
const ALGORITHM = 'aes-256-gcm';

export function encryptData(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    return {
        encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex')
    };
}

export function decryptData(encrypted, iv, authTag) {
    const decipher = crypto.createDecipheriv(
        ALGORITHM,
        ENCRYPTION_KEY,
        Buffer.from(iv, 'hex')
    );

    decipher.setAuthTag(Buffer.from(authTag, 'hex'));

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

// =============================================
// EXPORTAR TODOS LOS MIDDLEWARES
// =============================================

export default {
    generateCsrfToken,
    verifyCsrfToken,
    sanitizeInput,
    securityLogger,
    trackLoginAttempts,
    recordFailedLogin,
    clearLoginAttempts,
    validateResourceOwnership,
    securityHeaders,
    detectAnomalies,
    encryptData,
    decryptData
};
