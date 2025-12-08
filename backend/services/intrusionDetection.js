import pool from '../config/database.js';
import nodemailer from 'nodemailer';

/**
 * SISTEMA DE DETECCIÓN DE INTRUSOS (IDS)
 * Monitorea actividad sospechosa y genera alertas en tiempo real
 */

// Configuración de alertas
const ALERT_CONFIG = {
    email: process.env.SECURITY_ALERT_EMAIL || 'admin@tescha.com',
    enableEmailAlerts: process.env.ENABLE_EMAIL_ALERTS === 'true',
    enableConsoleAlerts: true,
    enableDatabaseAlerts: true
};

// Umbrales de detección
const THRESHOLDS = {
    loginAttempts: 5,           // Intentos de login en ventana de tiempo
    loginWindow: 300000,        // 5 minutos
    requestsPerMinute: 60,      // Requests por minuto
    failedAuthPerHour: 10,      // Autenticaciones fallidas por hora
    suspiciousPatterns: 3       // Patrones sospechosos detectados
};

// Almacenamiento en memoria (en producción usar Redis)
const activityLog = new Map();
const suspiciousIPs = new Set();
const blockedIPs = new Set();

// =============================================
// DETECCIÓN DE PATRONES SOSPECHOSOS
// =============================================

export function detectSuspiciousPattern(req) {
    const ip = req.ip;
    const path = req.path;
    const method = req.method;

    // Excepción: Permitir búsqueda múltiple en /api/pagos
    if (path === '/api/pagos' && req.query.search) {
        return { detected: false };
    }

    // Patrones sospechosos
    const patterns = [
        // SQL Injection
        /('|(--)|;|\/\*|\*\/|xp_|sp_|exec|execute|select|insert|update|delete|drop|create|alter)/i,
        // XSS
        /<script|javascript:|onerror=|onload=|<iframe|<object|<embed/i,
        // Path Traversal
        /\.\.|\/etc\/|\/proc\/|\/sys\/|\/var\//i,
        // Command Injection
        /;|\||&|`|\$\(|\$\{/,
        // File Upload Attacks
        /\.php|\.asp|\.jsp|\.exe|\.sh|\.bat/i
    ];

    const fullPath = `${method} ${path}`;
    const queryString = JSON.stringify(req.query);
    const body = JSON.stringify(req.body);

    for (const pattern of patterns) {
        if (pattern.test(fullPath) || pattern.test(queryString) || pattern.test(body)) {
            return {
                detected: true,
                type: 'SUSPICIOUS_PATTERN',
                pattern: pattern.toString(),
                details: `Patrón sospechoso detectado en ${method} ${path}`
            };
        }
    }

    // Detectar escaneo de puertos/endpoints
    if (!activityLog.has(ip)) {
        activityLog.set(ip, []);
    }

    const ipActivity = activityLog.get(ip);
    ipActivity.push({ path, timestamp: Date.now() });

    // Limpiar actividad antigua
    const fiveMinutesAgo = Date.now() - 300000;
    const recentActivity = ipActivity.filter(a => a.timestamp > fiveMinutesAgo);
    activityLog.set(ip, recentActivity);

    // Detectar escaneo (muchos endpoints diferentes en poco tiempo)
    const uniquePaths = new Set(recentActivity.map(a => a.path));
    if (uniquePaths.size > 20) {
        return {
            detected: true,
            type: 'PORT_SCANNING',
            details: `${uniquePaths.size} endpoints diferentes accedidos en 5 minutos`
        };
    }

    return { detected: false };
}

// =============================================
// DETECCIÓN DE ANOMALÍAS DE TRÁFICO
// =============================================

export function detectTrafficAnomaly(ip) {
    if (!activityLog.has(ip)) {
        return { detected: false };
    }

    const ipActivity = activityLog.get(ip);
    const oneMinuteAgo = Date.now() - 60000;
    const recentRequests = ipActivity.filter(a => a.timestamp > oneMinuteAgo);

    if (recentRequests.length > THRESHOLDS.requestsPerMinute) {
        return {
            detected: true,
            type: 'TRAFFIC_ANOMALY',
            requests: recentRequests.length,
            details: `${recentRequests.length} requests en el último minuto`
        };
    }

    return { detected: false };
}

// =============================================
// GENERACIÓN DE ALERTAS
// =============================================

async function sendAlert(alert) {
    const alertData = {
        timestamp: new Date().toISOString(),
        type: alert.type,
        severity: alert.severity || 'HIGH',
        ip: alert.ip,
        user: alert.user,
        details: alert.details,
        action: alert.action || 'LOGGED'
    };

    // Alerta en consola
    if (ALERT_CONFIG.enableConsoleAlerts) {
        console.error('\n' + '='.repeat(60));
        console.error('🚨 ALERTA DE SEGURIDAD');
        console.error('='.repeat(60));
        console.error(`Tipo: ${alertData.type}`);
        console.error(`Severidad: ${alertData.severity}`);
        console.error(`IP: ${alertData.ip}`);
        console.error(`Usuario: ${alertData.user || 'N/A'}`);
        console.error(`Detalles: ${alertData.details}`);
        console.error(`Acción: ${alertData.action}`);
        console.error(`Timestamp: ${alertData.timestamp}`);
        console.error('='.repeat(60) + '\n');
    }

    // Guardar en base de datos
    if (ALERT_CONFIG.enableDatabaseAlerts) {
        try {
            await pool.query(
                `INSERT INTO security_logs (event_type, ip_address, details) 
         VALUES ($1, $2, $3)`,
                ['SECURITY_ALERT', alertData.ip, JSON.stringify(alertData)]
            );
        } catch (error) {
            console.error('Error saving alert to database:', error.message);
        }
    }

    // Enviar email (si está configurado)
    if (ALERT_CONFIG.enableEmailAlerts) {
        try {
            await sendEmailAlert(alertData);
            console.log('📧 Email de alerta enviado a:', ALERT_CONFIG.email);
        } catch (error) {
            console.error('❌ Error sending email alert:', error.message);
        }
    }
}

async function sendEmailAlert(alertData) {
    // 🔒 Nodemailer 7.x - Sintaxis actualizada
    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: parseInt(process.env.SMTP_PORT || '587'),
        secure: false, // true para 465, false para 587
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
        }
    });

    // Verificar conexión SMTP
    try {
        await transporter.verify();
        console.log('✅ Servidor SMTP conectado');
    } catch (error) {
        console.error('❌ Error SMTP:', error.message);
        throw error;
    }

    const mailOptions = {
        from: {
            name: 'Sistema TESCHA 🔒',
            address: process.env.SMTP_USER
        },
        to: ALERT_CONFIG.email,
        subject: `🚨 ALERTA DE SEGURIDAD - ${alertData.type}`,
        html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 2px solid #d32f2f; border-radius: 8px;">
        <div style="background: #d32f2f; color: white; padding: 20px; text-align: center;">
          <h2 style="margin: 0;">🚨 ALERTA DE SEGURIDAD</h2>
          <p style="margin: 5px 0 0 0;">Sistema TESCHA</p>
        </div>
        <div style="padding: 20px;">
          <div style="background: #fff3e0; padding: 15px; border-left: 4px solid #ff9800; margin: 10px 0;">
            <table style="width: 100%;">
              <tr><td style="padding: 5px; font-weight: bold;">Tipo:</td><td>${alertData.type}</td></tr>
              <tr><td style="padding: 5px; font-weight: bold;">Severidad:</td><td style="color: #d32f2f;">${alertData.severity}</td></tr>
              <tr><td style="padding: 5px; font-weight: bold;">IP:</td><td style="font-family: monospace;">${alertData.ip}</td></tr>
              <tr><td style="padding: 5px; font-weight: bold;">Usuario:</td><td>${alertData.user || 'N/A'}</td></tr>
              <tr><td style="padding: 5px; font-weight: bold;">Detalles:</td><td>${alertData.details}</td></tr>
              <tr><td style="padding: 5px; font-weight: bold;">Acción:</td><td style="color: #1976d2;">${alertData.action}</td></tr>
              <tr><td style="padding: 5px; font-weight: bold;">Timestamp:</td><td>${alertData.timestamp}</td></tr>
            </table>
          </div>
        </div>
        <div style="background: #f5f5f5; padding: 15px; text-align: center;">
          <p style="margin: 0; color: #666; font-size: 12px;">
            Email automático - Sistema de Detección de Intrusos
          </p>
        </div>
      </div>
    `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('📧 Email enviado:', info.messageId);
    return info;
}

// =============================================
// MIDDLEWARE DE DETECCIÓN
// =============================================

export const intrusionDetectionMiddleware = async (req, res, next) => {
    const ip = req.ip;
    const user = req.user?.username || 'anonymous';

    // 🏠 WHITELIST: IPs confiables que NUNCA serán bloqueadas (localhost, desarrollo)
    const trustedIPs = [
        '::1',              // IPv6 localhost
        '127.0.0.1',        // IPv4 localhost
        '::ffff:127.0.0.1', // IPv4-mapped IPv6 localhost
        'localhost'
    ];

    const isTrustedIP = trustedIPs.includes(ip);

    // Verificar si la IP está bloqueada (solo IPs externas, NUNCA localhost)
    if (blockedIPs.has(ip) && !isTrustedIP) {
        return res.status(403).json({
            error: 'Tu IP ha sido bloqueada por actividad sospechosa. Contacta al administrador.'
        });
    }

    // Detectar patrones sospechosos
    const patternDetection = detectSuspiciousPattern(req);
    if (patternDetection.detected) {
        // 🔔 ALERTAR sobre actividad sospechosa
        await sendAlert({
            type: patternDetection.type,
            severity: isTrustedIP ? 'LOW' : 'HIGH', // Menor severidad para localhost
            ip,
            user,
            details: patternDetection.details + (isTrustedIP ? ' (IP confiable - desarrollo)' : ''),
            action: isTrustedIP ? 'LOGGED_TRUSTED' : 'LOGGED'
        });

        // 🏠 Si es localhost (desarrollo), SOLO alertar, NUNCA bloquear
        if (isTrustedIP) {
            console.log(`ℹ️  Patrón sospechoso de localhost (desarrollo) - Solo registrado, no bloqueado`);
            // PERMITIR CONTINUAR - Es el desarrollador haciendo pruebas
            return next();
        }

        // 🌐 Para IPs EXTERNAS: marcar como sospechosa y contar intentos
        suspiciousIPs.add(ip);

        // Contar intentos sospechosos
        if (!activityLog.has(ip)) {
            activityLog.set(ip, []);
        }
        const ipActivity = activityLog.get(ip);
        ipActivity.push({
            path: req.path,
            timestamp: Date.now(),
            suspicious: true // Marcar como sospechoso
        });

        // Solo bloquear IPs EXTERNAS después de 10+ intentos sospechosos
        const suspiciousCount = ipActivity.filter(a => a.suspicious).length;
        if (suspiciousCount >= 10) {
            blockedIPs.add(ip);
            await sendAlert({
                type: 'IP_BLOCKED',
                severity: 'CRITICAL',
                ip,
                user,
                details: `🚨 IP EXTERNA bloqueada después de ${suspiciousCount} intentos sospechosos`,
                action: 'IP_BLOCKED'
            });
            return res.status(403).json({
                error: 'Tu IP ha sido bloqueada por múltiples intentos sospechosos.'
            });
        }

        // ⚠️ PERMITIR CONTINUAR (para IPs externas con pocos intentos)
        console.log(`⚠️  Actividad sospechosa de IP EXTERNA ${ip} (intento ${suspiciousCount}/10)`);
        // NO retornar error - dejar que continúe
    }

    // Detectar anomalías de tráfico (solo alertar, no bloquear)
    const trafficDetection = detectTrafficAnomaly(ip);
    if (trafficDetection.detected) {
        await sendAlert({
            type: trafficDetection.type,
            severity: 'MEDIUM',
            ip,
            user,
            details: trafficDetection.details,
            action: 'LOGGED'
        });
        // NO bloquear por tráfico alto - solo alertar
    }

    next();
};

// =============================================
// FUNCIONES DE GESTIÓN
// =============================================

export function unblockIP(ip) {
    blockedIPs.delete(ip);
    suspiciousIPs.delete(ip);
    activityLog.delete(ip);
    console.log(`IP desbloqueada: ${ip}`);
}

export function getBlockedIPs() {
    return Array.from(blockedIPs);
}

export function getSuspiciousIPs() {
    return Array.from(suspiciousIPs);
}

export async function getSecurityReport() {
    try {
        const result = await pool.query(`
      SELECT 
        event_type,
        COUNT(*) as count,
        MAX(created_at) as last_occurrence
      FROM security_logs
      WHERE created_at > NOW() - INTERVAL '24 hours'
      GROUP BY event_type
      ORDER BY count DESC
    `);

        return {
            last24Hours: result.rows,
            blockedIPs: getBlockedIPs(),
            suspiciousIPs: getSuspiciousIPs(),
            timestamp: new Date().toISOString()
        };
    } catch (error) {
        console.error('Error generating security report:', error.message);
        return {
            last24Hours: [],
            blockedIPs: getBlockedIPs(),
            suspiciousIPs: getSuspiciousIPs(),
            timestamp: new Date().toISOString()
        };
    }
}

// Exportar sendAlert como named export
export { sendAlert };

export default {
    detectSuspiciousPattern,
    detectTrafficAnomaly,
    intrusionDetectionMiddleware,
    sendAlert,
    unblockIP,
    getBlockedIPs,
    getSuspiciousIPs,
    getSecurityReport
};
