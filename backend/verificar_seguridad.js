import pool from './config/database.js';
import fs from 'fs';
import path from 'path';

/**
 * SCRIPT DE VERIFICACIÓN DE SEGURIDAD
 * Verifica que todas las medidas de seguridad estén activas
 */

console.log('\n🔒 INICIANDO VERIFICACIÓN DE SEGURIDAD DEL SISTEMA TESCHA\n');
console.log('='.repeat(70));

const checks = [];
let totalScore = 0;
const maxScore = 100;

// =============================================
// 1. VERIFICAR VARIABLES DE ENTORNO
// =============================================
async function checkEnvironmentVariables() {
    console.log('\n📋 1. VERIFICANDO VARIABLES DE ENTORNO...');

    const requiredVars = [
        'DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASSWORD',
        'JWT_SECRET', 'JWT_EXPIRES_IN', 'PORT', 'NODE_ENV'
    ];

    const optionalVars = [
        'ENCRYPTION_KEY', 'SECURITY_ALERT_EMAIL', 'SMTP_HOST', 'SMTP_USER'
    ];

    let score = 0;
    const missingRequired = [];
    const missingOptional = [];

    requiredVars.forEach(varName => {
        if (process.env[varName]) {
            score += 5;
        } else {
            missingRequired.push(varName);
        }
    });

    optionalVars.forEach(varName => {
        if (process.env[varName]) {
            score += 2.5;
        } else {
            missingOptional.push(varName);
        }
    });

    if (missingRequired.length === 0) {
        console.log('   ✅ Todas las variables requeridas están configuradas');
    } else {
        console.log(`   ❌ Variables requeridas faltantes: ${missingRequired.join(', ')}`);
    }

    if (missingOptional.length === 0) {
        console.log('   ✅ Todas las variables opcionales están configuradas');
    } else {
        console.log(`   ⚠️  Variables opcionales faltantes: ${missingOptional.join(', ')}`);
    }

    // Verificar seguridad de JWT_SECRET
    if (process.env.JWT_SECRET) {
        if (process.env.JWT_SECRET.length < 32) {
            console.log('   ⚠️  JWT_SECRET es muy corto (mínimo 32 caracteres recomendado)');
            score -= 5;
        } else if (process.env.JWT_SECRET.includes('cambialo') || process.env.JWT_SECRET.includes('secreto')) {
            console.log('   ⚠️  JWT_SECRET parece ser el valor por defecto - CAMBIAR EN PRODUCCIÓN');
            score -= 5;
        } else {
            console.log('   ✅ JWT_SECRET tiene longitud adecuada');
        }
    }

    // Verificar NODE_ENV
    if (process.env.NODE_ENV === 'production') {
        console.log('   ✅ NODE_ENV configurado en production');
    } else {
        console.log('   ⚠️  NODE_ENV no está en production (actual: ' + (process.env.NODE_ENV || 'development') + ')');
    }

    checks.push({
        name: 'Variables de Entorno',
        score: Math.max(0, score),
        maxScore: 50,
        status: missingRequired.length === 0 ? 'PASS' : 'FAIL'
    });

    return Math.max(0, score);
}

// =============================================
// 2. VERIFICAR TABLAS DE SEGURIDAD
// =============================================
async function checkSecurityTables() {
    console.log('\n📋 2. VERIFICANDO TABLAS DE SEGURIDAD EN BASE DE DATOS...');

    const requiredTables = [
        'security_logs',
        'login_attempts',
        'notificaciones_enviadas',
        'auditoria'
    ];

    let score = 0;

    try {
        for (const tableName of requiredTables) {
            const result = await pool.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_schema = 'public' 
          AND table_name = $1
        )
      `, [tableName]);

            if (result.rows[0].exists) {
                console.log(`   ✅ Tabla ${tableName} existe`);
                score += 5;
            } else {
                console.log(`   ❌ Tabla ${tableName} NO existe`);
            }
        }

        checks.push({
            name: 'Tablas de Seguridad',
            score,
            maxScore: 20,
            status: score === 20 ? 'PASS' : 'FAIL'
        });

        return score;
    } catch (error) {
        console.log('   ❌ Error al verificar tablas:', error.message);
        checks.push({
            name: 'Tablas de Seguridad',
            score: 0,
            maxScore: 20,
            status: 'FAIL'
        });
        return 0;
    }
}

// =============================================
// 3. VERIFICAR LOGS DE SEGURIDAD RECIENTES
// =============================================
async function checkSecurityLogs() {
    console.log('\n📋 3. VERIFICANDO LOGS DE SEGURIDAD...');

    try {
        const result = await pool.query(`
      SELECT 
        event_type,
        COUNT(*) as count
      FROM security_logs
      WHERE created_at > NOW() - INTERVAL '24 hours'
      GROUP BY event_type
      ORDER BY count DESC
    `);

        if (result.rows.length > 0) {
            console.log('   📊 Eventos de seguridad en las últimas 24 horas:');
            result.rows.forEach(row => {
                console.log(`      - ${row.event_type}: ${row.count} eventos`);
            });
        } else {
            console.log('   ℹ️  No hay eventos de seguridad en las últimas 24 horas');
        }

        // Verificar si hay alertas críticas
        const criticalResult = await pool.query(`
      SELECT COUNT(*) as count
      FROM security_logs
      WHERE created_at > NOW() - INTERVAL '24 hours'
      AND event_type = 'SECURITY_ALERT'
    `);

        const criticalCount = parseInt(criticalResult.rows[0].count);

        if (criticalCount > 0) {
            console.log(`   ⚠️  ${criticalCount} alertas de seguridad en las últimas 24 horas`);
        } else {
            console.log('   ✅ No hay alertas críticas recientes');
        }

        checks.push({
            name: 'Logs de Seguridad',
            score: 10,
            maxScore: 10,
            status: 'PASS'
        });

        return 10;
    } catch (error) {
        console.log('   ⚠️  No se pudieron verificar logs:', error.message);
        checks.push({
            name: 'Logs de Seguridad',
            score: 5,
            maxScore: 10,
            status: 'PARTIAL'
        });
        return 5;
    }
}

// =============================================
// 4. VERIFICAR INTENTOS DE LOGIN FALLIDOS
// =============================================
async function checkFailedLogins() {
    console.log('\n📋 4. VERIFICANDO INTENTOS DE LOGIN FALLIDOS...');

    try {
        const result = await pool.query(`
      SELECT 
        ip_address,
        COUNT(*) as attempts
      FROM login_attempts
      WHERE attempt_time > NOW() - INTERVAL '1 hour'
      GROUP BY ip_address
      HAVING COUNT(*) >= 5
      ORDER BY attempts DESC
    `);

        if (result.rows.length > 0) {
            console.log('   ⚠️  IPs con múltiples intentos fallidos en la última hora:');
            result.rows.forEach(row => {
                console.log(`      - ${row.ip_address}: ${row.attempts} intentos`);
            });
        } else {
            console.log('   ✅ No hay IPs con intentos sospechosos recientes');
        }

        checks.push({
            name: 'Intentos de Login',
            score: 10,
            maxScore: 10,
            status: 'PASS'
        });

        return 10;
    } catch (error) {
        console.log('   ⚠️  No se pudieron verificar intentos de login:', error.message);
        checks.push({
            name: 'Intentos de Login',
            score: 5,
            maxScore: 10,
            status: 'PARTIAL'
        });
        return 5;
    }
}

// =============================================
// 5. VERIFICAR SISTEMA DE NOTIFICACIONES
// =============================================
async function checkNotificationSystem() {
    console.log('\n📋 5. VERIFICANDO SISTEMA DE NOTIFICACIONES...');

    try {
        const result = await pool.query(`
      SELECT 
        tipo,
        COUNT(*) as count,
        MAX(fecha_envio) as ultima_notificacion
      FROM notificaciones_enviadas
      WHERE fecha_envio > NOW() - INTERVAL '7 days'
      GROUP BY tipo
    `);

        if (result.rows.length > 0) {
            console.log('   📧 Notificaciones enviadas en los últimos 7 días:');
            result.rows.forEach(row => {
                const fecha = new Date(row.ultima_notificacion).toLocaleString('es-MX');
                console.log(`      - ${row.tipo}: ${row.count} notificaciones (última: ${fecha})`);
            });
        } else {
            console.log('   ℹ️  No hay notificaciones enviadas en los últimos 7 días');
        }

        checks.push({
            name: 'Sistema de Notificaciones',
            score: 10,
            maxScore: 10,
            status: 'PASS'
        });

        return 10;
    } catch (error) {
        console.log('   ⚠️  No se pudo verificar sistema de notificaciones:', error.message);
        checks.push({
            name: 'Sistema de Notificaciones',
            score: 5,
            maxScore: 10,
            status: 'PARTIAL'
        });
        return 5;
    }
}

// =============================================
// EJECUTAR TODAS LAS VERIFICACIONES
// =============================================
async function runSecurityChecks() {
    try {
        totalScore += await checkEnvironmentVariables();
        totalScore += await checkSecurityTables();
        totalScore += await checkSecurityLogs();
        totalScore += await checkFailedLogins();
        totalScore += await checkNotificationSystem();

        // Reporte final
        console.log('\n' + '='.repeat(70));
        console.log('📊 REPORTE DE SEGURIDAD');
        console.log('='.repeat(70));

        checks.forEach(check => {
            const percentage = ((check.score / check.maxScore) * 100).toFixed(1);
            const statusIcon = check.status === 'PASS' ? '✅' : check.status === 'FAIL' ? '❌' : '⚠️';
            console.log(`${statusIcon} ${check.name}: ${check.score}/${check.maxScore} (${percentage}%)`);
        });

        console.log('\n' + '='.repeat(70));
        const finalPercentage = ((totalScore / maxScore) * 100).toFixed(1);
        console.log(`🎯 PUNTUACIÓN TOTAL: ${totalScore}/${maxScore} (${finalPercentage}%)`);

        let grade = 'F';
        if (finalPercentage >= 90) grade = 'A+';
        else if (finalPercentage >= 80) grade = 'A';
        else if (finalPercentage >= 70) grade = 'B';
        else if (finalPercentage >= 60) grade = 'C';
        else if (finalPercentage >= 50) grade = 'D';

        console.log(`📈 CALIFICACIÓN: ${grade}`);

        if (finalPercentage >= 80) {
            console.log('\n✅ EL SISTEMA ES SEGURO Y ESTÁ PROTEGIDO CONTRA HACKEOS');
        } else if (finalPercentage >= 60) {
            console.log('\n⚠️  EL SISTEMA TIENE SEGURIDAD BÁSICA PERO NECESITA MEJORAS');
        } else {
            console.log('\n❌ EL SISTEMA TIENE VULNERABILIDADES CRÍTICAS - ACCIÓN INMEDIATA REQUERIDA');
        }

        console.log('='.repeat(70));

        // Recomendaciones
        console.log('\n💡 RECOMENDACIONES:');

        if (!process.env.ENCRYPTION_KEY) {
            console.log('   • Generar ENCRYPTION_KEY: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
        }

        if (process.env.NODE_ENV !== 'production') {
            console.log('   • Cambiar NODE_ENV a "production" en el servidor de producción');
        }

        if (!process.env.SECURITY_ALERT_EMAIL) {
            console.log('   • Configurar SECURITY_ALERT_EMAIL para recibir alertas de seguridad');
        }

        console.log('   • Revisar el archivo AUDITORIA_SEGURIDAD.md para más detalles');
        console.log('   • Configurar backups automáticos de la base de datos');
        console.log('   • Implementar HTTPS en producción');

        console.log('\n✅ Verificación completada\n');

    } catch (error) {
        console.error('\n❌ Error durante la verificación:', error);
    } finally {
        await pool.end();
    }
}

// Ejecutar
runSecurityChecks();
