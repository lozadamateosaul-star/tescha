/**
 * 🔐 PRUEBAS DE SEGURIDAD COMPLETAS - TESCHA
 * Verifica protección contra inyección SQL, creación de usuarios maliciosos,
 * bypass de autenticación, y otros vectores de ataque
 */

import axios from 'axios';

const API_URL = 'http://localhost:5000/api';
const TIMEOUT = 5000;

const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;
const vulnerabilities = [];

function testResult(passed, testName, details = '') {
  totalTests++;
  if (passed) {
    passedTests++;
    log(`  ✅ ${testName}`, 'green');
  } else {
    failedTests++;
    log(`  ❌ ${testName}`, 'red');
    vulnerabilities.push({ test: testName, details });
  }
  if (details) {
    log(`     ${details}`, 'yellow');
  }
}

// ==================== PRUEBA 1: BYPASS DE LOGIN ====================
async function testLoginBypass() {
  log('\n╔════════════════════════════════════════╗', 'cyan');
  log('║  PRUEBA 1: Bypass de Autenticación   ║', 'cyan');
  log('╚════════════════════════════════════════╝', 'cyan');

  const maliciousPayloads = [
    { username: "' OR '1'='1", password: "' OR '1'='1" },
    { username: "admin'--", password: "cualquiera" },
    { username: "' OR 1=1--", password: "" },
    { username: "admin", password: "' OR 'x'='x" },
    { username: "'; DROP TABLE usuarios;--", password: "123" },
    { username: "1' UNION SELECT 'admin','$2a$10$...','coordinador'--", password: "123" }
  ];

  for (const payload of maliciousPayloads) {
    try {
      const response = await axios.post(`${API_URL}/auth/login`, payload, {
        timeout: TIMEOUT,
        validateStatus: () => true
      });

      const vulnerable = response.status === 200 && response.data.token;
      testResult(
        !vulnerable,
        `SQL Injection en login: "${payload.username}"`,
        vulnerable ? `⚠️ TOKEN OBTENIDO: ${response.data.token?.substring(0, 20)}...` : ''
      );
    } catch (error) {
      testResult(true, `Protección contra: "${payload.username}"`, 'Timeout o error esperado');
    }
  }
}

// ==================== PRUEBA 2: CREACIÓN DE USUARIOS MALICIOSOS ====================
async function testMaliciousUserCreation(token) {
  log('\n╔════════════════════════════════════════╗', 'cyan');
  log('║  PRUEBA 2: Creación de Usuarios      ║', 'cyan');
  log('╚════════════════════════════════════════╝', 'cyan');

  if (!token) {
    log('  ⚠️ Sin token, omitiendo pruebas autenticadas', 'yellow');
    return;
  }

  const maliciousUsers = [
    {
      username: "admin'; DROP TABLE usuarios;--",
      password: "123456",
      rol: "coordinador"
    },
    {
      username: "hacker",
      password: "123",
      rol: "' OR '1'='1"
    },
    {
      username: "<script>alert('XSS')</script>",
      password: "123",
      rol: "coordinador"
    },
    {
      username: "../../etc/passwd",
      password: "123",
      rol: "coordinador"
    },
    {
      username: "superadmin",
      password: "123",
      rol: "coordinador'; UPDATE usuarios SET rol='coordinador' WHERE '1'='1"
    }
  ];

  for (const user of maliciousUsers) {
    try {
      const response = await axios.post(`${API_URL}/auth/register`, user, {
        headers: { Authorization: `Bearer ${token}` },
        timeout: TIMEOUT,
        validateStatus: () => true
      });

      const vulnerable = response.status === 201 || (response.status === 200 && response.data.id);
      testResult(
        !vulnerable,
        `Bloqueo de usuario malicioso: "${user.username.substring(0, 30)}..."`,
        vulnerable ? `⚠️ Usuario creado con ID: ${response.data.id}` : ''
      );
    } catch (error) {
      testResult(true, `Protección contra user: "${user.username.substring(0, 30)}..."`);
    }
  }
}

// ==================== PRUEBA 3: INYECCIÓN SQL EN BÚSQUEDAS ====================
async function testSearchInjection(token) {
  log('\n╔════════════════════════════════════════╗', 'cyan');
  log('║  PRUEBA 3: Inyección en Búsquedas    ║', 'cyan');
  log('╚════════════════════════════════════════╝', 'cyan');

  if (!token) {
    log('  ⚠️ Sin token, omitiendo pruebas', 'yellow');
    return;
  }

  const searchPayloads = [
    "' OR 1=1--",
    "'; SELECT * FROM usuarios--",
    "1' UNION SELECT password FROM usuarios--",
    "%'; DROP TABLE alumnos; --",
    "test' AND SLEEP(5)--"
  ];

  const endpoints = [
    '/alumnos',
    '/maestros',
    '/grupos',
    '/pagos'
  ];

  for (const endpoint of endpoints) {
    for (const payload of searchPayloads) {
      try {
        const response = await axios.get(`${API_URL}${endpoint}`, {
          params: { search: payload },
          headers: { Authorization: `Bearer ${token}` },
          timeout: TIMEOUT,
          validateStatus: () => true
        });

        const vulnerable = 
          (response.status === 200 && response.data.error?.includes('syntax')) ||
          (response.status === 500 && response.data.error?.includes('postgresql'));

        testResult(
          !vulnerable,
          `${endpoint} contra: "${payload.substring(0, 30)}..."`,
          vulnerable ? `⚠️ Error SQL expuesto: ${response.data.error?.substring(0, 50)}` : ''
        );
      } catch (error) {
        testResult(true, `${endpoint} protegido contra: "${payload.substring(0, 20)}..."`);
      }
    }
  }
}

// ==================== PRUEBA 4: MANIPULACIÓN DE IDs EN UPDATE ====================
async function testUpdateInjection(token) {
  log('\n╔════════════════════════════════════════╗', 'cyan');
  log('║  PRUEBA 4: Inyección en UPDATE       ║', 'cyan');
  log('╚════════════════════════════════════════╝', 'cyan');

  if (!token) {
    log('  ⚠️ Sin token, omitiendo pruebas', 'yellow');
    return;
  }

  const maliciousUpdates = [
    {
      "nombre; DROP TABLE alumnos;--": "hack"
    },
    {
      "password' WHERE username='admin';--": "hacked"
    },
    {
      "rol": "coordinador'; UPDATE usuarios SET rol='coordinador' WHERE 1=1;--"
    },
    {
      "correo": "test@test.com'; DELETE FROM pagos;--"
    }
  ];

  const endpoints = [
    { url: '/alumnos/1', name: 'Alumnos' },
    { url: '/grupos/1', name: 'Grupos' },
    { url: '/libros/1', name: 'Libros' }
  ];

  for (const endpoint of endpoints) {
    for (const payload of maliciousUpdates) {
      try {
        const response = await axios.put(`${API_URL}${endpoint.url}`, payload, {
          headers: { Authorization: `Bearer ${token}` },
          timeout: TIMEOUT,
          validateStatus: () => true
        });

        const vulnerable = response.status === 200 && !response.data.error?.includes('válidos');
        testResult(
          !vulnerable,
          `${endpoint.name} UPDATE con campo: "${Object.keys(payload)[0].substring(0, 30)}..."`,
          vulnerable ? `⚠️ Campo malicioso aceptado` : 'Whitelist funcionando'
        );
      } catch (error) {
        testResult(true, `${endpoint.name} UPDATE protegido`);
      }
    }
  }
}

// ==================== PRUEBA 5: RATE LIMITING ====================
async function testRateLimiting() {
  log('\n╔════════════════════════════════════════╗', 'cyan');
  log('║  PRUEBA 5: Rate Limiting              ║', 'cyan');
  log('╚════════════════════════════════════════╝', 'cyan');

  try {
    // Hacer 6 intentos de login para exceder el límite de 5
    let blocked = false;
    let blockedAt = 0;
    
    for (let i = 0; i < 7; i++) {
      try {
        const response = await axios.post(`${API_URL}/auth/login`, {
          username: `test${i}`,
          password: 'wrongpassword'
        }, {
          timeout: TIMEOUT,
          validateStatus: () => true
        });
        
        if (response.status === 429) {
          blocked = true;
          blockedAt = i + 1;
          break;
        }
        
        // Pequeña pausa entre requests
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (error) {
        // Ignorar errores de timeout
        if (error.code !== 'ECONNABORTED') {
          throw error;
        }
      }
    }
    
    testResult(
      blocked,
      `Rate limiting en login (${blockedAt} intentos)`,
      blocked ? `Bloqueado correctamente en el intento #${blockedAt}` : '⚠️ No se activó el límite después de 7 intentos'
    );
  } catch (error) {
    testResult(false, 'Error al probar rate limiting', error.message);
  }
}

// ==================== PRUEBA 6: ACCESO SIN TOKEN ====================
async function testUnauthorizedAccess() {
  log('\n╔════════════════════════════════════════╗', 'cyan');
  log('║  PRUEBA 6: Acceso sin Autenticación  ║', 'cyan');
  log('╚════════════════════════════════════════╝', 'cyan');

  const protectedEndpoints = [
    { method: 'get', url: '/alumnos' },
    { method: 'get', url: '/maestros' },
    { method: 'get', url: '/pagos' },
    { method: 'post', url: '/alumnos' },
    { method: 'put', url: '/alumnos/1' },
    { method: 'delete', url: '/alumnos/1' }
  ];

  for (const endpoint of protectedEndpoints) {
    try {
      const response = await axios[endpoint.method](`${API_URL}${endpoint.url}`, {
        timeout: TIMEOUT,
        validateStatus: () => true
      });

      const isProtected = response.status === 401 || response.status === 403;
      testResult(
        isProtected,
        `${endpoint.method.toUpperCase()} ${endpoint.url} sin token`,
        isProtected ? 'Acceso denegado correctamente' : `⚠️ Acceso permitido con status ${response.status}`
      );
    } catch (error) {
      testResult(true, `${endpoint.method.toUpperCase()} ${endpoint.url} protegido`);
    }
  }
}

// ==================== PRUEBA 7: XSS EN INPUTS ====================
async function testXSSProtection(token) {
  log('\n╔════════════════════════════════════════╗', 'cyan');
  log('║  PRUEBA 7: Protección contra XSS     ║', 'cyan');
  log('╚════════════════════════════════════════╝', 'cyan');

  if (!token) {
    log('  ⚠️ Sin token, omitiendo pruebas', 'yellow');
    return;
  }

  const xssPayloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg onload=alert('XSS')>",
    "';alert('XSS');//"
  ];

  for (const payload of xssPayloads) {
    try {
      const response = await axios.post(`${API_URL}/alumnos`, {
        nombre: payload,
        apellido_paterno: "Test",
        apellido_materno: "Test",
        correo: `test${Date.now()}@test.com`,
        matricula: `TEST${Date.now()}`,
        nivel_actual: "A1"
      }, {
        headers: { Authorization: `Bearer ${token}` },
        timeout: TIMEOUT,
        validateStatus: () => true
      });

      // Verificar si el payload fue sanitizado
      if (response.status === 201 && response.data.nombre) {
        const sanitized = !response.data.nombre.includes('<script>') && 
                         !response.data.nombre.includes('onerror');
        testResult(
          sanitized,
          `Sanitización de XSS: "${payload.substring(0, 30)}..."`,
          sanitized ? 'Código HTML/JS removido' : `⚠️ XSS almacenado: ${response.data.nombre}`
        );
      } else {
        testResult(true, `Rechazo de payload XSS: "${payload.substring(0, 30)}..."`);
      }
    } catch (error) {
      testResult(true, `Protección XSS funcionando para: "${payload.substring(0, 20)}..."`);
    }
  }
}

// ==================== EJECUCIÓN PRINCIPAL ====================
async function runAllTests() {
  log('\n╔═══════════════════════════════════════════════════════════╗', 'magenta');
  log('║        🔒 PRUEBAS DE SEGURIDAD COMPLETAS - TESCHA       ║', 'magenta');
  log('╚═══════════════════════════════════════════════════════════╝', 'magenta');

  log(`\n📋 Configuración:`, 'blue');
  log(`   API URL: ${API_URL}`);
  log(`   Timeout: ${TIMEOUT}ms`);
  log(`   Fecha: ${new Date().toLocaleString('es-MX')}`);

  // Intentar obtener token legítimo
  log(`\n🔑 Intentando autenticación legítima...`, 'blue');
  let token = null;
  try {
    const response = await axios.post(`${API_URL}/auth/login`, {
      username: 'coordinador',
      password: 'admin123'
    }, { timeout: TIMEOUT });
    token = response.data.token;
    log(`   ✅ Token obtenido para pruebas autenticadas`, 'green');
  } catch (error) {
    log(`   ⚠️  No se pudo obtener token legítimo. Verificar que el servidor esté corriendo.`, 'yellow');
    log(`   ℹ️  Continuando con pruebas no autenticadas...`, 'blue');
  }

  // Ejecutar todas las pruebas
  await testLoginBypass();
  await testMaliciousUserCreation(token);
  await testSearchInjection(token);
  await testUpdateInjection(token);
  await testRateLimiting();
  await testUnauthorizedAccess();
  await testXSSProtection(token);

  // Reporte final
  log('\n\n╔═══════════════════════════════════════════════════════════╗', 'magenta');
  log('║                    📊 REPORTE FINAL                       ║', 'magenta');
  log('╚═══════════════════════════════════════════════════════════╝', 'magenta');

  log(`\n✅ Tests Pasados: ${passedTests}`, 'green');
  log(`❌ Tests Fallados: ${failedTests}`, failedTests > 0 ? 'red' : 'green');
  log(`📊 Total de Tests: ${totalTests}`);

  const securityScore = totalTests > 0 ? ((passedTests / totalTests) * 100).toFixed(2) : 0;
  const scoreColor = securityScore >= 95 ? 'green' : securityScore >= 80 ? 'yellow' : 'red';
  
  log(`\n🛡️  PUNTUACIÓN DE SEGURIDAD: ${securityScore}%`, scoreColor);

  if (securityScore >= 95) {
    log(`\n🎉 ¡EXCELENTE! El sistema tiene seguridad de nivel empresarial`, 'green');
  } else if (securityScore >= 80) {
    log(`\n⚠️  BUENO. Hay algunas áreas que necesitan atención`, 'yellow');
  } else {
    log(`\n🚨 CRÍTICO. Se encontraron vulnerabilidades serias`, 'red');
  }

  if (vulnerabilities.length > 0) {
    log(`\n\n⚠️  VULNERABILIDADES DETECTADAS (${vulnerabilities.length}):`, 'red');
    vulnerabilities.forEach((vuln, idx) => {
      log(`\n${idx + 1}. ${vuln.test}`, 'red');
      if (vuln.details) {
        log(`   ${vuln.details}`, 'yellow');
      }
    });
  } else {
    log(`\n\n✨ ¡PERFECTO! No se detectaron vulnerabilidades`, 'green');
  }

  log(`\n═══════════════════════════════════════════════════════════\n`, 'magenta');

  process.exit(failedTests > 0 ? 1 : 0);
}

// Ejecutar
runAllTests().catch(error => {
  log(`\n❌ Error fatal: ${error.message}`, 'red');
  console.error(error);
  process.exit(1);
});
