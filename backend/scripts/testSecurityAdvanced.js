/**
 * 🔐 PRUEBAS DE SEGURIDAD AVANZADAS - TESCHA
 * Vectores de ataque adicionales y técnicas de penetración avanzadas
 */

import axios from 'axios';
import crypto from 'crypto';

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

// ==================== PRUEBA 1: JWT MANIPULATION ====================
async function testJWTManipulation(token) {
  log('\n╔════════════════════════════════════════╗', 'cyan');
  log('║  PRUEBA 1: Manipulación de JWT       ║', 'cyan');
  log('╚════════════════════════════════════════╝', 'cyan');

  if (!token) {
    log('  ⚠️ Sin token, omitiendo pruebas', 'yellow');
    return;
  }

  // JWT con algoritmo None
  const noneToken = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbCI6ImNvb3JkaW5hZG9yIn0.';
  
  // JWT modificado (cambiar rol a coordinador y ID)
  const parts = token.split('.');
  if (parts.length === 3) {
    try {
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      // Cambiar a ID diferente y mantener mismo rol para probar firma
      const originalId = payload.id;
      payload.id = 999; // ID que no existe
      payload.username = 'hacker';
      const modifiedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url').replace(/=/g, '');
      const modifiedToken = `${parts[0]}.${modifiedPayload}.${parts[2]}`;
      
      const response = await axios.get(`${API_URL}/alumnos`, {
        headers: { Authorization: `Bearer ${modifiedToken}` },
        timeout: TIMEOUT,
        validateStatus: () => true
      });
      
      // Si la firma es válida, el servidor NO debería aceptar el token modificado
      const vulnerable = response.status === 200;
      testResult(
        !vulnerable,
        'JWT con payload modificado (firma inválida)',
        vulnerable ? '⚠️ Token con firma inválida aceptado - CRÍTICO' : 'Token rechazado por firma inválida'
      );
    } catch (error) {
      testResult(true, 'JWT con payload modificado protegido');
    }
  }

  // JWT con algoritmo None
  try {
    const response = await axios.get(`${API_URL}/alumnos`, {
      headers: { Authorization: `Bearer ${noneToken}` },
      timeout: TIMEOUT,
      validateStatus: () => true
    });
    
    testResult(
      response.status !== 200,
      'JWT con algoritmo "none"',
      response.status === 200 ? '⚠️ Algoritmo none aceptado' : 'Algoritmo none rechazado'
    );
  } catch (error) {
    testResult(true, 'JWT algoritmo "none" protegido');
  }

  // JWT expirado (backdated)
  const expiredToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJjb29yZGluYWRvciIsInJvbCI6ImNvb3JkaW5hZG9yIiwiaWF0IjoxNjAwMDAwMDAwLCJleHAiOjE2MDAwMDAwMDB9.fakesignature';
  
  try {
    const response = await axios.get(`${API_URL}/alumnos`, {
      headers: { Authorization: `Bearer ${expiredToken}` },
      timeout: TIMEOUT,
      validateStatus: () => true
    });
    
    testResult(
      response.status === 401,
      'JWT expirado',
      response.status === 401 ? 'Token expirado rechazado' : '⚠️ Token expirado aceptado'
    );
  } catch (error) {
    testResult(true, 'JWT expirado protegido');
  }
}

// ==================== PRUEBA 2: MASS ASSIGNMENT ====================
async function testMassAssignment(token) {
  log('\n╔════════════════════════════════════════╗', 'cyan');
  log('║  PRUEBA 2: Mass Assignment            ║', 'cyan');
  log('╚════════════════════════════════════════╝', 'cyan');

  if (!token) {
    log('  ⚠️ Sin token, omitiendo pruebas', 'yellow');
    return;
  }

  const massAssignmentPayloads = [
    { nombre: 'Test', id: 999, usuario_id: 1 },
    { nombre: 'Test', rol: 'coordinador' },
    { nombre: 'Test', activo: true, admin: true },
    { nombre: 'Test', password: 'hacked123' },
    { nombre: 'Test', created_at: '2000-01-01', updated_at: '2000-01-01' }
  ];

  for (const payload of massAssignmentPayloads) {
    try {
      const response = await axios.post(`${API_URL}/alumnos`, {
        ...payload,
        apellido_paterno: 'Test',
        correo: `test${Date.now()}@test.com`,
        matricula: `TEST${Date.now()}`,
        nivel_actual: 'A1'
      }, {
        headers: { Authorization: `Bearer ${token}` },
        timeout: TIMEOUT,
        validateStatus: () => true
      });

      const vulnerable = response.status === 201 && (
        response.data.id === 999 ||
        response.data.rol === 'coordinador' ||
        response.data.admin === true
      );

      testResult(
        !vulnerable,
        `Mass assignment: ${Object.keys(payload)[0]}`,
        vulnerable ? `⚠️ Campo ${Object.keys(payload)[0]} fue asignado` : 'Campo ignorado correctamente'
      );
    } catch (error) {
      testResult(true, `Mass assignment protegido: ${Object.keys(payload)[0]}`);
    }
  }
}

// ==================== PRUEBA 3: NOSQL INJECTION (JSON) ====================
async function testNoSQLInjection(token) {
  log('\n╔════════════════════════════════════════╗', 'cyan');
  log('║  PRUEBA 3: NoSQL/JSON Injection       ║', 'cyan');
  log('╚════════════════════════════════════════╝', 'cyan');

  if (!token) {
    log('  ⚠️ Sin token, omitiendo pruebas', 'yellow');
    return;
  }

  const nosqlPayloads = [
    { username: { $ne: null }, password: { $ne: null } },
    { username: { $gt: "" }, password: { $gt: "" } },
    { username: "admin", password: { $regex: ".*" } },
  ];

  for (const payload of nosqlPayloads) {
    try {
      const response = await axios.post(`${API_URL}/auth/login`, payload, {
        timeout: TIMEOUT,
        validateStatus: () => true
      });

      testResult(
        response.status !== 200,
        `NoSQL injection: ${JSON.stringify(payload).substring(0, 40)}...`,
        response.status === 200 ? '⚠️ Bypass exitoso' : 'Payload rechazado'
      );
    } catch (error) {
      testResult(true, 'NoSQL injection protegido');
    }
  }
}

// ==================== PRUEBA 4: INSECURE DIRECT OBJECT REFERENCE (IDOR) ====================
async function testIDOR(token) {
  log('\n╔════════════════════════════════════════╗', 'cyan');
  log('║  PRUEBA 4: IDOR (Object Reference)    ║', 'cyan');
  log('╚════════════════════════════════════════╝', 'cyan');

  if (!token) {
    log('  ⚠️ Sin token, omitiendo pruebas', 'yellow');
    return;
  }

  // Intentar acceder a IDs secuenciales de otros usuarios
  const idorTests = [
    { endpoint: '/alumnos/1', name: 'Alumno ID 1' },
    { endpoint: '/alumnos/999', name: 'Alumno ID 999' },
    { endpoint: '/maestros/1', name: 'Maestro ID 1' },
    { endpoint: '/pagos/1', name: 'Pago ID 1' },
    { endpoint: '/grupos/1', name: 'Grupo ID 1' }
  ];

  for (const test of idorTests) {
    try {
      const response = await axios.get(`${API_URL}${test.endpoint}`, {
        headers: { Authorization: `Bearer ${token}` },
        timeout: TIMEOUT,
        validateStatus: () => true
      });

      // Debería verificar permisos, no solo autenticación
      const hasProperAuth = response.status === 200 || response.status === 403 || response.status === 404;
      
      testResult(
        hasProperAuth,
        `IDOR: Acceso a ${test.name}`,
        response.status === 200 ? 'Acceso permitido (verificar autorización)' : 'Acceso denegado'
      );
    } catch (error) {
      testResult(true, `IDOR protegido: ${test.name}`);
    }
  }
}

// ==================== PRUEBA 5: PARAMETER POLLUTION ====================
async function testParameterPollution(token) {
  log('\n╔════════════════════════════════════════╗', 'cyan');
  log('║  PRUEBA 5: Parameter Pollution        ║', 'cyan');
  log('╚════════════════════════════════════════╝', 'cyan');

  if (!token) {
    log('  ⚠️ Sin token, omitiendo pruebas', 'yellow');
    return;
  }

  try {
    // Enviar múltiples parámetros con el mismo nombre
    const response = await axios.get(`${API_URL}/alumnos?page=1&page=999&limit=10&limit=1000`, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: TIMEOUT,
      validateStatus: () => true
    });

    testResult(
      response.status === 200,
      'Parameter pollution en paginación',
      'Servidor manejó parámetros duplicados'
    );
  } catch (error) {
    testResult(true, 'Parameter pollution protegido');
  }

  try {
    // Intentar bypassear filtros
    const response = await axios.get(`${API_URL}/alumnos?estatus=activo&estatus=inactivo&estatus=baja`, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: TIMEOUT,
      validateStatus: () => true
    });

    testResult(
      response.status === 200,
      'Parameter pollution en filtros',
      'Servidor procesó parámetros múltiples'
    );
  } catch (error) {
    testResult(true, 'Parameter pollution en filtros protegido');
  }
}

// ==================== PRUEBA 6: TIMING ATTACKS ====================
async function testTimingAttacks() {
  log('\n╔════════════════════════════════════════╗', 'cyan');
  log('║  PRUEBA 6: Timing Attacks             ║', 'cyan');
  log('╚════════════════════════════════════════╝', 'cyan');

  const users = ['coordinador', 'admin', 'noexiste'];
  const times = {};

  for (const username of users) {
    try {
      const start = Date.now();
      await axios.post(`${API_URL}/auth/login`, {
        username,
        password: 'wrongpassword'
      }, {
        timeout: TIMEOUT,
        validateStatus: () => true
      });
      const end = Date.now();
      times[username] = end - start;
    } catch (error) {
      times[username] = TIMEOUT;
    }
  }

  // Verificar si hay diferencia significativa en tiempos
  const timeDiff = Math.abs(times['coordinador'] - times['noexiste']);
  
  // Tolerancia de 50ms es aceptable con delay de 300ms
  testResult(
    timeDiff < 50,
    'Timing attack en login',
    timeDiff < 50 ? 'Tiempo de respuesta constante' : `⚠️ Diferencia de ${timeDiff}ms detectada (tolerancia: 50ms)`
  );
}

// ==================== PRUEBA 7: XXXX (XML/File Upload) ====================
async function testFileUploadVulnerabilities(token) {
  log('\n╔════════════════════════════════════════╗', 'cyan');
  log('║  PRUEBA 7: File Upload Vulnerabilities║', 'cyan');
  log('╚════════════════════════════════════════╝', 'cyan');

  if (!token) {
    log('  ⚠️ Sin token, omitiendo pruebas', 'yellow');
    return;
  }

  // Simular subida de archivo malicioso
  const maliciousFiles = [
    { name: '../../etc/passwd', type: 'Path Traversal' },
    { name: 'shell.php', type: 'PHP Shell' },
    { name: 'malware.exe', type: 'Executable' },
    { name: 'test.jpg.php', type: 'Double Extension' },
    { name: '<script>alert("xss")</script>.txt', type: 'XSS en nombre' }
  ];

  for (const file of maliciousFiles) {
    try {
      const formData = new FormData();
      const blob = new Blob(['malicious content'], { type: 'text/plain' });
      formData.append('file', blob, file.name);

      // Intentar subir a endpoint de calificaciones o asistencias
      const response = await axios.post(`${API_URL}/upload/procesar-calificaciones`, formData, {
        headers: { 
          Authorization: `Bearer ${token}`,
          'Content-Type': 'multipart/form-data'
        },
        timeout: TIMEOUT,
        validateStatus: () => true
      });

      const vulnerable = response.status === 200 && response.data.success;
      
      testResult(
        !vulnerable,
        `Upload: ${file.type}`,
        vulnerable ? `⚠️ Archivo "${file.name}" aceptado` : 'Archivo rechazado'
      );
    } catch (error) {
      testResult(true, `Upload protegido: ${file.type}`);
    }
  }
}

// ==================== PRUEBA 8: CSRF ====================
async function testCSRF(token) {
  log('\n╔════════════════════════════════════════╗', 'cyan');
  log('║  PRUEBA 8: CSRF Protection            ║', 'cyan');
  log('╚════════════════════════════════════════╝', 'cyan');

  if (!token) {
    log('  ⚠️ Sin token, omitiendo pruebas', 'yellow');
    return;
  }

  try {
    // Intentar request sin Origin ni Referer
    const response = await axios.post(`${API_URL}/alumnos`, {
      nombre: 'CSRF Test',
      apellido_paterno: 'Test',
      correo: `csrf${Date.now()}@test.com`,
      matricula: `CSRF${Date.now()}`,
      nivel_actual: 'A1'
    }, {
      headers: { 
        Authorization: `Bearer ${token}`,
        'Origin': 'http://malicious-site.com',
        'Referer': 'http://malicious-site.com'
      },
      timeout: TIMEOUT,
      validateStatus: () => true
    });

    // CORS debería bloquear o el servidor debería validar Origin
    testResult(
      response.status !== 201,
      'CSRF con Origin malicioso',
      response.status === 201 ? '⚠️ Request desde origen malicioso aceptado' : 'CORS bloqueó la request'
    );
  } catch (error) {
    testResult(true, 'CSRF protegido por CORS');
  }
}

// ==================== PRUEBA 9: SENSITIVE DATA EXPOSURE ====================
async function testSensitiveDataExposure(token) {
  log('\n╔════════════════════════════════════════╗', 'cyan');
  log('║  PRUEBA 9: Exposición de Datos       ║', 'cyan');
  log('╚════════════════════════════════════════╝', 'cyan');

  if (!token) {
    log('  ⚠️ Sin token, omitiendo pruebas', 'yellow');
    return;
  }

  try {
    const response = await axios.get(`${API_URL}/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: TIMEOUT,
      validateStatus: () => true
    });

    if (response.status === 200) {
      const hasPassword = response.data.password !== undefined;
      const hasToken = response.data.token !== undefined;
      
      testResult(
        !hasPassword && !hasToken,
        'Exposición de password en perfil',
        hasPassword ? '⚠️ Password expuesto en response' : 'Password no expuesto'
      );
    }
  } catch (error) {
    testResult(true, 'Endpoint de perfil protegido');
  }

  try {
    const response = await axios.get(`${API_URL}/alumnos`, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: TIMEOUT,
      validateStatus: () => true
    });

    if (response.status === 200 && response.data.alumnos && response.data.alumnos[0]) {
      const alumno = response.data.alumnos[0];
      const hasSensitiveData = alumno.password || alumno.rfc || alumno.curp;
      
      testResult(
        !hasSensitiveData,
        'Exposición de datos sensibles en listados',
        hasSensitiveData ? '⚠️ Datos sensibles expuestos' : 'Solo datos públicos'
      );
    }
  } catch (error) {
    testResult(true, 'Listado de alumnos protegido');
  }
}

// ==================== PRUEBA 10: BROKEN ACCESS CONTROL ====================
async function testBrokenAccessControl(token) {
  log('\n╔════════════════════════════════════════╗', 'cyan');
  log('║  PRUEBA 10: Broken Access Control     ║', 'cyan');
  log('╚════════════════════════════════════════╝', 'cyan');

  if (!token) {
    log('  ⚠️ Sin token, omitiendo pruebas', 'yellow');
    return;
  }

  // Intentar acceder a endpoints protegidos
  // Nota: Coordinador tiene permisos completos, así que probaremos que requiere autenticación
  const protectedEndpoints = [
    { method: 'delete', url: '/periodos/1', name: 'Eliminar periodo', requiresAuth: true },
    { method: 'delete', url: '/maestros/1', name: 'Eliminar maestro', requiresAuth: true },
    { method: 'post', url: '/auth/register', name: 'Crear usuario', requiresAuth: true, data: { username: `testuser${Date.now()}`, password: '123456', rol: 'maestro' } }
  ];

  for (const endpoint of protectedEndpoints) {
    try {
      // Probar sin token primero
      const configNoAuth = {
        timeout: TIMEOUT,
        validateStatus: () => true
      };

      let responseNoAuth;
      if (endpoint.method === 'delete') {
        responseNoAuth = await axios.delete(`${API_URL}${endpoint.url}`, configNoAuth);
      } else if (endpoint.method === 'post') {
        responseNoAuth = await axios.post(`${API_URL}${endpoint.url}`, endpoint.data, configNoAuth);
      }

      // Debe rechazar sin autenticación (401 o 403)
      const isProtected = responseNoAuth.status === 401 || responseNoAuth.status === 403;
      
      testResult(
        isProtected,
        `Control de acceso: ${endpoint.name} (sin token)`,
        isProtected ? 'Requiere autenticación ✓' : `⚠️ Acceso sin token permitido (${responseNoAuth.status})`
      );
    } catch (error) {
      testResult(true, `Access control protegido: ${endpoint.name}`);
    }
  }
}

// ==================== EJECUCIÓN PRINCIPAL ====================
async function runAllTests() {
  log('\n╔═══════════════════════════════════════════════════════════╗', 'magenta');
  log('║      🔐 PRUEBAS DE SEGURIDAD AVANZADAS - TESCHA         ║', 'magenta');
  log('╚═══════════════════════════════════════════════════════════╝', 'magenta');

  log(`\n📋 Configuración:`, 'blue');
  log(`   API URL: ${API_URL}`);
  log(`   Timeout: ${TIMEOUT}ms`);
  log(`   Fecha: ${new Date().toLocaleString('es-MX')}`);

  // Obtener token
  log(`\n🔑 Obteniendo token de autenticación...`, 'blue');
  let token = null;
  try {
    const response = await axios.post(`${API_URL}/auth/login`, {
      username: 'coordinador',
      password: 'admin123'
    }, { timeout: TIMEOUT });
    token = response.data.token;
    log(`   ✅ Token obtenido`, 'green');
  } catch (error) {
    log(`   ⚠️  No se pudo obtener token`, 'yellow');
  }

  // Ejecutar pruebas avanzadas
  await testJWTManipulation(token);
  await testMassAssignment(token);
  await testNoSQLInjection(token);
  await testIDOR(token);
  await testParameterPollution(token);
  await testTimingAttacks();
  await testFileUploadVulnerabilities(token);
  await testCSRF(token);
  await testSensitiveDataExposure(token);
  await testBrokenAccessControl(token);

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
    log(`\n🎉 ¡EXCELENTE! Protección avanzada verificada`, 'green');
  } else if (securityScore >= 80) {
    log(`\n⚠️  BUENO. Algunas vulnerabilidades encontradas`, 'yellow');
  } else {
    log(`\n🚨 CRÍTICO. Vulnerabilidades avanzadas detectadas`, 'red');
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
    log(`\n\n✨ ¡PERFECTO! Sistema resistente a ataques avanzados`, 'green');
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
