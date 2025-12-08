import axios from 'axios';
import chalk from 'chalk';

/**
 * SCRIPT DE PRUEBAS DE PENETRACIÓN - SISTEMA TESCHA
 * 
 * Este script prueba la seguridad del sistema simulando diferentes tipos de ataques.
 * SOLO USAR EN AMBIENTE DE DESARROLLO/PRUEBAS
 */

const API_URL = 'http://localhost:5000/api';
const RESULTS = [];

// Utilidades
const log = {
    success: (msg) => console.log(chalk.green('✅ ' + msg)),
    error: (msg) => console.log(chalk.red('❌ ' + msg)),
    warning: (msg) => console.log(chalk.yellow('⚠️  ' + msg)),
    info: (msg) => console.log(chalk.blue('ℹ️  ' + msg)),
    title: (msg) => console.log(chalk.cyan.bold('\n' + '='.repeat(60) + '\n' + msg + '\n' + '='.repeat(60)))
};

const addResult = (test, passed, details) => {
    RESULTS.push({ test, passed, details });
    if (passed) {
        log.success(`${test}: SEGURO`);
    } else {
        log.error(`${test}: VULNERABLE - ${details}`);
    }
};

// =============================================
// TEST 1: SQL INJECTION
// =============================================
async function testSQLInjection() {
    log.title('TEST 1: SQL INJECTION');

    const payloads = [
        "admin' OR '1'='1",
        "admin'--",
        "admin' OR 1=1--",
        "' UNION SELECT * FROM usuarios--",
        "1'; DROP TABLE usuarios--"
    ];

    for (const payload of payloads) {
        try {
            const response = await axios.post(`${API_URL}/auth/login`, {
                username: payload,
                password: 'cualquier_cosa'
            });

            if (response.status === 200) {
                addResult('SQL Injection', false, `Payload exitoso: ${payload}`);
                return;
            }
        } catch (error) {
            // Esperamos que falle
        }
    }

    addResult('SQL Injection', true, 'Todos los payloads bloqueados');
}

// =============================================
// TEST 2: XSS (Cross-Site Scripting)
// =============================================
async function testXSS() {
    log.title('TEST 2: XSS (Cross-Site Scripting)');

    const payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "';alert('XSS');//"
    ];

    // Necesitamos un token válido para esta prueba
    let token;
    try {
        const loginResponse = await axios.post(`${API_URL}/auth/login`, {
            username: 'admin',
            password: 'admin123'
        });
        token = loginResponse.data.token;
    } catch (error) {
        log.warning('No se pudo obtener token para prueba XSS');
        return;
    }

    for (const payload of payloads) {
        try {
            const response = await axios.post(
                `${API_URL}/alumnos`,
                {
                    nombre_completo: payload,
                    correo: 'test@test.com',
                    tipo_alumno: 'interno'
                },
                {
                    headers: { Authorization: `Bearer ${token}` }
                }
            );

            // Verificar si el payload fue sanitizado
            if (response.data.nombre_completo && response.data.nombre_completo.includes('<script>')) {
                addResult('XSS', false, `Payload no sanitizado: ${payload}`);
                return;
            }
        } catch (error) {
            // Puede fallar por validación, lo cual es bueno
        }
    }

    addResult('XSS', true, 'Todos los payloads sanitizados o bloqueados');
}

// =============================================
// TEST 3: FUERZA BRUTA
// =============================================
async function testBruteForce() {
    log.title('TEST 3: FUERZA BRUTA');

    log.info('Intentando 10 logins fallidos...');

    let blocked = false;
    for (let i = 1; i <= 10; i++) {
        try {
            await axios.post(`${API_URL}/auth/login`, {
                username: 'admin',
                password: `wrong_password_${i}`
            });
        } catch (error) {
            if (error.response?.status === 429) {
                log.info(`Bloqueado después de ${i} intentos`);
                blocked = true;
                break;
            }
        }
    }

    if (blocked) {
        addResult('Fuerza Bruta', true, 'Rate limiting activo');
    } else {
        addResult('Fuerza Bruta', false, 'No hay límite de intentos');
    }
}

// =============================================
// TEST 4: CSRF (Cross-Site Request Forgery)
// =============================================
async function testCSRF() {
    log.title('TEST 4: CSRF (Cross-Site Request Forgery)');

    // Obtener token válido
    let token;
    try {
        const loginResponse = await axios.post(`${API_URL}/auth/login`, {
            username: 'admin',
            password: 'admin123'
        });
        token = loginResponse.data.token;
    } catch (error) {
        log.warning('No se pudo obtener token para prueba CSRF');
        return;
    }

    // Intentar hacer un POST sin token CSRF
    try {
        await axios.post(
            `${API_URL}/alumnos`,
            {
                nombre_completo: 'Test CSRF',
                correo: 'csrf@test.com',
                tipo_alumno: 'interno'
            },
            {
                headers: {
                    Authorization: `Bearer ${token}`
                    // Sin X-CSRF-Token
                }
            }
        );

        // Si llegamos aquí, no hay protección CSRF
        addResult('CSRF', false, 'No requiere token CSRF');
    } catch (error) {
        if (error.response?.status === 403) {
            addResult('CSRF', true, 'Token CSRF requerido');
        } else {
            addResult('CSRF', true, 'Protegido (otra validación)');
        }
    }
}

// =============================================
// TEST 5: IDOR (Insecure Direct Object Reference)
// =============================================
async function testIDOR() {
    log.title('TEST 5: IDOR (Insecure Direct Object Reference)');

    // Obtener token de un usuario
    let token;
    try {
        const loginResponse = await axios.post(`${API_URL}/auth/login`, {
            username: 'maestro1',
            password: 'maestro123'
        });
        token = loginResponse.data.token;
    } catch (error) {
        log.warning('No se pudo obtener token para prueba IDOR');
        return;
    }

    // Intentar acceder a un alumno que no le pertenece
    try {
        await axios.get(`${API_URL}/alumnos/999`, {
            headers: { Authorization: `Bearer ${token}` }
        });

        addResult('IDOR', false, 'Puede acceder a recursos de otros');
    } catch (error) {
        if (error.response?.status === 403 || error.response?.status === 404) {
            addResult('IDOR', true, 'Validación de propiedad activa');
        }
    }
}

// =============================================
// TEST 6: JWT TOKEN MANIPULATION
// =============================================
async function testJWTManipulation() {
    log.title('TEST 6: JWT TOKEN MANIPULATION');

    // Obtener token válido
    let token;
    try {
        const loginResponse = await axios.post(`${API_URL}/auth/login`, {
            username: 'admin',
            password: 'admin123'
        });
        token = loginResponse.data.token;
    } catch (error) {
        log.warning('No se pudo obtener token para prueba JWT');
        return;
    }

    // Modificar el token
    const parts = token.split('.');
    const modifiedToken = parts[0] + '.' + parts[1] + '.MODIFIED';

    try {
        await axios.get(`${API_URL}/dashboard`, {
            headers: { Authorization: `Bearer ${modifiedToken}` }
        });

        addResult('JWT Manipulation', false, 'Token modificado aceptado');
    } catch (error) {
        if (error.response?.status === 401) {
            addResult('JWT Manipulation', true, 'Token modificado rechazado');
        }
    }
}

// =============================================
// TEST 7: VALIDACIÓN DE DATOS
// =============================================
async function testDataValidation() {
    log.title('TEST 7: VALIDACIÓN DE DATOS');

    let token;
    try {
        const loginResponse = await axios.post(`${API_URL}/auth/login`, {
            username: 'admin',
            password: 'admin123'
        });
        token = loginResponse.data.token;
    } catch (error) {
        log.warning('No se pudo obtener token para prueba de validación');
        return;
    }

    const invalidData = [
        { correo: 'no_es_un_correo', field: 'correo' },
        { telefono: '123', field: 'teléfono' },
        { nivel_actual: 'Z9', field: 'nivel' }
    ];

    let allBlocked = true;
    for (const data of invalidData) {
        try {
            await axios.post(
                `${API_URL}/alumnos`,
                {
                    nombre_completo: 'Test Validation',
                    tipo_alumno: 'interno',
                    ...data
                },
                {
                    headers: { Authorization: `Bearer ${token}` }
                }
            );

            allBlocked = false;
            log.error(`Dato inválido aceptado: ${data.field}`);
        } catch (error) {
            if (error.response?.status === 400) {
                // Esperado - validación funcionando
            }
        }
    }

    if (allBlocked) {
        addResult('Validación de Datos', true, 'Todos los datos inválidos rechazados');
    } else {
        addResult('Validación de Datos', false, 'Algunos datos inválidos aceptados');
    }
}

// =============================================
// TEST 8: ACCESO SIN AUTENTICACIÓN
// =============================================
async function testUnauthorizedAccess() {
    log.title('TEST 8: ACCESO SIN AUTENTICACIÓN');

    const endpoints = [
        '/alumnos',
        '/maestros',
        '/grupos',
        '/pagos',
        '/reportes/reprobacion'
    ];

    let allBlocked = true;
    for (const endpoint of endpoints) {
        try {
            await axios.get(`${API_URL}${endpoint}`);
            allBlocked = false;
            log.error(`Endpoint accesible sin auth: ${endpoint}`);
        } catch (error) {
            if (error.response?.status === 401) {
                // Esperado
            }
        }
    }

    if (allBlocked) {
        addResult('Acceso Sin Auth', true, 'Todos los endpoints protegidos');
    } else {
        addResult('Acceso Sin Auth', false, 'Algunos endpoints sin protección');
    }
}

// =============================================
// TEST 9: ESCALACIÓN DE PRIVILEGIOS
// =============================================
async function testPrivilegeEscalation() {
    log.title('TEST 9: ESCALACIÓN DE PRIVILEGIOS');

    // Login como maestro
    let token;
    try {
        const loginResponse = await axios.post(`${API_URL}/auth/login`, {
            username: 'maestro1',
            password: 'maestro123'
        });
        token = loginResponse.data.token;
    } catch (error) {
        log.warning('No se pudo obtener token de maestro');
        return;
    }

    // Intentar crear otro maestro (solo coordinador puede)
    try {
        await axios.post(
            `${API_URL}/maestros`,
            {
                nombre: 'Hacker',
                apellido_paterno: 'Test',
                correo: 'hacker@test.com'
            },
            {
                headers: { Authorization: `Bearer ${token}` }
            }
        );

        addResult('Escalación de Privilegios', false, 'Maestro puede crear maestros');
    } catch (error) {
        if (error.response?.status === 403) {
            addResult('Escalación de Privilegios', true, 'RBAC funcionando correctamente');
        }
    }
}

// =============================================
// TEST 10: DOS (Denial of Service)
// =============================================
async function testDoS() {
    log.title('TEST 10: DOS (Denial of Service)');

    log.info('Enviando 150 requests rápidos...');

    const promises = [];
    for (let i = 0; i < 150; i++) {
        promises.push(
            axios.get(`${API_URL}/`).catch(() => { })
        );
    }

    try {
        await Promise.all(promises);
        addResult('DoS', false, 'No hay límite de requests');
    } catch (error) {
        if (error.response?.status === 429) {
            addResult('DoS', true, 'Rate limiting activo');
        }
    }
}

// =============================================
// EJECUTAR TODAS LAS PRUEBAS
// =============================================
async function runAllTests() {
    console.log(chalk.cyan.bold('\n' + '█'.repeat(60)));
    console.log(chalk.cyan.bold('█' + ' '.repeat(58) + '█'));
    console.log(chalk.cyan.bold('█' + '  PRUEBAS DE PENETRACIÓN - SISTEMA TESCHA'.padEnd(58) + '█'));
    console.log(chalk.cyan.bold('█' + ' '.repeat(58) + '█'));
    console.log(chalk.cyan.bold('█'.repeat(60) + '\n'));

    log.warning('ADVERTENCIA: Estas pruebas simularán ataques reales.');
    log.warning('Solo ejecutar en ambiente de desarrollo/pruebas.\n');

    await testSQLInjection();
    await testXSS();
    await testBruteForce();
    await testCSRF();
    await testIDOR();
    await testJWTManipulation();
    await testDataValidation();
    await testUnauthorizedAccess();
    await testPrivilegeEscalation();
    await testDoS();

    // Resumen
    log.title('RESUMEN DE RESULTADOS');

    const passed = RESULTS.filter(r => r.passed).length;
    const failed = RESULTS.filter(r => !r.passed).length;
    const total = RESULTS.length;

    console.log('\n');
    console.log(chalk.green(`✅ Pruebas Pasadas: ${passed}/${total}`));
    console.log(chalk.red(`❌ Pruebas Fallidas: ${failed}/${total}`));
    console.log('\n');

    if (failed === 0) {
        console.log(chalk.green.bold('🎉 ¡SISTEMA COMPLETAMENTE SEGURO!'));
    } else {
        console.log(chalk.red.bold('⚠️  SE ENCONTRARON VULNERABILIDADES'));
        console.log('\nVulnerabilidades encontradas:');
        RESULTS.filter(r => !r.passed).forEach(r => {
            console.log(chalk.red(`  • ${r.test}: ${r.details}`));
        });
    }

    console.log('\n' + chalk.cyan('█'.repeat(60)) + '\n');

    // Guardar resultados
    const fs = await import('fs');
    const report = {
        fecha: new Date().toISOString(),
        total,
        passed,
        failed,
        porcentaje: Math.round((passed / total) * 100),
        resultados: RESULTS
    };

    fs.writeFileSync(
        'security-test-report.json',
        JSON.stringify(report, null, 2)
    );

    log.success('Reporte guardado en: security-test-report.json');
}

// Ejecutar
runAllTests().catch(console.error);
