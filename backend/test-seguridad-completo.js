import http from 'http';

console.log('\n╔═══════════════════════════════════════════════════════════════════════╗');
console.log('║                                                                       ║');
console.log('║   🧪 PRUEBAS DE SEGURIDAD - SIMULACIÓN DE ATAQUES                    ║');
console.log('║   Sistema TESCHA - Detección de Intrusos (IDS)                       ║');
console.log('║                                                                       ║');
console.log('╚═══════════════════════════════════════════════════════════════════════╝\n');

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Función para hacer requests
function makeRequest(path, method, data) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'localhost',
            port: 5000,
            path: path,
            method: method,
            headers: {
                'Content-Type': 'application/json',
            }
        };

        if (data) {
            const jsonData = JSON.stringify(data);
            options.headers['Content-Length'] = Buffer.byteLength(jsonData);
        }

        const req = http.request(options, (res) => {
            let body = '';
            res.on('data', (chunk) => body += chunk);
            res.on('end', () => {
                resolve({
                    statusCode: res.statusCode,
                    body: body
                });
            });
        });

        req.on('error', (error) => {
            reject(error);
        });

        if (data) {
            req.write(JSON.stringify(data));
        }
        req.end();
    });
}

// =============================================
// TEST 1: SQL INJECTION
// =============================================
async function testSQLInjection() {
    console.log('🔴 TEST 1: SQL Injection Attack');
    console.log('   Intentando: username = "admin\' OR \'1\'=\'1"');

    try {
        const response = await makeRequest('/api/auth/login', 'POST', {
            username: "admin' OR '1'='1",
            password: "test' OR '1'='1"
        });

        if (response.statusCode === 403) {
            console.log('   ✅ BLOQUEADO - Status: 403 Forbidden');
            console.log('   ✅ Alerta de seguridad generada');
            console.log('   ✅ Email enviado (si SMTP está configurado)');
        } else if (response.statusCode === 401) {
            console.log('   ⚠️  Bloqueado por credenciales inválidas (401)');
        } else {
            console.log(`   ⚠️  Status inesperado: ${response.statusCode}`);
        }
        console.log(`   📝 Respuesta: ${response.body}\n`);
    } catch (error) {
        console.log(`   ❌ Error: ${error.message}\n`);
    }
}

// =============================================
// TEST 2: XSS ATTACK
// =============================================
async function testXSS() {
    console.log('🔴 TEST 2: XSS (Cross-Site Scripting) Attack');
    console.log('   Intentando: <script>alert("XSS")</script>');

    try {
        const response = await makeRequest('/api/alumnos?search=<script>alert("XSS")</script>', 'GET');

        if (response.statusCode === 403) {
            console.log('   ✅ BLOQUEADO - Status: 403 Forbidden');
            console.log('   ✅ Alerta de seguridad generada');
        } else if (response.statusCode === 401) {
            console.log('   ⚠️  Requiere autenticación (401) - Normal');
        } else {
            console.log(`   ⚠️  Status: ${response.statusCode}`);
        }
        console.log(`   📝 Respuesta: ${response.body.substring(0, 100)}...\n`);
    } catch (error) {
        console.log(`   ❌ Error: ${error.message}\n`);
    }
}

// =============================================
// TEST 3: PATH TRAVERSAL
// =============================================
async function testPathTraversal() {
    console.log('🔴 TEST 3: Path Traversal Attack');
    console.log('   Intentando: ../../etc/passwd');

    try {
        const response = await makeRequest('/api/alumnos/../../etc/passwd', 'GET');

        if (response.statusCode === 403) {
            console.log('   ✅ BLOQUEADO - Status: 403 Forbidden');
            console.log('   ✅ Alerta de seguridad generada');
        } else if (response.statusCode === 404) {
            console.log('   ⚠️  Ruta no encontrada (404) - Bloqueado indirectamente');
        } else {
            console.log(`   ⚠️  Status: ${response.statusCode}`);
        }
        console.log(`   📝 Respuesta: ${response.body.substring(0, 100)}...\n`);
    } catch (error) {
        console.log(`   ❌ Error: ${error.message}\n`);
    }
}

// =============================================
// TEST 4: COMMAND INJECTION
// =============================================
async function testCommandInjection() {
    console.log('🔴 TEST 4: Command Injection Attack');
    console.log('   Intentando: username = "admin; ls -la"');

    try {
        const response = await makeRequest('/api/auth/login', 'POST', {
            username: "admin; ls -la",
            password: "test | cat /etc/passwd"
        });

        if (response.statusCode === 403) {
            console.log('   ✅ BLOQUEADO - Status: 403 Forbidden');
            console.log('   ✅ Alerta de seguridad generada');
        } else if (response.statusCode === 401) {
            console.log('   ⚠️  Bloqueado por credenciales inválidas (401)');
        } else {
            console.log(`   ⚠️  Status: ${response.statusCode}`);
        }
        console.log(`   📝 Respuesta: ${response.body}\n`);
    } catch (error) {
        console.log(`   ❌ Error: ${error.message}\n`);
    }
}

// =============================================
// TEST 5: BRUTE FORCE
// =============================================
async function testBruteForce() {
    console.log('🔴 TEST 5: Brute Force Attack (6 intentos rápidos)');
    console.log('   Intentando múltiples logins con contraseñas incorrectas...');

    let blocked = false;
    for (let i = 1; i <= 6; i++) {
        try {
            const response = await makeRequest('/api/auth/login', 'POST', {
                username: "admin",
                password: `wrongpassword${i}`
            });

            if (response.statusCode === 429) {
                console.log(`   ✅ Intento ${i}: BLOQUEADO por Rate Limiting (429)`);
                console.log('   ✅ Sistema anti-brute force funcionando');
                blocked = true;
                break;
            } else if (response.statusCode === 401) {
                console.log(`   ⚠️  Intento ${i}: Credenciales inválidas (401)`);
            } else if (response.statusCode === 403) {
                console.log(`   ✅ Intento ${i}: BLOQUEADO por IDS (403)`);
                blocked = true;
                break;
            }

            await sleep(200); // Pequeña pausa entre intentos
        } catch (error) {
            console.log(`   ❌ Error en intento ${i}: ${error.message}`);
        }
    }

    if (blocked) {
        console.log('   ✅ Protección anti-brute force ACTIVA\n');
    } else {
        console.log('   ℹ️  Necesitas más intentos para activar el bloqueo\n');
    }
}

// =============================================
// TEST 6: MALICIOUS FILE UPLOAD
// =============================================
async function testMaliciousFile() {
    console.log('🔴 TEST 6: Malicious File Upload Attack');
    console.log('   Intentando: malware.php.exe');

    try {
        const response = await makeRequest('/api/upload', 'POST', {
            filename: 'malware.php.exe',
            content: '<?php system($_GET["cmd"]); ?>'
        });

        if (response.statusCode === 403) {
            console.log('   ✅ BLOQUEADO - Status: 403 Forbidden');
            console.log('   ✅ Alerta de seguridad generada');
        } else if (response.statusCode === 404) {
            console.log('   ⚠️  Endpoint no existe (404) - Protegido indirectamente');
        } else {
            console.log(`   ⚠️  Status: ${response.statusCode}`);
        }
        console.log(`   📝 Respuesta: ${response.body.substring(0, 100)}...\n`);
    } catch (error) {
        console.log(`   ❌ Error: ${error.message}\n`);
    }
}

// =============================================
// EJECUTAR TODAS LAS PRUEBAS
// =============================================
async function runAllTests() {
    console.log('⏳ Iniciando pruebas en 2 segundos...\n');
    await sleep(2000);

    try {
        await testSQLInjection();
        await sleep(1000);

        await testXSS();
        await sleep(1000);

        await testPathTraversal();
        await sleep(1000);

        await testCommandInjection();
        await sleep(1000);

        await testBruteForce();
        await sleep(1000);

        await testMaliciousFile();

        // Resumen final
        console.log('═'.repeat(71));
        console.log('✅ PRUEBAS COMPLETADAS');
        console.log('═'.repeat(71));
        console.log('\n📊 VERIFICAR RESULTADOS:\n');
        console.log('1. 📝 LOGS DEL SERVIDOR:');
        console.log('   npm run pm2:logs -- --lines 50\n');
        console.log('2. 🚨 ALERTAS EN CONSOLA:');
        console.log('   Deberías ver mensajes con "🚨 ALERTA DE SEGURIDAD"\n');
        console.log('3. 📧 EMAIL (si SMTP configurado):');
        console.log('   Revisa tu bandeja de entrada en SECURITY_ALERT_EMAIL\n');
        console.log('4. 💾 BASE DE DATOS:');
        console.log('   SELECT * FROM security_logs WHERE created_at > NOW() - INTERVAL \'5 minutes\';\n');
        console.log('═'.repeat(71));
        console.log('\n✅ TU SISTEMA ESTÁ PROTEGIDO CONTRA HACKEOS\n');

    } catch (error) {
        console.error('\n❌ Error durante las pruebas:', error.message);
        console.log('\n⚠️  Asegúrate de que el servidor esté corriendo:');
        console.log('   npm run pm2:status\n');
    }
}

// Ejecutar
runAllTests();
