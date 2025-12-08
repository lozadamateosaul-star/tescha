// PRUEBA SIMPLE DE ATAQUE SQL INJECTION
console.log('\n🧪 PRUEBA DE SEGURIDAD - SQL INJECTION\n');

const http = require('http');

const data = JSON.stringify({
    username: "admin' OR '1'='1",
    password: "test"
});

const options = {
    hostname: 'localhost',
    port: 5000,
    path: '/api/auth/login',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': data.length
    }
};

const req = http.request(options, (res) => {
    console.log(`📊 Status Code: ${res.statusCode}`);

    if (res.statusCode === 403) {
        console.log('✅ ¡ATAQUE BLOQUEADO!');
        console.log('✅ El sistema detectó el intento de SQL Injection');
        console.log('\n📧 Verifica:');
        console.log('   1. Los logs del servidor (npm run pm2:logs)');
        console.log('   2. Tu email (si configuraste SMTP)');
        console.log('   3. La base de datos (tabla security_logs)');
    } else if (res.statusCode === 401) {
        console.log('⚠️  Credenciales inválidas (esperado)');
    } else {
        console.log('⚠️  Respuesta inesperada');
    }

    let body = '';
    res.on('data', (chunk) => {
        body += chunk;
    });

    res.on('end', () => {
        console.log('\n📝 Respuesta:', body);
        console.log('\n✅ Prueba completada\n');
    });
});

req.on('error', (error) => {
    console.error('❌ Error:', error.message);
    console.log('\n⚠️  Asegúrate de que el servidor esté corriendo:');
    console.log('   npm run pm2:status');
});

req.write(data);
req.end();
