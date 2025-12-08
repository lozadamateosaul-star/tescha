import axios from 'axios';

const API_URL = 'http://localhost:5000/api';

console.log('\n🔥 INICIANDO PRUEBAS DE SEGURIDAD CON ALERTAS\n');

async function testSecurityAlerts() {
    try {
        // Test 1: Email de prueba básico
        console.log('📧 TEST 1: Enviando email de prueba...');
        const emailTest = await axios.post(`${API_URL}/security-test/test-email`);
        console.log('✅', emailTest.data.message);
        console.log('');

        await sleep(2000);

        // Test 2: Simular SQL Injection
        console.log('💉 TEST 2: Simulando ataque SQL Injection...');
        const sqlTest = await axios.post(`${API_URL}/security-test/simulate-attack`, {
            type: 'SQL_INJECTION',
            severity: 'CRITICAL'
        });
        console.log('✅', sqlTest.data.message);
        console.log('');

        await sleep(2000);

        // Test 3: Simular XSS
        console.log('⚠️  TEST 3: Simulando ataque XSS...');
        const xssTest = await axios.post(`${API_URL}/security-test/simulate-attack`, {
            type: 'XSS_ATTACK',
            severity: 'HIGH'
        });
        console.log('✅', xssTest.data.message);
        console.log('');

        await sleep(2000);

        // Test 4: Simular Brute Force
        console.log('🔨 TEST 4: Simulando ataque de Fuerza Bruta...');
        const bruteTest = await axios.post(`${API_URL}/security-test/simulate-attack`, {
            type: 'BRUTE_FORCE',
            severity: 'HIGH'
        });
        console.log('✅', bruteTest.data.message);
        console.log('');

        console.log('\n' + '='.repeat(60));
        console.log('✅ TODAS LAS PRUEBAS COMPLETADAS');
        console.log('='.repeat(60));
        console.log('\n📬 Revisa tu email (laloquiroz7@gmail.com)');
        console.log('   Deberías tener 4 emails de alerta de seguridad\n');

    } catch (error) {
        console.error('\n❌ ERROR:', error.response?.data || error.message);
        if (error.response?.data?.stack) {
            console.error('\n📋 Stack:', error.response.data.stack);
        }
    }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Ejecutar pruebas
testSecurityAlerts();
