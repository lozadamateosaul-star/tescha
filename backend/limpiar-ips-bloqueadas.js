import { unblockIP } from './services/intrusionDetection.js';

console.log('🔓 Limpiando IPs bloqueadas...\n');

// Limpiar localhost
const ipsToUnblock = ['::1', '127.0.0.1', 'localhost', '::ffff:127.0.0.1'];

ipsToUnblock.forEach(ip => {
    try {
        unblockIP(ip);
        console.log(`✅ IP desbloqueada: ${ip}`);
    } catch (error) {
        console.log(`⚠️  ${ip}: ${error.message}`);
    }
});

console.log('\n✅ Limpieza completada');
console.log('💡 Reinicia el servidor: npm run pm2:restart\n');
