import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

console.log('🧪 Probando envío de email...\n');

console.log('Configuración:');
console.log('SMTP_HOST:', process.env.SMTP_HOST);
console.log('SMTP_PORT:', process.env.SMTP_PORT);
console.log('SMTP_USER:', process.env.SMTP_USER);
console.log('SMTP_PASS:', process.env.SMTP_PASS ? '***configurado***' : '❌ NO CONFIGURADO');
console.log('SECURITY_ALERT_EMAIL:', process.env.SECURITY_ALERT_EMAIL);
console.log('');

async function testEmail() {
    try {
        const transporter = nodemailer.createTransporter({
            host: process.env.SMTP_HOST,
            port: parseInt(process.env.SMTP_PORT),
            secure: true,
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS
            }
        });

        console.log('📧 Enviando email de prueba...');

        const info = await transporter.sendMail({
            from: process.env.SMTP_USER,
            to: process.env.SECURITY_ALERT_EMAIL,
            subject: '🧪 PRUEBA - Sistema de Alertas TESCHA',
            html: `
        <h2>✅ Prueba de Email - Sistema TESCHA</h2>
        <p>Este es un email de prueba del sistema de alertas de seguridad.</p>
        <p><strong>Si recibes este email, el sistema está configurado correctamente.</strong></p>
        <hr>
        <h3>Configuración Actual:</h3>
        <ul>
          <li>SMTP Host: ${process.env.SMTP_HOST}</li>
          <li>SMTP Port: ${process.env.SMTP_PORT}</li>
          <li>Email de alertas: ${process.env.SECURITY_ALERT_EMAIL}</li>
        </ul>
        <hr>
        <p><small>Este es un mensaje de prueba del Sistema de Seguridad TESCHA</small></p>
      `
        });

        console.log('✅ Email enviado exitosamente!');
        console.log('Message ID:', info.messageId);
        console.log('');
        console.log('📬 Verifica tu email:', process.env.SECURITY_ALERT_EMAIL);
        console.log('');
        console.log('Si no lo ves, revisa:');
        console.log('  1. Carpeta de SPAM');
        console.log('  2. Que el email sea correcto');
        console.log('  3. Que la contraseña de aplicación sea válida');

    } catch (error) {
        console.error('❌ Error al enviar email:');
        console.error('Mensaje:', error.message);
        console.error('');
        console.error('Posibles causas:');
        console.error('  1. Contraseña de aplicación incorrecta');
        console.error('  2. Email SMTP incorrecto');
        console.error('  3. Puerto bloqueado por firewall');
        console.error('  4. Verificación en 2 pasos no activada en Gmail');
        console.error('');
        console.error('Error completo:', error);
    }
}

testEmail();
