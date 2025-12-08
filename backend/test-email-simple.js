const nodemailer = require('nodemailer');
require('dotenv').config();

console.log('🧪 Probando envío de email de alerta...\n');

async function testEmail() {
    try {
        console.log('📧 Configuración:');
        console.log('  SMTP Host:', process.env.SMTP_HOST);
        console.log('  SMTP Port:', process.env.SMTP_PORT);
        console.log('  SMTP User:', process.env.SMTP_USER);
        console.log('  Email Destino:', process.env.SECURITY_ALERT_EMAIL);
        console.log('');

        const transporter = nodemailer.createTransporter({
            host: process.env.SMTP_HOST,
            port: parseInt(process.env.SMTP_PORT),
            secure: true,
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS
            }
        });

        console.log('📤 Enviando email de prueba...');

        const info = await transporter.sendMail({
            from: `"Sistema TESCHA" <${process.env.SMTP_USER}>`,
            to: process.env.SECURITY_ALERT_EMAIL,
            subject: '🚨 PRUEBA - Alerta de Seguridad TESCHA',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #d32f2f;">🚨 Alerta de Seguridad - Sistema TESCHA</h2>
          <p><strong>Esta es una prueba del sistema de alertas.</strong></p>
          
          <div style="background: #f5f5f5; padding: 15px; border-left: 4px solid #d32f2f; margin: 20px 0;">
            <p><strong>Tipo:</strong> PRUEBA_SISTEMA</p>
            <p><strong>Severidad:</strong> INFO</p>
            <p><strong>Detalles:</strong> Verificación de funcionamiento del sistema de emails</p>
            <p><strong>Timestamp:</strong> ${new Date().toISOString()}</p>
          </div>

          <p>✅ <strong>Si recibes este email, el sistema está configurado correctamente.</strong></p>
          
          <hr style="margin: 20px 0;">
          
          <p style="color: #666; font-size: 12px;">
            Este es un mensaje automático del Sistema de Detección de Intrusos de TESCHA.
          </p>
        </div>
      `
        });

        console.log('✅ Email enviado exitosamente!');
        console.log('📬 Message ID:', info.messageId);
        console.log('');
        console.log('Verifica tu email:', process.env.SECURITY_ALERT_EMAIL);
        console.log('Si no lo ves, revisa la carpeta de SPAM');

    } catch (error) {
        console.error('❌ Error al enviar email:');
        console.error('');
        console.error('Mensaje:', error.message);
        console.error('');

        if (error.code === 'EAUTH') {
            console.error('🔑 Error de autenticación. Verifica:');
            console.error('  1. Que la contraseña de aplicación sea correcta');
            console.error('  2. Que el email SMTP sea correcto');
            console.error('  3. Que tengas verificación en 2 pasos activada');
        } else if (error.code === 'ECONNECTION') {
            console.error('🌐 Error de conexión. Verifica:');
            console.error('  1. Conexión a internet');
            console.error('  2. Firewall no bloquee el puerto 465');
        }
    }
}

testEmail();
