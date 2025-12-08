/**
 * GUÍA DE PRUEBAS DE SEGURIDAD - SISTEMA TESCHA
 * 
 * Este documento explica cómo probar el sistema de alertas de seguridad
 */

console.log(`
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   🧪 GUÍA DE PRUEBAS - SISTEMA DE ALERTAS DE SEGURIDAD               ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝

📧 CONFIGURACIÓN DE EMAIL (REQUERIDA PARA ALERTAS)
═══════════════════════════════════════════════════════════════════════

Para recibir alertas por email cuando detecten intentos de hackeo:

1. Edita el archivo .env y agrega:

   SECURITY_ALERT_EMAIL=tu-email@gmail.com
   ENABLE_EMAIL_ALERTS=true
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=tu-email@gmail.com
   SMTP_PASS=tu_password_de_aplicacion

2. Para Gmail, genera una "Contraseña de aplicación":
   https://myaccount.google.com/apppasswords

3. Reinicia el servidor:
   npm run pm2:restart


🚨 CÓMO FUNCIONA EL SISTEMA DE ALERTAS
═══════════════════════════════════════════════════════════════════════

El sistema detecta automáticamente:

✅ SQL Injection
   Ejemplo: username = "admin' OR '1'='1"
   
✅ XSS (Cross-Site Scripting)
   Ejemplo: <script>alert('XSS')</script>
   
✅ Path Traversal
   Ejemplo: ../../etc/passwd
   
✅ Command Injection
   Ejemplo: ; ls -la | cat /etc/passwd
   
✅ Brute Force
   Ejemplo: 10+ intentos de login fallidos
   
✅ Port Scanning
   Ejemplo: 20+ endpoints diferentes en 5 minutos
   
✅ File Upload Malicioso
   Ejemplo: archivo.php.exe


📧 QUÉ RECIBIRÁS POR EMAIL
═══════════════════════════════════════════════════════════════════════

Cuando se detecte un ataque, recibirás un email con:

┌─────────────────────────────────────────────────────────────────┐
│ 🚨 ALERTA DE SEGURIDAD - SUSPICIOUS_PATTERN                     │
├─────────────────────────────────────────────────────────────────┤
│ Tipo: SUSPICIOUS_PATTERN                                        │
│ Severidad: HIGH                                                 │
│ IP: 192.168.1.100                                              │
│ Usuario: anonymous                                              │
│ Detalles: Patrón sospechoso detectado en POST /api/auth/login  │
│ Acción: BLOCKED                                                 │
│ Timestamp: 2025-12-05T16:00:00.000Z                           │
└─────────────────────────────────────────────────────────────────┘


🧪 PRUEBAS MANUALES
═══════════════════════════════════════════════════════════════════════

Puedes probar el sistema usando herramientas como:

1. POSTMAN o INSOMNIA:
   
   POST http://localhost:5000/api/auth/login
   Body: {
     "username": "admin' OR '1'='1",
     "password": "test"
   }
   
   ✅ Deberías recibir: 403 Forbidden
   ✅ Deberías ver en consola: 🚨 ALERTA DE SEGURIDAD
   ✅ Deberías recibir email (si está configurado)


2. CURL (desde terminal):

   # SQL Injection
   curl -X POST http://localhost:5000/api/auth/login \\
     -H "Content-Type: application/json" \\
     -d "{\\"username\\":\\"admin' OR '1'='1\\",\\"password\\":\\"test\\"}"
   
   # XSS Attack
   curl "http://localhost:5000/api/alumnos?search=<script>alert('XSS')</script>"
   
   # Path Traversal
   curl "http://localhost:5000/api/alumnos/../../../etc/passwd"


3. NAVEGADOR (para XSS):
   
   http://localhost:5000/api/alumnos?search=<script>alert('XSS')</script>


📊 VERIFICAR ALERTAS
═══════════════════════════════════════════════════════════════════════

1. En la consola del servidor:
   
   npm run pm2:logs
   
   Busca líneas como:
   🚨 ALERTA DE SEGURIDAD
   ══════════════════════════════════════
   Tipo: SUSPICIOUS_PATTERN
   Severidad: HIGH
   IP: ::1
   ...


2. En la base de datos:
   
   SELECT * FROM security_logs 
   WHERE created_at > NOW() - INTERVAL '1 hour'
   ORDER BY created_at DESC;


3. En tu email:
   
   Revisa tu bandeja de entrada (o spam)
   Asunto: "🚨 ALERTA DE SEGURIDAD - SUSPICIOUS_PATTERN"


🎯 EJEMPLO COMPLETO DE PRUEBA
═══════════════════════════════════════════════════════════════════════

1. Asegúrate de que el servidor esté corriendo:
   npm run pm2:status

2. Abre otra terminal y ejecuta:
   
   curl -X POST http://localhost:5000/api/auth/login \\
     -H "Content-Type: application/json" \\
     -d "{\\"username\\":\\"admin' OR '1'='1\\",\\"password\\":\\"test\\"}"

3. Verifica la respuesta:
   ✅ Status: 403 Forbidden
   ✅ Body: {"error":"Actividad sospechosa detectada"}

4. Revisa los logs:
   npm run pm2:logs

5. Revisa tu email (si configuraste SMTP)


🔍 LOGS ESPERADOS
═══════════════════════════════════════════════════════════════════════

En la consola del servidor deberías ver:

════════════════════════════════════════════════════════════
🚨 ALERTA DE SEGURIDAD
════════════════════════════════════════════════════════════
Tipo: SUSPICIOUS_PATTERN
Severidad: HIGH
IP: ::1
Usuario: N/A
Detalles: Patrón sospechoso detectado en POST /api/auth/login
Acción: BLOCKED
Timestamp: 2025-12-05T22:00:00.000Z
════════════════════════════════════════════════════════════

📧 ¡EMAIL ENVIADO AUTOMÁTICAMENTE!
   📧 Destinatario: tu-email@gmail.com
   📨 Message ID: <xxxxx@gmail.com>
   ✓ Estado: Enviado


⚙️ CONFIGURACIÓN RECOMENDADA
═══════════════════════════════════════════════════════════════════════

En tu archivo .env:

# Alertas de Seguridad
SECURITY_ALERT_EMAIL=admin@tescha.com
ENABLE_EMAIL_ALERTS=true

# SMTP (Gmail)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=alertas@tescha.com
SMTP_PASS=xxxx xxxx xxxx xxxx  # Contraseña de aplicación de 16 caracteres


💡 TIPS
═══════════════════════════════════════════════════════════════════════

✅ Las alertas se envían AUTOMÁTICAMENTE cuando se detecta un ataque
✅ No necesitas hacer nada manualmente
✅ El sistema bloquea el ataque Y envía la alerta
✅ Puedes ver todas las alertas en la tabla security_logs
✅ Las alertas incluyen: IP, tipo de ataque, timestamp, detalles


🎉 RESULTADO ESPERADO
═══════════════════════════════════════════════════════════════════════

Cuando alguien intente hackear tu sistema:

1. ❌ El ataque es BLOQUEADO inmediatamente
2. 🚨 Se genera una ALERTA en consola
3. 💾 Se guarda en la base de datos (security_logs)
4. 📧 Se envía un EMAIL al administrador
5. 🔒 La IP puede ser bloqueada si hay múltiples intentos


═══════════════════════════════════════════════════════════════════════
                    ✅ TU SISTEMA ESTÁ PROTEGIDO
═══════════════════════════════════════════════════════════════════════
`);
