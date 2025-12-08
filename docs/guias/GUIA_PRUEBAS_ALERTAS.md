# 🧪 GUÍA RÁPIDA: PROBAR SISTEMA DE ALERTAS DE SEGURIDAD

## 📧 PASO 1: Configurar Email (IMPORTANTE)

Para recibir alertas por email cuando detecten hackeos, edita tu archivo `.env`:

```bash
# Alertas de Seguridad
SECURITY_ALERT_EMAIL=tu-email@gmail.com
ENABLE_EMAIL_ALERTS=true

# SMTP (Gmail)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=tu-email@gmail.com
SMTP_PASS=xxxx xxxx xxxx xxxx  # Contraseña de aplicación
```

### Cómo obtener la contraseña de aplicación de Gmail:
1. Ve a: https://myaccount.google.com/apppasswords
2. Genera una nueva contraseña de aplicación
3. Cópiala en `SMTP_PASS` (sin espacios)

### Reiniciar el servidor:
```bash
npm run pm2:restart
```

---

## 🚨 PASO 2: Simular un Ataque

### Opción A: Usar POSTMAN o INSOMNIA

1. Crea una nueva request POST
2. URL: `http://localhost:5000/api/auth/login`
3. Headers: `Content-Type: application/json`
4. Body (JSON):
```json
{
  "username": "admin' OR '1'='1",
  "password": "test"
}
```
5. Enviar

**Resultado esperado:**
- Status: `403 Forbidden`
- Body: `{"error":"Actividad sospechosa detectada"}`

---

### Opción B: Usar el Navegador

Abre en tu navegador:
```
http://localhost:5000/api/alumnos?search=<script>alert('XSS')</script>
```

**Resultado esperado:**
- Error 403 o el script es bloqueado

---

### Opción C: Usar PowerShell

```powershell
$body = @{
    username = "admin' OR '1'='1"
    password = "test"
} | ConvertTo-Json

Invoke-WebRequest -Uri "http://localhost:5000/api/auth/login" `
    -Method POST `
    -Body $body `
    -ContentType "application/json"
```

---

## 📊 PASO 3: Verificar las Alertas

### 1. En la Consola del Servidor

```bash
npm run pm2:logs
```

Deberías ver algo como:

```
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
```

### 2. En tu Email

Si configuraste SMTP correctamente, recibirás un email con:

**Asunto:** 🚨 ALERTA DE SEGURIDAD - SUSPICIOUS_PATTERN

**Contenido:**
- Tipo de ataque
- IP del atacante
- Detalles del intento
- Timestamp
- Acción tomada (BLOCKED)

### 3. En la Base de Datos

Conecta a PostgreSQL y ejecuta:

```sql
SELECT 
    event_type,
    ip_address,
    details,
    created_at
FROM security_logs
WHERE created_at > NOW() - INTERVAL '1 hour'
ORDER BY created_at DESC;
```

---

## 🎯 TIPOS DE ATAQUES QUE PUEDES PROBAR

### 1. SQL Injection
```json
{
  "username": "admin' OR '1'='1",
  "password": "test"
}
```

### 2. XSS (Cross-Site Scripting)
```
http://localhost:5000/api/alumnos?search=<script>alert('XSS')</script>
```

### 3. Path Traversal
```
http://localhost:5000/api/alumnos/../../../etc/passwd
```

### 4. Command Injection
```json
{
  "username": "admin; ls -la",
  "password": "test | cat /etc/passwd"
}
```

### 5. Brute Force
Intenta hacer login 10 veces con contraseña incorrecta:
```json
{
  "username": "admin",
  "password": "wrong1"
}
```
Repite cambiando "wrong1" por "wrong2", "wrong3", etc.

---

## ✅ QUÉ ESPERAR

Cuando simules un ataque:

1. ❌ **El ataque es BLOQUEADO** (Status 403)
2. 🚨 **Se genera una ALERTA** en la consola del servidor
3. 💾 **Se guarda en la base de datos** (tabla `security_logs`)
4. 📧 **Se envía un EMAIL** al administrador (si SMTP está configurado)
5. 🔒 **La IP puede ser bloqueada** si hay múltiples intentos

---

## 🔍 VERIFICACIÓN RÁPIDA

### ¿El servidor está corriendo?
```bash
npm run pm2:status
```

### ¿Hay alertas recientes?
```bash
npm run pm2:logs -- --lines 50
```

### ¿Está configurado el email?
Verifica que en `.env` tengas:
- `SECURITY_ALERT_EMAIL`
- `ENABLE_EMAIL_ALERTS=true`
- `SMTP_USER` y `SMTP_PASS`

---

## 📧 EJEMPLO DE EMAIL QUE RECIBIRÁS

```
De: Sistema TESCHA 🔒 <tu-email@gmail.com>
Para: admin@tescha.com
Asunto: 🚨 ALERTA DE SEGURIDAD - SUSPICIOUS_PATTERN

┌─────────────────────────────────────────────────────────┐
│ 🚨 ALERTA DE SEGURIDAD                                  │
│ Sistema TESCHA                                          │
├─────────────────────────────────────────────────────────┤
│ Tipo: SUSPICIOUS_PATTERN                                │
│ Severidad: HIGH                                         │
│ IP: ::1                                                 │
│ Usuario: anonymous                                      │
│ Detalles: Patrón sospechoso detectado en               │
│           POST /api/auth/login                          │
│ Acción: BLOCKED                                         │
│ Timestamp: 2025-12-05T22:06:00.000Z                    │
└─────────────────────────────────────────────────────────┘

Email automático - Sistema de Detección de Intrusos
```

---

## 💡 TIPS

✅ **No necesitas hacer nada manualmente** - El sistema detecta y alerta automáticamente
✅ **Todas las alertas se guardan** - Puedes revisarlas en `security_logs`
✅ **Las IPs sospechosas se bloquean** - Después de múltiples intentos
✅ **Los emails se envían en tiempo real** - Inmediatamente después de detectar el ataque

---

## 🎉 CONCLUSIÓN

Tu sistema TESCHA tiene un **Sistema de Detección de Intrusos (IDS)** activo que:

1. ✅ Detecta automáticamente intentos de hackeo
2. ✅ Bloquea los ataques inmediatamente
3. ✅ Envía alertas por email al administrador
4. ✅ Registra todo en la base de datos
5. ✅ Bloquea IPs sospechosas

**¡Tu sistema está protegido!** 🛡️
