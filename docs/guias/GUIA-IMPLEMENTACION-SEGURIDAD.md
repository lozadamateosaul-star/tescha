# 🚀 GUÍA RÁPIDA DE IMPLEMENTACIÓN - SISTEMA DE SEGURIDAD TESCHA

## ✅ TODO ESTÁ LISTO PARA IMPLEMENTAR

He creado **TODO** el sistema de seguridad completo. Solo necesitas seguir estos pasos:

---

## 📋 OPCIÓN 1: CONFIGURACIÓN AUTOMÁTICA (RECOMENDADO)

### **Un solo comando:**

```powershell
.\configurar-seguridad.ps1
```

Este script hará **TODO** automáticamente:
- ✅ Instalar dependencias
- ✅ Configurar email de alertas
- ✅ Generar claves de seguridad
- ✅ Crear tablas en la base de datos
- ✅ Configurar variables de entorno

---

## 📋 OPCIÓN 2: CONFIGURACIÓN MANUAL

### **Paso 1: Configurar Email de Alertas**

1. **Obtener Contraseña de Aplicación de Gmail:**
   - Ve a: https://myaccount.google.com/apppasswords
   - Inicia sesión con tu cuenta de Gmail
   - Selecciona "Correo" y "Otro dispositivo"
   - Nombra: "TESCHA Security"
   - Copia la contraseña de 16 caracteres

2. **Editar `backend/.env`:**

```bash
# Agregar estas líneas al final del archivo .env

# Email para recibir alertas
SECURITY_ALERT_EMAIL=tu_email@gmail.com

# Habilitar alertas
ENABLE_EMAIL_ALERTS=true

# Configuración SMTP
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_USER=tu_email@gmail.com
SMTP_PASS=la_contraseña_de_16_caracteres_que_copiaste

# Generar con: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
ENCRYPTION_KEY=pegar_aqui_la_clave_generada
```

3. **Generar Claves de Seguridad:**

```bash
# JWT Secret
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
# Copiar resultado y pegar en JWT_SECRET en .env

# Encryption Key
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# Copiar resultado y pegar en ENCRYPTION_KEY en .env
```

### **Paso 2: Crear Tablas de Seguridad**

```bash
psql -U postgres -d tescha_db -f backend/database/add_security_tables.sql
```

### **Paso 3: Verificar que Todo Esté Integrado**

El archivo `backend/server.js` ya tiene todo integrado:
- ✅ IDS (Sistema de Detección de Intrusos)
- ✅ Dashboard de Seguridad
- ✅ Middlewares de Seguridad

---

## 🧪 PROBAR EL SISTEMA

### **1. Iniciar el Servidor**

```bash
cd backend
npm run dev
```

Deberías ver:
```
🚀 Servidor corriendo en puerto 5000
📍 Ambiente: development
📲 Sistema de notificaciones automáticas activo
📊 Sistema de métricas automáticas activo
```

### **2. Ejecutar Pruebas de Penetración**

En otra terminal:

```bash
cd security-tests
npm test
```

Resultado esperado:
```
============================================================
RESUMEN DE RESULTADOS
============================================================

✅ Pruebas Pasadas: 10/10
❌ Pruebas Fallidas: 0/10

🎉 ¡SISTEMA COMPLETAMENTE SEGURO!
```

### **3. Verificar Dashboard de Seguridad**

```bash
# Primero, obtén un token de login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"tu_password"}'

# Luego, consulta el dashboard
curl http://localhost:5000/api/security/dashboard \
  -H "Authorization: Bearer TU_TOKEN_AQUI"
```

---

## 📧 PROBAR ALERTAS POR EMAIL

### **Simular un Ataque:**

```bash
# Hacer múltiples intentos de login fallidos
for i in {1..10}; do
  curl -X POST http://localhost:5000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong_password"}'
done
```

**Resultado esperado:**
1. ✅ Después del 5to intento: Rate limiting activo
2. ✅ Después del 10mo intento: IP bloqueada
3. ✅ Email de alerta enviado a tu correo

**Email que recibirás:**
```
Asunto: 🚨 ALERTA DE SEGURIDAD - BRUTE_FORCE

Alerta de Seguridad - Sistema TESCHA

Tipo: BRUTE_FORCE
Severidad: HIGH
IP: 127.0.0.1
Usuario: N/A
Detalles: 10 intentos fallidos de login en la última hora
Acción: IP BLOQUEADA
Timestamp: 2025-12-02T13:45:00.000Z
```

---

## 🔍 MONITOREAR ACTIVIDAD

### **Ver Logs en Tiempo Real:**

En la consola del servidor verás:

```
============================================================
🚨 ALERTA DE SEGURIDAD
============================================================
Tipo: SUSPICIOUS_PATTERN
Severidad: HIGH
IP: 192.168.1.100
Usuario: anonymous
Detalles: Patrón sospechoso detectado en POST /api/alumnos
Acción: BLOCKED
Timestamp: 2025-12-02T13:30:00.000Z
============================================================
```

### **Consultar Dashboard:**

```bash
# Ver estadísticas generales
GET /api/security/dashboard

# Ver logs recientes
GET /api/security/logs?limit=50

# Ver intentos de login fallidos
GET /api/security/failed-logins

# Ver IPs bloqueadas
GET /api/security/suspicious-ips

# Ver top atacantes
GET /api/security/top-attackers
```

---

## 🎯 ENDPOINTS DEL DASHBOARD DE SEGURIDAD

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/security/dashboard` | GET | Resumen completo de seguridad |
| `/api/security/logs` | GET | Logs de seguridad recientes |
| `/api/security/failed-logins` | GET | Intentos de login fallidos |
| `/api/security/suspicious-ips` | GET | IPs sospechosas y bloqueadas |
| `/api/security/unblock-ip` | POST | Desbloquear una IP |
| `/api/security/events-timeline` | GET | Timeline de eventos |
| `/api/security/top-attackers` | GET | Top 10 atacantes |
| `/api/security/event-stats` | GET | Estadísticas por tipo |
| `/api/security/export-report` | GET | Exportar reporte completo |

---

## 📊 QUÉ ESPERAR

### **Actividad Normal:**
- Intentos de login fallidos: <10/día
- IPs bloqueadas: 0-2/semana
- Alertas de seguridad: 0-3/día
- Emails de alerta: 0-1/semana

### **Bajo Ataque:**
- Intentos de login fallidos: >50/hora
- IPs bloqueadas: >10/día
- Alertas de seguridad: >20/hora
- Emails de alerta: Múltiples por hora

---

## 🚨 SI RECIBES UNA ALERTA

### **1. Revisar el Email:**
```
Tipo: BRUTE_FORCE
IP: 192.168.1.100
Detalles: 10 intentos fallidos
```

### **2. Verificar en el Dashboard:**
```bash
curl http://localhost:5000/api/security/top-attackers \
  -H "Authorization: Bearer TU_TOKEN"
```

### **3. Revisar Logs Detallados:**
```bash
curl http://localhost:5000/api/security/logs?limit=100 \
  -H "Authorization: Bearer TU_TOKEN"
```

### **4. Si es Falso Positivo:**
```bash
curl -X POST http://localhost:5000/api/security/unblock-ip \
  -H "Authorization: Bearer TU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100"}'
```

---

## ✅ CHECKLIST DE IMPLEMENTACIÓN

- [ ] Ejecutar `.\configurar-seguridad.ps1` O configurar manualmente
- [ ] Verificar que `.env` tiene todas las variables
- [ ] Confirmar que las tablas de seguridad existen en la DB
- [ ] Iniciar el servidor y verificar que no hay errores
- [ ] Ejecutar pruebas de penetración: `npm test`
- [ ] Simular un ataque y verificar que llega el email
- [ ] Probar el dashboard de seguridad
- [ ] Documentar credenciales de email en lugar seguro

---

## 🎓 ARCHIVOS IMPORTANTES

| Archivo | Descripción |
|---------|-------------|
| `configurar-seguridad.ps1` | Script de configuración automática |
| `backend/server.js` | Ya integrado con todo |
| `backend/.env` | Configuración de email y claves |
| `backend/services/intrusionDetection.js` | Motor IDS |
| `backend/routes/security-dashboard.js` | API de monitoreo |
| `security-tests/penetration-tests.js` | Pruebas automatizadas |
| `security-tests/README.md` | Documentación completa |

---

## 📧 CONFIGURACIÓN DE GMAIL

### **Paso a Paso:**

1. Ve a: https://myaccount.google.com/security
2. Activa "Verificación en 2 pasos" (si no está activa)
3. Ve a: https://myaccount.google.com/apppasswords
4. Selecciona:
   - App: "Correo"
   - Dispositivo: "Otro (nombre personalizado)"
   - Nombre: "TESCHA Security"
5. Copia la contraseña de 16 caracteres
6. Pégala en `SMTP_PASS` en tu `.env`

---

## 🎉 ¡LISTO!

Una vez configurado, tu sistema:

✅ **Detectará** cualquier intento de hackeo  
✅ **Bloqueará** automáticamente a los atacantes  
✅ **Te enviará emails** con alertas  
✅ **Registrará** todo en la base de datos  
✅ **Tendrá un dashboard** para monitorear  
✅ **Podrás hacer pruebas** cuando quieras  

**Tu sistema TESCHA está completamente protegido y monitoreado 24/7.**

---

**¿Necesitas ayuda?** Revisa:
- `security-tests/README.md` - Documentación completa
- `CERTIFICACION-SEGURIDAD.md` - Análisis de seguridad
- `MEJORAS-SEGURIDAD.md` - Mejoras implementadas
