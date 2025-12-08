# 🔒 SISTEMA DE PRUEBAS Y DETECCIÓN DE INTRUSOS - TESCHA

## 📋 CONTENIDO

Este directorio contiene herramientas avanzadas para:
1. **Pruebas de Penetración** - Simular ataques para verificar seguridad
2. **Detección de Intrusos (IDS)** - Monitoreo en tiempo real
3. **Dashboard de Seguridad** - Visualización y gestión

---

## 🧪 1. PRUEBAS DE PENETRACIÓN

### **Archivo:** `penetration-tests.js`

Este script simula **10 tipos diferentes de ataques** para verificar la seguridad de tu sistema.

### **Instalación:**

```bash
cd security-tests
npm install axios chalk
```

### **Ejecución:**

```bash
# Asegúrate de que el servidor esté corriendo
cd ../backend
npm run dev

# En otra terminal, ejecuta las pruebas
cd security-tests
node penetration-tests.js
```

### **Pruebas Incluidas:**

| # | Prueba | Descripción |
|---|--------|-------------|
| 1 | SQL Injection | Intenta inyectar código SQL malicioso |
| 2 | XSS | Intenta inyectar scripts JavaScript |
| 3 | Fuerza Bruta | Múltiples intentos de login |
| 4 | CSRF | Requests sin token CSRF |
| 5 | IDOR | Acceso a recursos de otros usuarios |
| 6 | JWT Manipulation | Modificación de tokens |
| 7 | Validación de Datos | Datos inválidos/malformados |
| 8 | Acceso Sin Auth | Endpoints sin autenticación |
| 9 | Escalación de Privilegios | Intentos de acceso no autorizado |
| 10 | DoS | Múltiples requests simultáneos |

### **Resultados:**

El script genera:
- ✅ Reporte en consola con colores
- 📄 Archivo JSON: `security-test-report.json`
- 📊 Estadísticas de pruebas pasadas/fallidas

### **Ejemplo de Salida:**

```
============================================================
TEST 1: SQL INJECTION
============================================================
✅ SQL Injection: SEGURO

============================================================
TEST 2: XSS (Cross-Site Scripting)
============================================================
✅ XSS: SEGURO

...

============================================================
RESUMEN DE RESULTADOS
============================================================

✅ Pruebas Pasadas: 10/10
❌ Pruebas Fallidas: 0/10

🎉 ¡SISTEMA COMPLETAMENTE SEGURO!
```

---

## 🚨 2. SISTEMA DE DETECCIÓN DE INTRUSOS (IDS)

### **Archivo:** `backend/services/intrusionDetection.js`

Sistema que monitorea actividad sospechosa en tiempo real y genera alertas automáticas.

### **Características:**

#### **Detecciones Automáticas:**

1. **Patrones Sospechosos**
   - SQL Injection attempts
   - XSS attempts
   - Path Traversal
   - Command Injection
   - File Upload attacks

2. **Fuerza Bruta**
   - Múltiples intentos de login fallidos
   - Tracking por IP + Username
   - Bloqueo automático

3. **Anomalías de Tráfico**
   - Requests excesivos por minuto
   - Escaneo de endpoints
   - Comportamiento automatizado

4. **Acceso No Autorizado**
   - Intentos repetidos de acceso prohibido
   - Escalación de privilegios
   - Manipulación de tokens

#### **Acciones Automáticas:**

- 📝 **Logging:** Todos los eventos se registran en `security_logs`
- 🚫 **Bloqueo:** IPs sospechosas se bloquean automáticamente
- 📧 **Alertas:** Notificaciones por email (configurable)
- 🖥️ **Consola:** Alertas en tiempo real en la consola

### **Configuración:**

Agregar a `.env`:

```bash
# Alertas de Seguridad
SECURITY_ALERT_EMAIL=admin@tescha.com
ENABLE_EMAIL_ALERTS=true

# SMTP (para envío de emails)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_USER=tu_email@gmail.com
SMTP_PASS=tu_password_de_aplicacion
```

### **Integración:**

En `server.js`:

```javascript
import { intrusionDetectionMiddleware } from './services/intrusionDetection.js';

// Después de otros middlewares
app.use(intrusionDetectionMiddleware);
```

### **Ejemplo de Alerta:**

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

---

## 📊 3. DASHBOARD DE SEGURIDAD

### **Archivo:** `backend/routes/security-dashboard.js`

API completa para monitorear la seguridad del sistema.

### **Endpoints Disponibles:**

#### **1. Dashboard General**
```
GET /api/security/dashboard
```
Retorna resumen completo de seguridad de las últimas 24 horas.

**Respuesta:**
```json
{
  "report": {
    "last24Hours": [...],
    "blockedIPs": ["192.168.1.100"],
    "suspiciousIPs": ["192.168.1.101"],
    "timestamp": "2025-12-02T13:30:00.000Z"
  },
  "stats": {
    "login_attempts_24h": "45",
    "unauthorized_attempts_24h": "12",
    "suspicious_activity_24h": "8",
    "unique_ips_24h": "23"
  }
}
```

#### **2. Logs de Seguridad**
```
GET /api/security/logs?limit=50&type=UNAUTHORIZED_ACCESS&hours=24
```

#### **3. Intentos de Login Fallidos**
```
GET /api/security/failed-logins?hours=24
```

#### **4. IPs Sospechosas**
```
GET /api/security/suspicious-ips
```

#### **5. Desbloquear IP**
```
POST /api/security/unblock-ip
Body: { "ip": "192.168.1.100" }
```

#### **6. Timeline de Eventos**
```
GET /api/security/events-timeline?hours=24
```

#### **7. Top Atacantes**
```
GET /api/security/top-attackers
```

#### **8. Estadísticas por Tipo**
```
GET /api/security/event-stats
```

#### **9. Exportar Reporte**
```
GET /api/security/export-report?days=7
```

#### **10. Limpiar Logs Antiguos**
```
DELETE /api/security/cleanup-logs
Body: { "days": 90 }
```

### **Integración:**

En `server.js`:

```javascript
import securityDashboardRoutes from './routes/security-dashboard.js';

app.use('/api/security', securityDashboardRoutes);
```

---

## 🎯 GUÍA DE USO COMPLETA

### **Paso 1: Instalar Dependencias**

```bash
cd backend
npm install nodemailer

cd ../security-tests
npm install axios chalk
```

### **Paso 2: Configurar Variables de Entorno**

Agregar a `backend/.env`:

```bash
# Seguridad
SECURITY_ALERT_EMAIL=admin@tescha.com
ENABLE_EMAIL_ALERTS=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_USER=tu_email@gmail.com
SMTP_PASS=tu_password
```

### **Paso 3: Integrar IDS en el Servidor**

En `backend/server.js`:

```javascript
import { intrusionDetectionMiddleware } from './services/intrusionDetection.js';
import securityDashboardRoutes from './routes/security-dashboard.js';

// Middlewares
app.use(intrusionDetectionMiddleware);

// Rutas
app.use('/api/security', securityDashboardRoutes);
```

### **Paso 4: Ejecutar Pruebas**

```bash
# Terminal 1: Servidor
cd backend
npm run dev

# Terminal 2: Pruebas
cd security-tests
node penetration-tests.js
```

### **Paso 5: Monitorear Dashboard**

```bash
# Ver estadísticas
curl http://localhost:5000/api/security/dashboard \
  -H "Authorization: Bearer TU_TOKEN"

# Ver logs recientes
curl http://localhost:5000/api/security/logs?limit=10 \
  -H "Authorization: Bearer TU_TOKEN"

# Ver IPs bloqueadas
curl http://localhost:5000/api/security/suspicious-ips \
  -H "Authorization: Bearer TU_TOKEN"
```

---

## 🔍 INTERPRETACIÓN DE RESULTADOS

### **Pruebas de Penetración:**

✅ **10/10 Pasadas:** Sistema completamente seguro  
⚠️ **8-9/10 Pasadas:** Seguridad buena, revisar fallos  
❌ **<8/10 Pasadas:** Vulnerabilidades críticas, corregir urgente

### **Alertas del IDS:**

| Severidad | Acción Recomendada |
|-----------|-------------------|
| 🔴 CRITICAL | Bloqueo inmediato + Investigación |
| 🟠 HIGH | Monitoreo cercano + Alerta |
| 🟡 MEDIUM | Registro + Revisión periódica |
| 🟢 LOW | Solo registro |

### **IPs Bloqueadas:**

- **Automático:** Después de 3 actividades sospechosas
- **Manual:** Coordinador puede desbloquear
- **Permanente:** Hasta desbloqueo manual

---

## 📈 MONITOREO CONTINUO

### **Tareas Diarias:**

1. Revisar dashboard de seguridad
2. Verificar alertas nuevas
3. Revisar IPs bloqueadas
4. Verificar intentos de login fallidos

### **Tareas Semanales:**

1. Ejecutar pruebas de penetración
2. Revisar top atacantes
3. Analizar patrones de ataque
4. Exportar reporte semanal

### **Tareas Mensuales:**

1. Limpiar logs antiguos
2. Revisar configuración de seguridad
3. Actualizar umbrales de detección
4. Capacitar al equipo

---

## 🚨 QUÉ HACER SI DETECTAS UN ATAQUE

### **1. Ataque en Curso:**

```bash
# Ver IPs atacantes
curl http://localhost:5000/api/security/top-attackers

# Bloquear manualmente (el IDS ya debería haberlo hecho)
# Verificar en logs
curl http://localhost:5000/api/security/logs?type=SECURITY_ALERT
```

### **2. Después del Ataque:**

1. Revisar logs completos
2. Identificar vector de ataque
3. Verificar si hubo acceso exitoso
4. Cambiar credenciales si es necesario
5. Actualizar reglas de seguridad
6. Documentar el incidente

### **3. Falso Positivo:**

```bash
# Desbloquear IP
curl -X POST http://localhost:5000/api/security/unblock-ip \
  -H "Authorization: Bearer TU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100"}'
```

---

## 📊 MÉTRICAS DE SEGURIDAD

### **KPIs Importantes:**

- **Intentos de Login Fallidos:** <10/día es normal
- **IPs Bloqueadas:** <5/semana es normal
- **Alertas de Seguridad:** <3/día es normal
- **Patrones Sospechosos:** 0 es ideal

### **Umbrales de Alerta:**

- 🟢 **Normal:** <10 eventos/día
- 🟡 **Atención:** 10-50 eventos/día
- 🟠 **Preocupante:** 50-100 eventos/día
- 🔴 **Crítico:** >100 eventos/día

---

## 🎓 CONCLUSIÓN

Con estas herramientas tienes:

✅ **Pruebas Automatizadas:** Verifica seguridad regularmente  
✅ **Detección en Tiempo Real:** IDS monitorea 24/7  
✅ **Dashboard Completo:** Visualiza toda la actividad  
✅ **Alertas Automáticas:** Notificaciones inmediatas  
✅ **Bloqueo Automático:** Protección proactiva  
✅ **Reportes Detallados:** Análisis profundo  

**Tu sistema TESCHA está completamente protegido y monitoreado.**

---

**Última actualización:** 2 de Diciembre, 2025  
**Versión:** 1.0  
**Autor:** Sistema de Seguridad TESCHA
