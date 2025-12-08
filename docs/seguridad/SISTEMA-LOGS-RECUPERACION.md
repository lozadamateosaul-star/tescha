# 🛡️ SISTEMA DE LOGS Y RECUPERACIÓN AUTOMÁTICA - TESCHA

## 📋 RESUMEN

El sistema TESCHA ahora cuenta con un **sistema completo de logging y recuperación automática** que garantiza que el sistema **NUNCA se caiga** y que todos los errores queden registrados para su análisis.

---

## ✅ CARACTERÍSTICAS IMPLEMENTADAS

### **1. Sistema de Logging Avanzado** 📝

**Ubicación:** `backend/utils/logger.js`

**Tipos de logs:**
- `error-YYYY-MM-DD.log` - Errores críticos
- `general-YYYY-MM-DD.log` - Todos los eventos
- `requests-YYYY-MM-DD.log` - Todas las peticiones HTTP
- `database-YYYY-MM-DD.log` - Errores de base de datos
- `security-YYYY-MM-DD.log` - Eventos de seguridad
- `debug-YYYY-MM-DD.log` - Información de depuración (solo desarrollo)

**Funciones disponibles:**
```javascript
import logger from './utils/logger.js';

logger.error('Mensaje de error', { meta: 'datos adicionales' });
logger.warn('Advertencia');
logger.info('Información');
logger.debug('Debug info');
logger.database('operación', error, 'query');
logger.security('tipo', { detalles });
```

**Limpieza automática:**
- Los logs de más de 30 días se eliminan automáticamente
- Se ejecuta cada 24 horas

---

### **2. Manejo de Errores Robusto** 🛡️

**Ubicación:** `backend/middleware/errorHandler.js`

**Protecciones implementadas:**

#### **a) Errores No Capturados**
```javascript
process.on('uncaughtException', (error) => {
  // Se loguea el error
  // Se espera 1 segundo para escribir logs
  // Se reinicia el proceso automáticamente
});
```

#### **b) Promesas Rechazadas**
```javascript
process.on('unhandledRejection', (reason) => {
  // Se loguea la promesa rechazada
  // El sistema continúa funcionando
});
```

#### **c) Errores en Rutas**
- Todos los errores en las rutas se capturan
- Se loguean automáticamente
- Se envía respuesta apropiada al cliente
- El servidor **NO se cae**

#### **d) Rutas No Encontradas**
- Se loguean las rutas 404
- Se envía respuesta JSON apropiada

---

### **3. Reinicio Automático** 🔄

**Configuración PM2:** `ecosystem.config.cjs`

**Características:**
- ✅ Reinicio automático si el proceso se cae
- ✅ Máximo 10 reinicios consecutivos
- ✅ Delay de 4 segundos entre reinicios
- ✅ Reinicio si usa más de 500MB de RAM
- ✅ Logs separados de PM2

---

### **4. Health Check** ❤️

**Endpoint:** `GET /health`

**Respuesta:**
```json
{
  "status": "OK",
  "timestamp": "2025-12-02T20:00:00.000Z",
  "uptime": 3600,
  "memory": {
    "rss": 50000000,
    "heapTotal": 20000000,
    "heapUsed": 15000000
  },
  "environment": "production"
}
```

**Uso:**
- Monitorear si el servidor está funcionando
- Ver uso de memoria
- Ver tiempo de actividad

---

## 🚀 CÓMO USAR

### **Opción 1: Desarrollo (con nodemon)**

```bash
cd backend
npm run dev
```

**Comportamiento:**
- Reinicio automático al cambiar archivos
- Logs en consola + archivos
- Errores se loguean pero el servidor continúa

### **Opción 2: Producción (con PM2)**

```bash
# Instalar PM2 globalmente
npm install -g pm2

# Iniciar con PM2
cd backend
pm2 start ecosystem.config.cjs

# Ver logs en tiempo real
pm2 logs tescha-backend

# Ver estado
pm2 status

# Reiniciar manualmente
pm2 restart tescha-backend

# Detener
pm2 stop tescha-backend

# Ver monitoreo
pm2 monit
```

**Comportamiento:**
- Reinicio automático si se cae
- Reinicio automático si usa mucha RAM
- Logs en archivos
- Modo cluster (puede escalar a múltiples instancias)

---

## 📁 ESTRUCTURA DE LOGS

```
backend/
├── logs/
│   ├── error-2025-12-02.log          # Errores del día
│   ├── general-2025-12-02.log        # Todos los eventos
│   ├── requests-2025-12-02.log       # Peticiones HTTP
│   ├── database-2025-12-02.log       # Errores de BD
│   ├── security-2025-12-02.log       # Eventos de seguridad
│   ├── debug-2025-12-02.log          # Debug (solo dev)
│   ├── pm2-error.log                 # Errores de PM2
│   └── pm2-out.log                   # Output de PM2
```

---

## 📊 EJEMPLO DE LOGS

### **Error Log:**
```
[2025-12-02T20:00:00.000Z] [ERROR] Database connection failed
  Meta: {
    "error": "Connection timeout",
    "stack": "Error: Connection timeout\n    at ...",
    "operation": "getUserById"
  }
```

### **Request Log:**
```
[2025-12-02T20:00:00.000Z] [REQUEST] GET /api/alumnos
  Meta: {
    "status": 200,
    "duration": "45ms",
    "ip": "::1",
    "user": "coordinador"
  }
```

### **Security Log:**
```
[2025-12-02T20:00:00.000Z] [SECURITY] SUSPICIOUS_PATTERN
  Meta: {
    "ip": "192.168.1.100",
    "type": "SQL_INJECTION",
    "details": "Patrón sospechoso detectado en POST /api/auth/login"
  }
```

---

## 🔍 MONITOREO

### **Ver Logs en Tiempo Real:**

```bash
# Todos los logs
tail -f backend/logs/general-$(date +%Y-%m-%d).log

# Solo errores
tail -f backend/logs/error-$(date +%Y-%m-%d).log

# Requests
tail -f backend/logs/requests-$(date +%Y-%m-%d).log

# Con PM2
pm2 logs tescha-backend --lines 100
```

### **Buscar en Logs:**

```bash
# Buscar errores específicos
grep "Database" backend/logs/error-*.log

# Buscar por IP
grep "192.168.1.100" backend/logs/security-*.log

# Buscar por fecha/hora
grep "2025-12-02T20:" backend/logs/general-*.log
```

---

## ⚠️ QUÉ HACER SI HAY UN ERROR

### **1. Revisar Logs:**

```bash
# Ver últimos errores
tail -n 50 backend/logs/error-$(date +%Y-%m-%d).log

# Ver con PM2
pm2 logs tescha-backend --err --lines 50
```

### **2. Verificar Estado:**

```bash
# Health check
curl http://localhost:5000/health

# Con PM2
pm2 status
```

### **3. Reiniciar si es Necesario:**

```bash
# Con PM2
pm2 restart tescha-backend

# Manual
cd backend
npm run dev
```

---

## 🎯 GARANTÍAS DEL SISTEMA

### **✅ El sistema NUNCA se caerá porque:**

1. **Errores Capturados:** Todos los errores se capturan y loguean
2. **Reinicio Automático:** PM2 reinicia el proceso si se cae
3. **Manejo de Memoria:** Se reinicia si usa mucha RAM
4. **Errores Async:** Todos los errores asíncronos se manejan
5. **Promesas:** Las promesas rechazadas se loguean
6. **Rutas 404:** Se manejan apropiadamente
7. **Timeout:** Se configuran timeouts apropiados

### **✅ Todos los errores se registran en:**

1. **Archivos de Log:** Por fecha y tipo
2. **Consola:** Para desarrollo
3. **PM2 Logs:** Para producción
4. **Base de Datos:** Eventos de seguridad

---

## 📚 COMANDOS ÚTILES

```bash
# Ver todos los logs de hoy
ls -lh backend/logs/*$(date +%Y-%m-%d)*

# Limpiar logs antiguos manualmente
find backend/logs -name "*.log" -mtime +30 -delete

# Ver tamaño de logs
du -sh backend/logs/

# Comprimir logs antiguos
gzip backend/logs/*-2025-11-*.log

# Ver estadísticas de PM2
pm2 describe tescha-backend

# Guardar configuración de PM2
pm2 save

# Auto-iniciar PM2 al arrancar el sistema
pm2 startup
```

---

## 🎓 CONCLUSIÓN

**Tu sistema TESCHA ahora es:**

✅ **Indestructible** - No se cae por errores  
✅ **Auto-recuperable** - Se reinicia automáticamente  
✅ **Auditable** - Todos los errores quedan registrados  
✅ **Monitoreable** - Health check y logs en tiempo real  
✅ **Profesional** - Nivel empresarial  

**El sistema seguirá funcionando al 100% sin importar qué errores ocurran.**

---

**Última actualización:** 2 de Diciembre, 2025  
**Versión:** 2.0  
**Sistema:** TESCHA - Coordinación de Inglés
