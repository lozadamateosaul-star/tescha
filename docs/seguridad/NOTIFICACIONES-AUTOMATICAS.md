# Sistema de Notificaciones Automáticas - TESCHA

## 📋 Descripción

Sistema automático de notificaciones para gestionar prórrogas de pago mediante WhatsApp y correo electrónico.

## 🚀 Características

✅ **Notificaciones Automáticas**: Se ejecutan diariamente a las 9:00 AM
✅ **Recordatorios**: Alertas 3 días antes del vencimiento de prórroga
✅ **Alertas de Vencimiento**: Notificación cuando una prórroga vence
✅ **WhatsApp**: Enlaces directos para enviar mensajes
✅ **Correo Electrónico**: Integración con cliente de correo
✅ **Registro de Notificaciones**: Evita duplicados
✅ **Verificaciones Periódicas**: Cada 6 horas

## ⚙️ Configuración

### 1. Variables de Entorno

El sistema está configurado con:
- **Teléfono Coordinador**: 5219060013

### 2. Cron Jobs Activos

```javascript
// Notificaciones diarias
'0 9 * * *'  // Todos los días a las 9:00 AM

// Verificaciones periódicas
'0 */6 * * *'  // Cada 6 horas
```

### 3. Base de Datos

Se crea automáticamente la tabla:
```sql
CREATE TABLE notificaciones_enviadas (
  id SERIAL PRIMARY KEY,
  pago_id INTEGER REFERENCES pagos(id),
  tipo VARCHAR(50),  -- 'recordatorio' o 'vencida'
  mensaje TEXT,
  fecha_envio TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW()
);
```

## 📱 Uso

### Automático

El sistema se ejecuta automáticamente al iniciar el servidor:

```bash
npm start
```

Verás en consola:
```
✅ Cron jobs de notificaciones iniciados
   - Notificaciones diarias: 9:00 AM
   - Verificaciones: cada 6 horas
📲 Sistema de notificaciones automáticas activo
```

### Manual (Para Pruebas)

**Endpoint de prueba**:
```
GET http://localhost:5000/api/test-notificaciones
```

**Endpoint autenticado**:
```
POST http://localhost:5000/api/notificaciones/ejecutar
Headers: Authorization: Bearer <token>
```

### Desde el Frontend

Los botones de WhatsApp y Correo en la tabla de pagos permiten envío manual.

## 📊 Formato de Mensajes

### Recordatorio (3 días antes)

```
🔔 RECORDATORIO DE PRÓRROGA

Estimado Coordinador,

Le informo que al alumno *Mateo Lozada Quiroz* con matrícula *201724408* 
se le acabará la prórroga el día *domingo, 15 de diciembre de 2025*.

📋 Detalles:
• Concepto: Colegiatura
• Monto: $2000.00
• Días restantes: 3
• Teléfono: 5512345678

_Notificación automática - Sistema TESCHA_
```

### Alerta de Vencimiento

```
⚠️ PRÓRROGA VENCIDA

Estimado Coordinador,

La prórroga del alumno *Mateo Lozada Quiroz* (201724408) 
venció hace *2 día(s)*.

📋 Detalles:
• Concepto: Colegiatura
• Monto: $2000.00
• Fecha límite: viernes, 13 de diciembre de 2025
• Teléfono: 5512345678

⚡ Acción requerida

_Notificación automática - Sistema TESCHA_
```

## 🔧 Personalización

### Cambiar horarios de ejecución

Editar `backend/services/notificacionesService.js`:

```javascript
// Cambiar hora de notificaciones
cron.schedule('0 8 * * *', ...);  // 8:00 AM

// Cambiar frecuencia de verificación
cron.schedule('0 */12 * * *', ...);  // Cada 12 horas
```

### Cambiar días de anticipación

```javascript
const porVencer = await obtenerProrrogasPorVencer(5);  // 5 días antes
```

### Integrar WhatsApp Business API (Twilio)

1. Instalar Twilio:
```bash
npm install twilio
```

2. Agregar en `notificacionesService.js`:
```javascript
import twilio from 'twilio';

const client = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

const enviarWhatsApp = async (telefono, mensaje) => {
  await client.messages.create({
    from: 'whatsapp:+14155238886',
    to: `whatsapp:+52${telefono}`,
    body: mensaje
  });
};
```

## 📝 Logs

El sistema registra en consola:

```
⏰ Cron job ejecutado: Notificaciones automáticas
🔄 Iniciando proceso de notificaciones automáticas...
📊 Prórrogas por vencer: 2
⚠️  Prórrogas vencidas: 1

=============================================================
📱 NOTIFICACIÓN RECORDATORIO - 01/12/2025 09:00:00
=============================================================
Alumno: Mateo Lozada Quiroz (201724408)
Monto: $2000.00
Fecha límite: 2025-12-15
URL WhatsApp: https://wa.me/5219060013?text=...
=============================================================

✅ Proceso de notificaciones completado
```

## 🛠️ Troubleshooting

### Las notificaciones no se ejecutan

1. Verificar que el servidor esté corriendo
2. Revisar logs de consola
3. Probar endpoint manual: `/api/test-notificaciones`

### Notificaciones duplicadas

El sistema evita duplicados automáticamente verificando `notificaciones_enviadas`.

### Cambiar teléfono del coordinador

Editar `backend/services/notificacionesService.js`:
```javascript
const TELEFONO_COORDINADOR = '5219876543210';  // Nuevo número
```

## 📈 Mejoras Futuras

- [ ] Integración con WhatsApp Business API oficial
- [ ] Envío de correos con SMTP (NodeMailer)
- [ ] Dashboard de notificaciones enviadas
- [ ] Configuración desde interfaz web
- [ ] Plantillas personalizables
- [ ] Notificaciones a múltiples destinatarios
- [ ] Reportes de efectividad

## 📞 Soporte

Para dudas o problemas, contactar a coordinación.
