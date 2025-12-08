# 🚀 GUÍA PM2 - AUTO-REINICIO Y LOGS

## ✅ YA ESTÁ FUNCIONANDO

El backend ahora está corriendo con **PM2** que:
- ✅ Se reinicia automáticamente si falla
- ✅ Guarda logs en `backend/logs/`
- ✅ Reinicia si usa más de 500MB de RAM
- ✅ Máximo 10 reinicios automáticos

---

## 📋 COMANDOS ÚTILES

### Ver estado del servidor
```powershell
cd c:\Users\dush3\Downloads\TESCHA\backend
npm run pm2:monit
```

### Ver logs en tiempo real
```powershell
npm run pm2:logs
```

### Reiniciar manualmente
```powershell
npm run pm2:restart
```

### Detener el servidor
```powershell
npm run pm2:stop
```

### Iniciar el servidor
```powershell
npm run pm2:start
```

---

## 📊 UBICACIÓN DE LOGS

Los logs se guardan en:
```
backend/logs/pm2-error.log  → Errores
backend/logs/pm2-out.log    → Salida normal
```

---

## 🔄 AUTO-REINICIO

PM2 reiniciará automáticamente el backend si:
- ❌ El servidor se cae (crash)
- ❌ Usa más de 500MB de RAM
- ❌ Hay un error fatal

**Configuración actual:**
- Max reinicios: 10
- Tiempo mínimo activo: 10 segundos
- Delay entre reinicios: 4 segundos

---

## 🎯 PARA EL FRONTEND

El frontend (React) NO necesita PM2 porque:
- Se ejecuta en el navegador
- Si falla, solo necesitas recargar (F5)
- En producción se sirve como archivos estáticos

---

## 📝 EJEMPLO DE USO

```powershell
# Ver si está corriendo
npm run pm2:monit

# Ver logs en vivo
npm run pm2:logs

# Si necesitas reiniciar
npm run pm2:restart
```

---

## ✅ VERIFICAR QUE FUNCIONA

1. Abre: http://localhost:3001/api/health
2. Deberías ver: `{"status":"ok"}`
3. Si ves eso, PM2 está funcionando correctamente

---

## 🚨 SI ALGO FALLA

1. Ver logs: `npm run pm2:logs`
2. Reiniciar: `npm run pm2:restart`
3. Si sigue fallando: `npm run pm2:stop` y luego `npm run pm2:start`

---

**¡LISTO! El backend ahora se reinicia solo si falla** 🎉
