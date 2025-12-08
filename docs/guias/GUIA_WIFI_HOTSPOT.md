# 🌐 GUÍA: CONFIGURACIÓN DUAL - WiFi Compartido + Hotspot

## 🎯 TU SISTEMA AHORA FUNCIONA EN 2 ESCENARIOS

---

## ✅ ESCENARIO 1: WIFI COMPARTIDO (Todos en la misma red)

### 📍 Situación:
- Hay un router WiFi en la escuela
- Tú y los maestros se conectan al mismo WiFi
- Todos tienen IPs como: 192.168.1.x

### 🔧 Configuración:

**Tu PC:**
- IP: `192.168.1.132` (o la que te asigne el router)
- Hostname: `coordinacion-tescha`

**Los maestros acceden con:**
```
http://coordinacion-tescha.local
```

o

```
http://192.168.1.132
```

### ✅ Ventajas:
- ✅ Dominio `.local` funciona automáticamente (con Bonjour/mDNS)
- ✅ Sin configuración adicional
- ✅ Más estable

---

## ✅ ESCENARIO 2: HOTSPOT (Tú compartes internet)

### 📍 Situación:
- NO hay WiFi en la escuela
- Tú compartes internet desde tu PC (Hotspot)
- Los maestros se conectan a TU hotspot

### 🔧 Configuración:

#### PASO 1: Activar Hotspot en Windows

1. **Abre Configuración** → Red e Internet → Zona con cobertura inalámbrica móvil
2. **Activa** "Compartir mi conexión a Internet"
3. **Nombre de red:** `TESCHA-WiFi` (o el que quieras)
4. **Contraseña:** (elige una segura)

#### PASO 2: Verificar tu IP del Hotspot

```powershell
ipconfig
```

Busca la sección **"Adaptador de LAN inalámbrica Conexión de área local"**:
```
IPv4: 192.168.137.1
```

(Normalmente Windows usa `192.168.137.1` para hotspot)

#### PASO 3: Los maestros se conectan

**WiFi:** `TESCHA-WiFi`  
**Contraseña:** (la que configuraste)

**Acceden con:**
```
http://192.168.137.1
```

### ⚠️ IMPORTANTE:

En modo Hotspot, `coordinacion-tescha.local` **NO funcionará** porque mDNS/Bonjour no funciona bien en redes de hotspot.

**Solución:** Los maestros usan directamente la IP:
```
http://192.168.137.1
```

---

## 📊 COMPARACIÓN

| Característica | WiFi Compartido | Hotspot |
|----------------|-----------------|---------|
| **URL** | `coordinacion-tescha.local` | `192.168.137.1` |
| **Configuración** | ✅ Ninguna | ⚠️ Activar hotspot |
| **Estabilidad** | ✅ Alta | ⚠️ Media |
| **Velocidad** | ✅ Rápida | ⚠️ Depende de tu conexión |
| **Número de usuarios** | ✅ Ilimitado | ⚠️ Máximo 8-10 |

---

## 🚀 CÓMO SABER QUÉ IP USAR

### Comando para ver todas tus IPs:

```powershell
ipconfig | findstr "IPv4"
```

**Resultado esperado:**
```
IPv4: 192.168.1.132     ← WiFi compartido
IPv4: 192.168.137.1     ← Hotspot (si está activo)
```

---

## 📝 INSTRUCCIONES PARA LOS MAESTROS

### Si hay WiFi en la escuela:

```
1. Conectarse al WiFi de la escuela
2. Abrir navegador
3. Escribir: http://coordinacion-tescha.local
4. ¡Listo!
```

### Si usas Hotspot:

```
1. Conectarse al WiFi: TESCHA-WiFi
2. Contraseña: [la que configuraste]
3. Abrir navegador
4. Escribir: http://192.168.137.1
5. ¡Listo!
```

---

## 🔧 CONFIGURACIÓN ACTUAL DEL SISTEMA

### ✅ Backend (CORS):
```javascript
Orígenes permitidos:
- http://localhost:3000
- http://127.0.0.1:3000
- http://coordinacion-tescha.local
- http://192.168.1.132          ← WiFi compartido
- http://192.168.1.132:3000
- http://192.168.137.1          ← Hotspot
- http://192.168.137.1:3000
```

### ✅ Frontend (Vite):
```javascript
host: '0.0.0.0'  ← Escucha en TODAS las interfaces
allowedHosts: [
  'localhost',
  'coordinacion-tescha.local',
  '.local'
]
```

### ✅ Nginx:
```nginx
server_name: 192.168.1.132 coordinacion-tescha.local localhost _;
listen: 80
```

---

## 🧪 PRUEBAS

### En WiFi Compartido:

```powershell
# Desde tu PC
ping coordinacion-tescha.local
curl http://coordinacion-tescha.local

# Desde PC de un maestro
ping coordinacion-tescha.local
# Abrir navegador: http://coordinacion-tescha.local
```

### En Hotspot:

```powershell
# Desde tu PC
ipconfig | findstr "192.168.137"
curl http://192.168.137.1

# Desde PC de un maestro conectado a tu hotspot
ping 192.168.137.1
# Abrir navegador: http://192.168.137.1
```

---

## 💡 RECOMENDACIONES

### Para la escuela (producción):

1. **Usa WiFi compartido** si hay router disponible
2. **Configura Bonjour** para que `coordinacion-tescha.local` funcione
3. **Mantén tu PC conectada** al WiFi todo el tiempo

### Para emergencias (sin WiFi):

1. **Activa Hotspot** desde tu PC
2. **Comparte la IP** `192.168.137.1` con los maestros
3. **Limita a 8-10 usuarios** simultáneos

---

## 🎯 RESUMEN

**Tu sistema YA está configurado para AMBOS escenarios:**

✅ **WiFi Compartido:** `http://coordinacion-tescha.local`  
✅ **Hotspot:** `http://192.168.137.1`

**Sin configuración adicional necesaria** 🎉

---

## 📞 SOPORTE RÁPIDO

### Si los maestros no pueden conectarse:

1. **Verificar que estén en la misma red:**
   ```powershell
   ipconfig
   ```
   Deben tener IPs en el mismo rango (192.168.1.x o 192.168.137.x)

2. **Verificar firewall:**
   ```powershell
   # Permitir puerto 80
   New-NetFirewallRule -DisplayName "TESCHA HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
   ```

3. **Reiniciar servicios:**
   ```powershell
   # Backend
   cd C:\Users\dush3\Downloads\TESCHA\backend
   npm run pm2:restart
   
   # Nginx
   taskkill /f /im nginx.exe
   cd C:\nginx
   start nginx
   ```

---

¡Todo listo para ambos escenarios! 🚀
