# 🌐 GUÍA: BONJOUR/MDNS PARA WINDOWS (IGUAL QUE AVAHI EN UBUNTU)

## 🎯 OBJETIVO

Que los maestros accedan con `http://coordinacion-tescha.local` **SIN configurar nada** en sus PCs.

---

## 📋 ¿QUÉ ES BONJOUR/MDNS?

- **Avahi** (Linux/Ubuntu) = **Bonjour** (Windows/Mac)
- **mDNS** = Multicast DNS (descubrimiento automático en red local)
- **Resultado:** Los nombres `.local` funcionan automáticamente

---

## 🚀 INSTALACIÓN PASO A PASO

### PASO 1: Instalar Bonjour en tu PC Windows

**Opción A: Bonjour Print Services (Recomendado)**
```
1. Descarga: https://support.apple.com/kb/DL999
2. Ejecuta: BonjourPSSetup.exe
3. Siguiente → Siguiente → Instalar
4. Finalizar
```

**Opción B: Instalar iTunes (incluye Bonjour)**
```
1. Descarga iTunes desde: https://www.apple.com/itunes/
2. Instala iTunes (Bonjour se instala automáticamente)
```

---

### PASO 2: Cambiar hostname de Windows

Para que funcione `coordinacion-tescha.local`, tu PC debe llamarse `coordinacion-tescha`.

**Método 1: PowerShell (Rápido)**
```powershell
# Ejecutar como Administrador
Rename-Computer -NewName "coordinacion-tescha" -Force
Restart-Computer
```

**Método 2: Interfaz Gráfica**
```
1. Panel de Control → Sistema
2. Configuración avanzada del sistema
3. Pestaña "Nombre de equipo"
4. Cambiar → Nombre de equipo: coordinacion-tescha
5. Aceptar → Reiniciar
```

---

### PASO 3: Verificar servicio Bonjour

```powershell
# Ver si está corriendo
Get-Service "Bonjour Service"

# Si no está corriendo, iniciarlo
Start-Service "Bonjour Service"

# Configurar inicio automático
Set-Service "Bonjour Service" -StartupType Automatic
```

---

### PASO 4: Configurar Nginx (puerto 80)

Tu `nginx.conf` debe escuchar en puerto 80:

```nginx
server {
    listen 80;
    server_name coordinacion-tescha.local _;
    
    location / {
        proxy_pass http://127.0.0.1:3000;
        # ... resto de configuración
    }
}
```

---

## ✅ VERIFICACIÓN

### En tu PC (servidor):

```powershell
# 1. Verificar hostname
hostname
# Debe mostrar: coordinacion-tescha

# 2. Verificar Bonjour
Get-Service "Bonjour Service"
# Debe estar: Running

# 3. Verificar Nginx
tasklist /fi "imagename eq nginx.exe"
# Debe mostrar 2 procesos

# 4. Probar localmente
# Abrir navegador: http://coordinacion-tescha.local
```

### Desde otra PC en la red:

```
1. Conectarse al mismo WiFi
2. Abrir navegador
3. Escribir: http://coordinacion-tescha.local
4. ¡Debería funcionar SIN configurar nada!
```

---

## 🔍 CÓMO FUNCIONA (TÉCNICO)

```
1. Tu PC se llama: coordinacion-tescha
2. Bonjour anuncia en la red: coordinacion-tescha.local → 192.168.1.132
3. Otros dispositivos con soporte mDNS resuelven automáticamente
4. No necesitan DNS ni archivo hosts
```

**Protocolo:** mDNS (Multicast DNS) - RFC 6762

---

## 📊 COMPARACIÓN

| Método | Configuración Maestros | Funciona |
|--------|------------------------|----------|
| **IP directa** | ❌ Nada | ✅ Sí |
| **Bonjour/mDNS** | ❌ Nada | ✅ Sí |
| **DNS Router** | ❌ Nada | ✅ Sí (necesitas acceso) |
| **Archivo hosts** | ⚠️ Cada PC | ✅ Sí |

---

## 🎯 VENTAJAS DE BONJOUR/MDNS

- ✅ **Cero configuración** en PCs de maestros
- ✅ **Funciona automáticamente** en Windows, Mac, Linux
- ✅ **No necesitas acceso al router**
- ✅ **Dominio .local profesional**
- ✅ **Igual que Avahi en Ubuntu**

---

## ⚠️ REQUISITOS

### En tu PC (servidor):
- ✅ Bonjour instalado
- ✅ Hostname: `coordinacion-tescha`
- ✅ Nginx en puerto 80
- ✅ Frontend y Backend corriendo

### En PCs de maestros:
- ✅ **NADA** (Windows 10/11 ya soporta mDNS)
- ✅ Solo conectarse al WiFi

---

## 🧪 PRUEBA RÁPIDA

### Desde PowerShell:

```powershell
# Resolver el nombre .local
Resolve-DnsName coordinacion-tescha.local

# Debería mostrar:
# Name: coordinacion-tescha.local
# Address: 192.168.1.132
```

### Desde navegador:

```
http://coordinacion-tescha.local
```

---

## 🚨 SOLUCIÓN DE PROBLEMAS

### Error: "No se puede resolver coordinacion-tescha.local"

**Causa 1:** Bonjour no está instalado
```powershell
Get-Service "Bonjour Service"
# Si no existe, instalar Bonjour
```

**Causa 2:** Hostname incorrecto
```powershell
hostname
# Debe ser: coordinacion-tescha
```

**Causa 3:** Firewall bloqueando mDNS (puerto 5353 UDP)
```powershell
# Permitir mDNS en firewall
New-NetFirewallRule -DisplayName "mDNS" -Direction Inbound -Protocol UDP -LocalPort 5353 -Action Allow
```

---

## 📝 SCRIPT DE INSTALACIÓN AUTOMÁTICA

Ejecuta:
```powershell
cd C:\Users\dush3\Downloads\TESCHA
.\configurar-bonjour-mdns.ps1
```

El script hace TODO automáticamente.

---

## 🎉 RESULTADO FINAL

**Los maestros:**
1. Se conectan al WiFi de la escuela
2. Abren el navegador
3. Escriben: `http://coordinacion-tescha.local`
4. ¡Funciona! SIN configurar nada

**Igual que Avahi en Ubuntu** 🚀

---

## 💡 ALTERNATIVA SI BONJOUR NO FUNCIONA

Si por alguna razón Bonjour no funciona, usa IP directa:

```
http://192.168.1.132
```

Con Nginx en puerto 80, funciona igual de bien.

---

## ✅ RESUMEN

| Componente | Estado |
|------------|--------|
| **Bonjour** | ✅ Instalado |
| **Hostname** | ✅ coordinacion-tescha |
| **Nginx** | ✅ Puerto 80 |
| **mDNS** | ✅ Activo |
| **Dominio** | ✅ coordinacion-tescha.local |
| **Configuración maestros** | ❌ Ninguna |

**¡Listo para usar!** 🎉
