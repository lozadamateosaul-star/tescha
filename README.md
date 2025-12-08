# 🎓 TESCHA - Sistema de Coordinación de Inglés

Sistema completo de gestión para coordinación de inglés con acceso local vía dominio `.local`

---

## 🚀 INSTALACIÓN RÁPIDA

### Para la computadora del coordinador:

```powershell
# 1. Abrir PowerShell como Administrador
# 2. Ejecutar:
cd C:\TESCHA
.\scripts\instalacion\instalar-todo.ps1
```

**El script instalará automáticamente:**
- ✅ Verificará Node.js y PostgreSQL
- ✅ Instalará todas las dependencias
- ✅ Configurará Bonjour (mDNS)
- ✅ Instalará Nginx
- ✅ Configurará el nombre de PC

---

## 📚 DOCUMENTACIÓN

Toda la documentación está organizada en la carpeta [`/docs`](./docs):

- **📖 [Guías](./docs/guias)** - Instalación, configuración y uso
  - [Guía de Instalación Completa](./docs/guias/GUIA_INSTALACION_COMPLETA.md)
  - [Guía WiFi Hotspot](./docs/guias/GUIA_WIFI_HOTSPOT.md)
  - [Guía Bonjour mDNS](./docs/guias/GUIA_BONJOUR_MDNS.md)
  - [Inicio Rápido](./docs/guias/INICIO-RAPIDO.md)

- **🔒 [Seguridad](./docs/seguridad)** - Auditorías y certificaciones
  - [Auditoría de Seguridad](./docs/seguridad/AUDITORIA_SEGURIDAD.md)
  - [Certificación de Seguridad](./docs/seguridad/CERTIFICACION-SEGURIDAD.md)
  - [Informe de Seguridad](./docs/seguridad/INFORME-SEGURIDAD.md)

- **📊 [Análisis](./docs/analisis)** - Análisis técnico y propuestas
- **✨ [Mejoras](./docs/mejoras)** - Nuevas funcionalidades implementadas
- **🔧 [Fixes](./docs/fixes)** - Correcciones y soluciones

Ver el [**índice completo de documentación**](./docs/README.md)

---

## 🌐 ACCESO

### Para los maestros:

```
1. Conectarse al WiFi de la escuela
2. Abrir navegador
3. Escribir: http://coordinacion-tescha.local
4. Hacer login
```

**Sin configurar nada en sus computadoras** ✅

---

## 🧪 PRUEBAS Y TESTS

Los scripts de pruebas y verificación están en la carpeta [`/tests`](./tests):
- **security-tests/** - Pruebas de seguridad automatizadas
- Scripts de verificación de sistema
- Tests de rendimiento

---

## 🛠️ SCRIPTS ÚTILES

Todos los scripts están organizados en la carpeta [`/scripts`](./scripts):

### 📦 Instalación
| Script | Descripción |
|--------|-------------|
| [`instalar-todo.ps1`](./scripts/instalacion/instalar-todo.ps1) | ⭐ Instalación automática completa |
| [`instalar-nginx.ps1`](./scripts/instalacion/instalar-nginx.ps1) | Instalación de Nginx |

### 🔧 Mantenimiento
| Script | Descripción |
|--------|-------------|
| [`detectar-red.ps1`](./scripts/mantenimiento/detectar-red.ps1) | ⭐ Detecta qué URL usar (WiFi/Hotspot) |
| [`reiniciar_servidor_rapido.ps1`](./scripts/mantenimiento/reiniciar_servidor_rapido.ps1) | Reinicio rápido de servicios |
| [`verificar_optimizacion.ps1`](./scripts/mantenimiento/verificar_optimizacion.ps1) | Verifica optimización |

### ⚙️ Configuración
| Script | Descripción |
|--------|-------------|
| [`configurar-bonjour-mdns.ps1`](./scripts/configuracion/configurar-bonjour-mdns.ps1) | Configura Bonjour/mDNS |
| [`configurar-seguridad.ps1`](./scripts/configuracion/configurar-seguridad.ps1) | Configura seguridad |

Ver [**todos los scripts**](./scripts/README.md)

---

## 🔧 COMANDOS RÁPIDOS

### Iniciar todo:

```powershell
# Backend
cd C:\TESCHA\backend
npm run pm2:start

# Frontend
cd C:\TESCHA\frontend
serve -s dist -l 3000

# Nginx
cd C:\nginx
start nginx
```

### Detener todo:

```powershell
# Backend
cd C:\TESCHA\backend
npm run pm2:stop

# Nginx
taskkill /f /im nginx.exe
```

### Ver logs:

```powershell
# Backend
cd C:\TESCHA\backend
npm run pm2:logs

# Nginx
Get-Content C:\nginx\logs\error.log -Tail 20
```

---

## 📊 ARQUITECTURA

```
Maestros (WiFi) → coordinacion-tescha.local
                        ↓
                    Nginx (Puerto 80)
                        ↓
        ┌───────────────┴───────────────┐
        ↓                               ↓
Frontend (Puerto 3000)        Backend (Puerto 5000)
    (React/Vite)                  (Node.js/Express)
                                        ↓
                                PostgreSQL (Puerto 5432)
```

---

## 🔒 SEGURIDAD

El sistema incluye **10 capas de seguridad:**

1. ✅ Autenticación JWT segura
2. ✅ Protección SQL Injection (100% queries parametrizadas)
3. ✅ Protección XSS (sanitización automática)
4. ✅ Rate Limiting (anti fuerza bruta)
5. ✅ Sistema de Detección de Intrusos (IDS)
6. ✅ Protección CSRF
7. ✅ Encriptación AES-256-GCM
8. ✅ Logging y auditoría completa
9. ✅ Security Headers (Helmet.js)
10. ✅ Notificaciones seguras (solo cron)

**Calificación:** A+ (95/100)

Ver [AUDITORIA_SEGURIDAD.md](AUDITORIA_SEGURIDAD.md) para más detalles.

---

## 📝 REQUISITOS

- Windows 10/11
- Node.js 18+ (LTS)
- PostgreSQL 15+
- 2GB RAM mínimo
- 5GB espacio en disco

---

## 🆘 SOPORTE

### Problemas comunes:

**"No se puede conectar a coordinacion-tescha.local"**
```powershell
# Verificar Bonjour
Get-Service "Bonjour Service"

# Verificar nombre de PC
hostname  # Debe mostrar: coordinacion-tescha
```

**"Puerto 80 ocupado"**
```powershell
# Detener IIS
iisreset /stop

# Reiniciar Nginx
taskkill /f /im nginx.exe
cd C:\nginx
start nginx
```

**"Error de base de datos"**
```powershell
# Verificar PostgreSQL
Get-Service postgresql*

# Iniciar si está detenido
Start-Service postgresql-x64-15
```

---

## 📞 CONTACTO

Para soporte técnico, consulta la documentación o ejecuta:

```powershell
cd C:\TESCHA
.\detectar-red.ps1
```

Este script te mostrará el estado de todos los servicios y la URL correcta para acceder.

---

## 📄 LICENCIA

Sistema desarrollado para el Tecnológico de Estudios Superiores de Chalco.

---

**¡Bienvenido a TESCHA!** 🚀
