# 🛠️ Scripts de TESCHA

Esta carpeta contiene todos los scripts PowerShell para instalación, configuración y mantenimiento del sistema TESCHA.

## 📂 Estructura

### 📦 `/instalacion`
Scripts para instalar el sistema y sus componentes:

- **`instalar-todo.ps1`** ⭐ - **SCRIPT PRINCIPAL** - Instalación automática completa
  - Verifica Node.js y PostgreSQL
  - Instala todas las dependencias
  - Configura Bonjour (mDNS)
  - Instala Nginx
  - Configura el nombre de PC

- **`instalar-nginx.ps1`** - Instalación de Nginx
- **`instalar-nginx-manual.ps1`** - Instalación manual de Nginx
- **`instalar-nginx-simple.ps1`** - Instalación simplificada de Nginx
- **`instalar-mejoras.ps1`** - Instalación de mejoras adicionales

### ⚙️ `/configuracion`
Scripts para configurar servicios y seguridad:

- **`configurar-bonjour-mdns.ps1`** - Configuración de Bonjour/mDNS para acceso `.local`
- **`configurar-dns-local.ps1`** - Configuración de DNS local
- **`configurar-seguridad.ps1`** - Configuración de seguridad del sistema

### 🔧 `/mantenimiento`
Scripts para operación diaria y diagnóstico:

- **`detectar-red.ps1`** ⭐ - **MUY ÚTIL** - Detecta qué URL usar (WiFi/Hotspot)
  - Muestra todas las IPs activas
  - Indica qué URL deben usar los maestros
  - Verifica estado de servicios (Nginx, Frontend, Backend)

- **`reiniciar-nginx.ps1`** - Reinicia Nginx
- **`reiniciar_servidor.ps1`** - Reinicia todos los servicios
- **`reiniciar_servidor_rapido.ps1`** - Reinicio rápido de servicios
- **`verificar_optimizacion.ps1`** - Verifica el estado de optimización

## 🚀 Uso Rápido

### Primera instalación (ejecutar como Administrador):
```powershell
cd C:\TESCHA
.\scripts\instalacion\instalar-todo.ps1
```

### Detectar qué URL usar:
```powershell
cd C:\TESCHA
.\scripts\mantenimiento\detectar-red.ps1
```

### Reiniciar servicios:
```powershell
cd C:\TESCHA
.\scripts\mantenimiento\reiniciar_servidor_rapido.ps1
```

## ⚠️ Importante

- Los scripts de **instalación** requieren permisos de **Administrador**
- Los scripts de **mantenimiento** pueden ejecutarse sin permisos especiales
- Siempre ejecuta los scripts desde la raíz del proyecto TESCHA

## 📝 Notas

- Todos los scripts tienen mensajes coloridos y claros
- Incluyen validaciones de errores
- Muestran el progreso de cada paso
- Son seguros de ejecutar múltiples veces

## 🔗 Documentación Relacionada

Ver la carpeta [`/docs/guias`](../docs/guias) para guías detalladas de uso.
