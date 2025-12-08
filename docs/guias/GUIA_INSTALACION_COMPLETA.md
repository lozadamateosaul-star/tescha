# 🚀 GUÍA DE INSTALACIÓN COMPLETA - TESCHA
## Instalación en la computadora del coordinador

---

## 📋 REQUISITOS PREVIOS

- ✅ Windows 10/11
- ✅ Conexión a internet (para descargas iniciales)
- ✅ Permisos de Administrador
- ✅ Al menos 2GB de espacio en disco

---

## 🎯 INSTALACIÓN PASO A PASO

### PASO 1: Instalar Node.js (Motor de JavaScript)

1. **Descargar Node.js:**
   - Ve a: https://nodejs.org/
   - Descarga la versión **LTS** (Recomendada)
   - Archivo: `node-v20.x.x-x64.msi` (o la versión actual)

2. **Instalar:**
   - Doble clic en el instalador
   - Siguiente → Siguiente → Instalar
   - **Importante:** Marcar la casilla "Automatically install necessary tools"
   - Finalizar

3. **Verificar instalación:**
   ```powershell
   node --version
   npm --version
   ```
   Debe mostrar las versiones instaladas.

---

### PASO 2: Instalar PostgreSQL (Base de Datos)

1. **Descargar PostgreSQL:**
   - Ve a: https://www.postgresql.org/download/windows/
   - Descarga PostgreSQL 15 o superior
   - Archivo: `postgresql-15.x-windows-x64.exe`

2. **Instalar:**
   - Doble clic en el instalador
   - Siguiente → Siguiente
   - **Contraseña para postgres:** `admin123` (o la que prefieras, **ANÓTALA**)
   - Puerto: `5432` (dejar por defecto)
   - Siguiente → Instalar

3. **Verificar instalación:**
   - Buscar "pgAdmin 4" en el menú inicio
   - Abrir pgAdmin
   - Conectar con contraseña que configuraste

---

### PASO 3: Copiar el proyecto TESCHA

1. **Copiar la carpeta completa:**
   ```
   Desde: USB/Disco/Descarga
   A: C:\TESCHA
   ```

2. **Verificar estructura:**
   ```
   C:\TESCHA\
   ├── backend\
   ├── frontend\
   ├── nginx.conf
   ├── instalar-nginx.ps1
   └── GUIA_INSTALACION.md (este archivo)
   ```

---

### PASO 4: Configurar la Base de Datos

1. **Crear la base de datos:**
   
   Abre PowerShell como Administrador:
   ```powershell
   # Conectar a PostgreSQL
   psql -U postgres
   
   # Crear base de datos
   CREATE DATABASE tescha;
   
   # Salir
   \q
   ```

2. **Importar el esquema:**
   ```powershell
   cd C:\TESCHA\backend\database
   psql -U postgres -d tescha -f schema.sql
   psql -U postgres -d tescha -f seed.sql
   ```

3. **Verificar:**
   ```powershell
   psql -U postgres -d tescha -c "\dt"
   ```
   Debe mostrar las tablas creadas.

---

### PASO 5: Configurar el Backend

1. **Instalar dependencias:**
   ```powershell
   cd C:\TESCHA\backend
   npm install
   ```
   (Esto puede tardar 3-5 minutos)

2. **Configurar variables de entorno:**
   
   Copia el archivo `.env.example` a `.env`:
   ```powershell
   Copy-Item .env.example .env
   ```

3. **Editar el archivo `.env`:**
   ```powershell
   notepad .env
   ```
   
   Configurar:
   ```env
   # Base de datos
   DB_USER=postgres
   DB_PASSWORD=admin123
   DB_HOST=localhost
   DB_PORT=5432
   DB_NAME=tescha
   
   # Servidor
   PORT=5000
   NODE_ENV=production
   
   # Seguridad (CAMBIAR ESTOS VALORES)
   JWT_SECRET=tu-secreto-super-seguro-aqui-cambiar
   ENCRYPTION_KEY=otra-clave-secreta-de-32-caracteres-cambiar
   
   # Frontend
   FRONTEND_URL=http://coordinacion-tescha.local
   
   # Email (Opcional - para alertas)
   SECURITY_ALERT_EMAIL=coordinador@escuela.edu.mx
   ENABLE_EMAIL_ALERTS=false
   ```

4. **Instalar PM2 (Gestor de procesos):**
   ```powershell
   npm install -g pm2
   ```

5. **Iniciar el backend:**
   ```powershell
   npm run pm2:start
   ```

6. **Verificar:**
   ```powershell
   npm run pm2:status
   ```
   Debe mostrar: `tescha-backend | online`

---

### PASO 6: Configurar el Frontend

1. **Instalar dependencias:**
   ```powershell
   cd C:\TESCHA\frontend
   npm install
   ```
   (Esto puede tardar 3-5 minutos)

2. **Construir para producción:**
   ```powershell
   npm run build
   ```
   (Esto crea la versión optimizada)

3. **Instalar servidor HTTP simple:**
   ```powershell
   npm install -g serve
   ```

4. **Iniciar el frontend:**
   ```powershell
   # En una nueva ventana de PowerShell
   cd C:\TESCHA\frontend
   serve -s dist -l 3000
   ```

---

### PASO 7: Instalar Bonjour (mDNS)

1. **Descargar Bonjour:**
   - Ve a: https://support.apple.com/kb/DL999
   - Descarga: `BonjourPSSetup.exe`

2. **Instalar:**
   - Doble clic en el instalador
   - Siguiente → Instalar → Finalizar

3. **Verificar:**
   ```powershell
   Get-Service "Bonjour Service"
   ```
   Debe mostrar: `Running`

---

### PASO 8: Cambiar nombre de la PC

**⚠️ IMPORTANTE: Esto reiniciará la computadora**

```powershell
# Abrir PowerShell como Administrador
Rename-Computer -NewName "coordinacion-tescha" -Force
Restart-Computer
```

Después del reinicio, el nombre de la PC será `coordinacion-tescha`.

---

### PASO 9: Instalar Nginx

1. **Ejecutar script de instalación:**
   ```powershell
   # Como Administrador
   cd C:\TESCHA
   .\instalar-nginx.ps1
   ```

2. **Verificar:**
   ```powershell
   tasklist /fi "imagename eq nginx.exe"
   ```
   Debe mostrar 2 procesos nginx.exe

3. **Probar:**
   Abrir navegador: `http://localhost`
   Debe mostrar la aplicación TESCHA

---

### PASO 10: Configurar inicio automático

Para que todo inicie automáticamente al encender la PC:

1. **Crear script de inicio:**
   ```powershell
   notepad C:\TESCHA\iniciar-tescha.ps1
   ```

2. **Contenido del script:**
   ```powershell
   # Iniciar Backend
   cd C:\TESCHA\backend
   pm2 start ecosystem.config.cjs
   
   # Iniciar Frontend
   Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd C:\TESCHA\frontend; serve -s dist -l 3000"
   
   # Iniciar Nginx
   cd C:\nginx
   start nginx
   
   Write-Host "✅ TESCHA iniciado correctamente" -ForegroundColor Green
   ```

3. **Crear tarea programada:**
   - Abrir "Programador de tareas"
   - Crear tarea básica
   - Nombre: "Iniciar TESCHA"
   - Desencadenador: Al iniciar sesión
   - Acción: Iniciar programa
   - Programa: `powershell.exe`
   - Argumentos: `-ExecutionPolicy Bypass -File C:\TESCHA\iniciar-tescha.ps1`
   - Finalizar

---

## ✅ VERIFICACIÓN FINAL

### 1. Verificar servicios:

```powershell
cd C:\TESCHA
.\detectar-red.ps1
```

Debe mostrar:
- ✅ Nginx: Corriendo
- ✅ Frontend: Corriendo en puerto 3000
- ✅ Backend: Corriendo en puerto 5000

### 2. Probar acceso local:

Abrir navegador:
```
http://coordinacion-tescha.local
```

Debe mostrar la página de login de TESCHA.

### 3. Probar login:

- **Usuario:** `coordinador`
- **Contraseña:** `Tescha2024!` (o la que configuraste)

---

## 🌐 ACCESO PARA LOS MAESTROS

### Instrucciones para los maestros:

```
1. Conectarse al WiFi de la escuela
2. Abrir navegador (Chrome, Edge, Firefox)
3. Escribir: http://coordinacion-tescha.local
4. Hacer login con sus credenciales
```

**¡Listo!** Sin configurar nada en sus computadoras.

---

## 🔧 COMANDOS ÚTILES

### Reiniciar servicios:

```powershell
# Backend
cd C:\TESCHA\backend
npm run pm2:restart

# Nginx
taskkill /f /im nginx.exe
cd C:\nginx
start nginx

# Frontend
# Cerrar la ventana de PowerShell y volver a ejecutar:
cd C:\TESCHA\frontend
serve -s dist -l 3000
```

### Ver logs:

```powershell
# Backend
cd C:\TESCHA\backend
npm run pm2:logs

# Nginx
Get-Content C:\nginx\logs\error.log -Tail 20
```

### Detener todo:

```powershell
# Backend
cd C:\TESCHA\backend
npm run pm2:stop

# Nginx
taskkill /f /im nginx.exe

# Frontend
# Cerrar la ventana de PowerShell
```

---

## 📊 RESUMEN DE PUERTOS

| Servicio | Puerto | URL |
|----------|--------|-----|
| **Nginx** | 80 | `http://coordinacion-tescha.local` |
| **Frontend** | 3000 | `http://localhost:3000` (interno) |
| **Backend** | 5000 | `http://localhost:5000` (interno) |
| **PostgreSQL** | 5432 | `localhost:5432` (interno) |

---

## 🆘 SOLUCIÓN DE PROBLEMAS

### Error: "No se puede conectar a la base de datos"

```powershell
# Verificar que PostgreSQL esté corriendo
Get-Service postgresql*

# Si no está corriendo, iniciarlo
Start-Service postgresql-x64-15
```

### Error: "Puerto 80 ocupado"

```powershell
# Ver qué está usando el puerto 80
netstat -ano | findstr :80

# Detener IIS si está instalado
iisreset /stop
```

### Error: "coordinacion-tescha.local no se resuelve"

```powershell
# Verificar Bonjour
Get-Service "Bonjour Service"

# Si no está corriendo
Start-Service "Bonjour Service"

# Verificar nombre de PC
hostname
# Debe mostrar: coordinacion-tescha
```

---

## 📞 SOPORTE

Si tienes problemas durante la instalación:

1. Ejecuta el script de diagnóstico:
   ```powershell
   cd C:\TESCHA
   .\detectar-red.ps1
   ```

2. Revisa los logs de error

3. Contacta al desarrollador con:
   - Captura de pantalla del error
   - Resultado del script de diagnóstico
   - Logs relevantes

---

## 🎉 ¡INSTALACIÓN COMPLETADA!

Tu sistema TESCHA está listo para usar en producción.

**Características:**
- ✅ Acceso con dominio local (`coordinacion-tescha.local`)
- ✅ Sin configuración en PCs de maestros
- ✅ Sistema de seguridad anti-hackeo
- ✅ Inicio automático al encender la PC
- ✅ Logs y monitoreo incluidos

**¡Bienvenido a TESCHA!** 🚀
