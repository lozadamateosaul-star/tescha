# 🖥️ COMANDOS ÚTILES - PowerShell

## 📦 Instalación Inicial

### Instalar Backend
```powershell
cd backend
npm install
```

### Instalar Frontend
```powershell
cd frontend
npm install
```

## 🗄️ Base de Datos

### Crear base de datos
```powershell
# Abrir PostgreSQL
psql -U postgres

# Dentro de psql:
CREATE DATABASE tescha_db;
\q
```

### Ejecutar schema manualmente
```powershell
cd backend
psql -U postgres -d tescha_db -f database/schema.sql
```

### Ejecutar datos de prueba
```powershell
cd backend
psql -U postgres -d tescha_db -f database/seed.sql
```

### Usar script de inicialización
```powershell
cd backend
npm run init-db
```

### Backup de base de datos
```powershell
pg_dump -U postgres tescha_db > backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').sql
```

### Restaurar backup
```powershell
psql -U postgres -d tescha_db < backup_20251201_120000.sql
```

## 🚀 Ejecutar el Sistema

### Iniciar Backend (desarrollo)
```powershell
cd backend
npm run dev
```

### Iniciar Backend (producción)
```powershell
cd backend
npm start
```

### Iniciar Frontend (desarrollo)
```powershell
cd frontend
npm run dev
```

### Iniciar Frontend (producción)
```powershell
cd frontend
npm run build
npm run preview
```

## 🔧 Mantenimiento

### Actualizar dependencias
```powershell
# Backend
cd backend
npm update

# Frontend
cd frontend
npm update
```

### Verificar vulnerabilidades
```powershell
npm audit
npm audit fix
```

### Limpiar node_modules y reinstalar
```powershell
# Backend
cd backend
Remove-Item -Recurse -Force node_modules
Remove-Item package-lock.json
npm install

# Frontend
cd frontend
Remove-Item -Recurse -Force node_modules
Remove-Item package-lock.json
npm install
```

## 📊 PostgreSQL - Comandos Útiles

### Ver todas las bases de datos
```powershell
psql -U postgres -c "\l"
```

### Ver tablas de la base de datos
```powershell
psql -U postgres -d tescha_db -c "\dt"
```

### Ver estructura de una tabla
```powershell
psql -U postgres -d tescha_db -c "\d alumnos"
```

### Contar registros
```powershell
psql -U postgres -d tescha_db -c "SELECT COUNT(*) FROM alumnos;"
```

### Ver últimos alumnos registrados
```powershell
psql -U postgres -d tescha_db -c "SELECT * FROM alumnos ORDER BY created_at DESC LIMIT 5;"
```

## 🧹 Limpiar el Sistema

### Eliminar logs
```powershell
Remove-Item backend/*.log -ErrorAction SilentlyContinue
```

### Limpiar cache de npm
```powershell
npm cache clean --force
```

### Reiniciar base de datos
```powershell
# ⚠️ CUIDADO: Esto elimina todos los datos
psql -U postgres -c "DROP DATABASE tescha_db;"
psql -U postgres -c "CREATE DATABASE tescha_db;"
cd backend
npm run init-db
```

## 🔍 Debugging

### Ver logs del backend en tiempo real
```powershell
cd backend
Get-Content *.log -Wait
```

### Verificar que PostgreSQL está corriendo
```powershell
Get-Service -Name postgresql*
```

### Iniciar PostgreSQL (si está detenido)
```powershell
Start-Service postgresql-x64-14  # Ajustar nombre del servicio
```

### Ver puertos en uso
```powershell
# Puerto 5000 (backend)
netstat -ano | Select-String ":5000"

# Puerto 3000 (frontend)
netstat -ano | Select-String ":3000"

# Puerto 5432 (PostgreSQL)
netstat -ano | Select-String ":5432"
```

### Matar proceso en puerto específico
```powershell
# Encontrar PID
$port = 5000
$pid = (Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue).OwningProcess

# Matar proceso
Stop-Process -Id $pid -Force
```

## 📦 Build para Producción

### Backend
```powershell
cd backend

# Copiar archivos necesarios
Copy-Item package.json, package-lock.json, server.js, config/, routes/, middleware/, database/ -Destination ./dist/ -Recurse

# Instalar solo dependencias de producción
cd dist
npm install --production
```

### Frontend
```powershell
cd frontend

# Build
npm run build

# Los archivos estarán en frontend/dist/
# Copiar a servidor web (nginx, apache, etc.)
```

## 🌐 Variables de Entorno

### Copiar archivos de ejemplo
```powershell
# Backend
Copy-Item backend/.env.example backend/.env

# Frontend
Copy-Item frontend/.env.example frontend/.env
```

### Editar variables de entorno
```powershell
# Backend
notepad backend/.env

# Frontend
notepad frontend/.env
```

## 📊 Estadísticas del Proyecto

### Contar líneas de código
```powershell
# Backend
(Get-ChildItem -Path backend/*.js -Recurse | Get-Content).Count

# Frontend
(Get-ChildItem -Path frontend/src/*.jsx -Recurse | Get-Content).Count
```

### Tamaño del proyecto
```powershell
# Total (sin node_modules)
$size = (Get-ChildItem -Path . -Recurse -Exclude node_modules | Measure-Object -Property Length -Sum).Sum / 1MB
Write-Host "Tamaño: $([math]::Round($size, 2)) MB"
```

## 🔐 Seguridad

### Cambiar contraseña del coordinador
```powershell
# Generar hash de nueva contraseña (usar en Node.js)
node -e "console.log(require('bcryptjs').hashSync('nueva_password', 10))"

# Actualizar en base de datos
psql -U postgres -d tescha_db -c "UPDATE usuarios SET password = 'HASH_AQUI' WHERE username = 'coordinador';"
```

## 🧪 Testing (cuando se implemente)

### Ejecutar tests
```powershell
# Backend
cd backend
npm test

# Frontend
cd frontend
npm test
```

## 📝 Git (cuando se use control de versiones)

### Inicializar repositorio
```powershell
git init
git add .
git commit -m "Commit inicial - Sistema TESCHA"
```

### Crear .gitignore
```powershell
# Ya existe en la raíz del proyecto
Get-Content .gitignore
```

## 🆘 Troubleshooting

### "Cannot find module"
```powershell
cd backend  # o frontend
npm install
```

### "Port already in use"
```powershell
# Ver qué proceso usa el puerto
netstat -ano | Select-String ":5000"

# Matar proceso (usar PID del comando anterior)
Stop-Process -Id XXXX -Force
```

### "Cannot connect to database"
```powershell
# Verificar que PostgreSQL está corriendo
Get-Service postgresql*

# Iniciar si está detenido
Start-Service postgresql-x64-14

# Verificar credenciales en backend/.env
notepad backend/.env
```

### Reinstalar todo desde cero
```powershell
# Backend
cd backend
Remove-Item -Recurse -Force node_modules, package-lock.json
npm install

# Frontend
cd frontend
Remove-Item -Recurse -Force node_modules, package-lock.json
npm install

# Base de datos
psql -U postgres -c "DROP DATABASE tescha_db;"
psql -U postgres -c "CREATE DATABASE tescha_db;"
cd backend
npm run init-db
```

## 📚 Recursos Adicionales

### Abrir documentación
```powershell
# README principal
notepad README.md

# Inicio rápido
notepad INICIO-RAPIDO.md

# Notas técnicas
notepad NOTAS-TECNICAS.md

# Resumen ejecutivo
notepad RESUMEN-EJECUTIVO.md
```

### Ver estructura del proyecto
```powershell
tree /F
```

---

**Nota:** Ajustar comandos según tu configuración específica de PostgreSQL y Node.js.
