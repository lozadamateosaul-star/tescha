# 🚀 Guía Completa de Despliegue en Render.com

## 📋 Requisitos Previos

1. ✅ Cuenta en [Render.com](https://render.com) (gratis)
2. ✅ Cuenta en [GitHub](https://github.com) (para subir el código)
3. ✅ Git instalado en tu computadora

## 🎯 Arquitectura en Render

```
┌─────────────────────────────────────────┐
│         USUARIOS (Internet)             │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│    Static Site (Frontend - React)       │
│    URL: tescha-frontend.onrender.com    │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│   Web Service (Backend - Node.js)       │
│    URL: tescha-api.onrender.com         │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│    PostgreSQL Database (Render)         │
│    Conexión interna                     │
└─────────────────────────────────────────┘
```

## 📦 PASO 1: Preparar el Proyecto para Render

### 1.1 Crear archivos de configuración

Ya he creado los archivos necesarios en tu proyecto. Verifica que existan:
- `render.yaml` (en la raíz)
- `backend/package.json` (actualizado)
- `frontend/.env.production` (nuevo)

### 1.2 Subir el proyecto a GitHub

```powershell
# Ir a la raíz del proyecto
cd C:\TESCHA

# Inicializar Git (si no está inicializado)
git init

# Agregar todos los archivos
git add .

# Hacer commit
git commit -m "Preparar proyecto para Render"

# Crear repositorio en GitHub y conectar
# Ve a github.com → New Repository → "TESCHA"
# Luego ejecuta:
git remote add origin https://github.com/TU_USUARIO/TESCHA.git
git branch -M main
git push -u origin main
```

## 🗄️ PASO 2: Crear Base de Datos PostgreSQL

1. **En Render Dashboard**, haz clic en **"Nuevo Postgres"** (la tarjeta que dice "Postgres")

2. **Configuración:**
   - **Name:** `tescha-db`
   - **Database:** `tescha`
   - **User:** `tescha_user` (o déjalo automático)
   - **Region:** `Oregon (US West)` (o el más cercano)
   - **Plan:** `Free` ✅

3. **Crear Database** → Espera 1-2 minutos

4. **Guardar estos datos** (los necesitarás):
   - Internal Database URL
   - External Database URL
   - Host
   - Port
   - Database
   - Username
   - Password

## ⚙️ PASO 3: Crear Web Service (Backend)

1. **En Render Dashboard**, haz clic en **"Nuevo servicio web"**

2. **Conectar GitHub:**
   - Autoriza Render a acceder a GitHub
   - Selecciona el repositorio `TESCHA`

3. **Configuración del servicio:**
   - **Name:** `tescha-backend`
   - **Region:** `Oregon (US West)` (mismo que la DB)
   - **Branch:** `main`
   - **Root Directory:** `backend`
   - **Runtime:** `Node`
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
   - **Plan:** `Free` ✅

4. **Variables de Entorno** (muy importante):

   Haz clic en "Advanced" → "Add Environment Variable" y agrega:

   ```
   NODE_ENV=production
   PORT=5000
   
   # Copiar de tu base de datos Render (Paso 2)
   DATABASE_URL=postgresql://tescha_user:PASSWORD@HOST:5432/tescha
   
   # O usar las variables individuales:
   DB_HOST=tu-db-host.render.com
   DB_PORT=5432
   DB_NAME=tescha
   DB_USER=tescha_user
   DB_PASSWORD=tu-password-aqui
   
   # JWT Secret (genera uno nuevo)
   JWT_SECRET=tu-secret-super-seguro-aqui-cambiar
   
   # CORS (URL de tu frontend - la obtendrás en el paso 4)
   FRONTEND_URL=https://tescha-frontend.onrender.com
   
   # Email (opcional - para notificaciones)
   EMAIL_USER=tu-email@gmail.com
   EMAIL_PASSWORD=tu-app-password
   ```

5. **Crear Web Service** → Espera 3-5 minutos

6. **Verificar:**
   - Ve a la URL: `https://tescha-backend.onrender.com`
   - Deberías ver un mensaje o JSON de tu API

## 🎨 PASO 4: Crear Static Site (Frontend)

1. **En Render Dashboard**, haz clic en **"Nuevo sitio estático"**

2. **Conectar GitHub:**
   - Selecciona el repositorio `TESCHA`

3. **Configuración del sitio:**
   - **Name:** `tescha-frontend`
   - **Branch:** `main`
   - **Root Directory:** `frontend`
   - **Build Command:** `npm install && npm run build`
   - **Publish Directory:** `dist`

4. **Variables de Entorno:**

   ```
   VITE_API_URL=https://tescha-backend.onrender.com
   ```

5. **Crear Static Site** → Espera 3-5 minutos

6. **Verificar:**
   - Ve a la URL: `https://tescha-frontend.onrender.com`
   - Deberías ver tu aplicación funcionando

## 🔄 PASO 5: Actualizar CORS en Backend

Ahora que tienes la URL del frontend, actualiza las variables de entorno del backend:

1. Ve a tu **Web Service (backend)** en Render
2. **Environment** → Editar `FRONTEND_URL`
3. Cambiar a: `https://tescha-frontend.onrender.com`
4. **Save Changes** → El servicio se reiniciará automáticamente

## 🗃️ PASO 6: Migrar Base de Datos

Necesitas crear las tablas en tu nueva base de datos de Render:

### Opción A: Desde tu computadora local

```powershell
# Conectarte a la base de datos de Render
# Usa el "External Database URL" que guardaste

psql "postgresql://tescha_user:PASSWORD@HOST:5432/tescha"

# Luego ejecuta tu schema
\i C:\TESCHA\backend\database\schema.sql

# Salir
\q
```

### Opción B: Desde Render Shell

1. Ve a tu **Web Service (backend)** en Render
2. **Shell** (en el menú superior)
3. Ejecuta:

```bash
# Conectar a la base de datos
psql $DATABASE_URL

# Pegar el contenido de tu schema.sql
# (copia y pega el contenido del archivo)

# Salir
\q
```

### Opción C: Importar datos existentes

Si tienes datos en tu base de datos local:

```powershell
# 1. Exportar desde tu DB local
pg_dump -U postgres tescha > backup_local.sql

# 2. Importar a Render
psql "postgresql://tescha_user:PASSWORD@HOST:5432/tescha" < backup_local.sql
```

## ✅ PASO 7: Verificación Final

### 7.1 Verificar Backend
```bash
# Prueba la API
curl https://tescha-backend.onrender.com/api/health
```

### 7.2 Verificar Frontend
- Abre: `https://tescha-frontend.onrender.com`
- Intenta hacer login
- Verifica que todo funcione

### 7.3 Verificar Base de Datos
```bash
# Conectar y verificar tablas
psql "postgresql://tescha_user:PASSWORD@HOST:5432/tescha"

# Ver tablas
\dt

# Ver usuarios
SELECT * FROM usuarios LIMIT 5;
```

## 🎉 URLs Finales

Después de completar todos los pasos:

- **Frontend:** `https://tescha-frontend.onrender.com`
- **Backend API:** `https://tescha-backend.onrender.com`
- **Base de Datos:** Acceso interno desde el backend

## ⚠️ Limitaciones del Plan Gratuito

### 🆓 Plan Free de Render:

1. **Web Services:**
   - ✅ 750 horas/mes gratis
   - ⚠️ Se "duerme" después de 15 minutos de inactividad
   - ⚠️ Primera carga puede tardar 30-60 segundos (mientras "despierta")
   - ✅ 512 MB RAM
   - ✅ 0.1 CPU

2. **PostgreSQL:**
   - ✅ 1 GB de almacenamiento
   - ✅ Expira después de 90 días (debes renovar gratis)
   - ⚠️ Sin backups automáticos

3. **Static Sites:**
   - ✅ Ilimitado
   - ✅ CDN global
   - ✅ Sin "sleep"

### 💡 Soluciones:

**Para evitar que se "duerma":**
- Usar un servicio de "ping" como [UptimeRobot](https://uptimerobot.com) (gratis)
- Configurar para hacer ping cada 10 minutos

**Para backups de DB:**
- Exportar manualmente cada semana
- O usar el script de backup que ya tienes

## 🔧 Troubleshooting

### Error: "Application failed to respond"
```bash
# Verificar logs del backend
# En Render Dashboard → Backend Service → Logs
```

### Error: "Cannot connect to database"
```bash
# Verificar variables de entorno
# Render Dashboard → Backend Service → Environment
# Asegúrate que DATABASE_URL esté correcto
```

### Error: "CORS policy"
```bash
# Verificar que FRONTEND_URL esté correcto en backend
# Y que el frontend use la URL correcta del backend
```

## 📝 Mantenimiento

### Actualizar el código:
```powershell
# Hacer cambios en tu código local
git add .
git commit -m "Descripción de cambios"
git push

# Render detectará el push y desplegará automáticamente
```

### Ver logs:
- Render Dashboard → Tu servicio → **Logs**

### Renovar base de datos (cada 90 días):
- Render te enviará un email
- Solo haz clic en "Extend for 90 days"

## 🎓 Próximos Pasos

1. ✅ Configura UptimeRobot para mantener el servicio activo
2. ✅ Configura backups automáticos de la base de datos
3. ✅ Agrega un dominio personalizado (opcional)
4. ✅ Configura monitoreo de errores (Sentry, etc.)

## 🆘 ¿Necesitas Ayuda?

Si algo no funciona:
1. Revisa los **Logs** en Render Dashboard
2. Verifica las **Variables de Entorno**
3. Asegúrate que la **Base de Datos** esté corriendo
4. Verifica que el **schema.sql** se haya ejecutado correctamente

---

**¡Listo!** Tu sistema TESCHA ahora está en la nube y accesible desde cualquier lugar 🚀
