# 📸 Guía Visual Paso a Paso - Render.com

## 🎯 Resumen Visual

Veo que ya estás en el Dashboard de Render. ¡Perfecto! Aquí está lo que necesitas hacer:

## 📋 PASO 1: Subir a GitHub (PRIMERO)

Antes de usar Render, necesitas subir tu código a GitHub:

### 1.1 Crear repositorio en GitHub
1. Ve a [github.com](https://github.com)
2. Click en **"New repository"** (botón verde)
3. Nombre: `TESCHA`
4. Descripción: `Sistema de Coordinación de Inglés`
5. **Public** o **Private** (tu elección)
6. **NO** marcar "Initialize with README"
7. Click **"Create repository"**

### 1.2 Subir tu código
```powershell
# Abrir PowerShell en la carpeta TESCHA
cd C:\Users\dush3\Downloads\TESCHA

# Inicializar Git
git init

# Agregar todos los archivos
git add .

# Hacer commit
git commit -m "Primer commit - Sistema TESCHA"

# Conectar con GitHub (reemplaza TU_USUARIO)
git remote add origin https://github.com/TU_USUARIO/TESCHA.git

# Subir código
git branch -M main
git push -u origin main
```

## 🗄️ PASO 2: Crear PostgreSQL en Render

En el Dashboard que tienes abierto:

### 2.1 Click en **"Postgres"** (la tarjeta que dice "Postgres")

### 2.2 Llenar el formulario:
```
Name: tescha-db
Database: tescha
User: tescha_user (o déjalo automático)
Region: Oregon (US West)
PostgreSQL Version: 16 (o la última)
```

### 2.3 Plan:
- Selecciona **"Free"** ✅

### 2.4 Click **"Create Database"**

### 2.5 IMPORTANTE - Guardar credenciales:
Después de crear, verás:
- **Internal Database URL** (úsala para el backend)
- **External Database URL** (úsala para conectarte desde tu PC)
- Host, Port, Database, Username, Password

**Copia y guarda** el "Internal Database URL" - lo necesitarás en el siguiente paso.

Ejemplo:
```
postgresql://tescha_user:abc123xyz@dpg-xxxxx-a.oregon-postgres.render.com/tescha
```

## ⚙️ PASO 3: Crear Backend (Web Service)

### 3.1 Volver al Dashboard → Click **"Servicios web"**

### 3.2 Click **"Nuevo servicio web"**

### 3.3 Conectar GitHub:
- Click **"Connect account"** o **"Configure account"**
- Autoriza Render a acceder a tu GitHub
- Selecciona el repositorio **"TESCHA"**

### 3.4 Configuración:
```
Name: tescha-backend
Region: Oregon (US West) ← MISMO que la base de datos
Branch: main
Root Directory: backend
Runtime: Node
Build Command: npm install
Start Command: npm start
```

### 3.5 Plan:
- Selecciona **"Free"** ✅

### 3.6 Variables de Entorno (MUY IMPORTANTE):

Click en **"Advanced"** → **"Add Environment Variable"**

Agrega estas variables:

| Key | Value |
|-----|-------|
| `NODE_ENV` | `production` |
| `PORT` | `5000` |
| `DATABASE_URL` | `[Pegar el Internal Database URL del Paso 2]` |
| `JWT_SECRET` | `[Generar uno seguro - ver abajo]` |
| `FRONTEND_URL` | `https://tescha-frontend.onrender.com` |

**Para generar JWT_SECRET:**
```powershell
# En PowerShell, ejecuta:
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### 3.7 Click **"Create Web Service"**

⏳ Espera 3-5 minutos mientras se despliega...

### 3.8 Verificar:
Cuando termine, verás una URL como:
```
https://tescha-backend.onrender.com
```

Ábrela en el navegador - deberías ver algo (JSON o mensaje de API).

## 🎨 PASO 4: Crear Frontend (Static Site)

### 4.1 Volver al Dashboard → Click **"Nuevo sitio estático"**

### 4.2 Conectar GitHub:
- Selecciona el repositorio **"TESCHA"**

### 4.3 Configuración:
```
Name: tescha-frontend
Branch: main
Root Directory: frontend
Build Command: npm install && npm run build
Publish Directory: dist
```

### 4.4 Variables de Entorno:

Click en **"Advanced"** → **"Add Environment Variable"**

| Key | Value |
|-----|-------|
| `VITE_API_URL` | `https://tescha-backend.onrender.com` |

### 4.5 Click **"Create Static Site"**

⏳ Espera 3-5 minutos...

### 4.6 Verificar:
Cuando termine, verás una URL como:
```
https://tescha-frontend.onrender.com
```

¡Ábrela y deberías ver tu aplicación! 🎉

## 🗃️ PASO 5: Migrar Base de Datos

Ahora necesitas crear las tablas en tu base de datos de Render:

### 5.1 Conectarte desde tu PC:

```powershell
# Usar el "External Database URL" que guardaste
psql "postgresql://tescha_user:PASSWORD@HOST:5432/tescha"
```

### 5.2 Ejecutar el schema:

```sql
-- Opción A: Desde psql
\i C:\Users\dush3\Downloads\TESCHA\backend\database\schema.sql

-- Opción B: O copiar y pegar el contenido del archivo
```

### 5.3 Verificar:

```sql
-- Ver tablas creadas
\dt

-- Ver si hay usuarios
SELECT * FROM usuarios;

-- Salir
\q
```

## ✅ PASO 6: Verificación Final

### 6.1 Probar Backend:
```
https://tescha-backend.onrender.com/api/health
```

### 6.2 Probar Frontend:
```
https://tescha-frontend.onrender.com
```

### 6.3 Probar Login:
- Abre el frontend
- Intenta hacer login
- Si funciona, ¡todo está correcto! 🎉

## 🎉 URLs Finales

Guarda estas URLs:

- **Frontend (para usuarios):** `https://tescha-frontend.onrender.com`
- **Backend (API):** `https://tescha-backend.onrender.com`
- **Base de Datos:** Solo accesible desde el backend

## ⚠️ Notas Importantes

### Servicio Gratuito:
- ✅ 750 horas/mes gratis
- ⚠️ Se "duerme" después de 15 minutos sin uso
- ⚠️ Primera carga puede tardar 30-60 segundos

### Base de Datos:
- ✅ 1 GB gratis
- ⚠️ Expira cada 90 días (renovar gratis)

### Solución al "Sleep":
Usa [UptimeRobot](https://uptimerobot.com) para hacer ping cada 10 minutos.

## 🔧 Si Algo Sale Mal

### Backend no inicia:
1. Ve a Render Dashboard → `tescha-backend` → **Logs**
2. Busca errores en rojo
3. Verifica que `DATABASE_URL` esté correcto

### Frontend no carga:
1. Ve a Render Dashboard → `tescha-frontend` → **Logs**
2. Verifica que `VITE_API_URL` esté correcto

### Error CORS:
1. Ve a `tescha-backend` → **Environment**
2. Verifica que `FRONTEND_URL` sea exactamente: `https://tescha-frontend.onrender.com`

## 📝 Actualizar el Código

Cuando hagas cambios:

```powershell
cd C:\Users\dush3\Downloads\TESCHA
git add .
git commit -m "Descripción de cambios"
git push
```

Render detectará el push y desplegará automáticamente. 🚀

## 🆘 ¿Necesitas Ayuda?

Si tienes problemas en algún paso, dime en qué paso estás y qué error ves.
