# 🚀 Inicio Rápido - Despliegue en Render

## ✅ Checklist Rápido

### 1️⃣ Preparar Repositorio GitHub
```powershell
cd C:\TESCHA
git init
git add .
git commit -m "Preparar para Render"
git remote add origin https://github.com/TU_USUARIO/TESCHA.git
git push -u origin main
```

### 2️⃣ Crear Servicios en Render

#### A. Base de Datos PostgreSQL
1. Dashboard → **"Nuevo Postgres"**
2. Name: `tescha-db`
3. Database: `tescha`
4. Plan: **Free**
5. **Crear** → Guardar credenciales

#### B. Backend (Web Service)
1. Dashboard → **"Nuevo servicio web"**
2. Conectar GitHub → Seleccionar `TESCHA`
3. Configuración:
   - Name: `tescha-backend`
   - Root Directory: `backend`
   - Build: `npm install`
   - Start: `npm start`
   - Plan: **Free**
4. **Variables de Entorno:**
   ```
   NODE_ENV=production
   DATABASE_URL=[copiar de la base de datos]
   JWT_SECRET=[generar uno seguro]
   FRONTEND_URL=https://tescha-frontend.onrender.com
   ```
5. **Crear Web Service**

#### C. Frontend (Static Site)
1. Dashboard → **"Nuevo sitio estático"**
2. Seleccionar `TESCHA`
3. Configuración:
   - Name: `tescha-frontend`
   - Root Directory: `frontend`
   - Build: `npm install && npm run build`
   - Publish: `dist`
4. **Variables de Entorno:**
   ```
   VITE_API_URL=https://tescha-backend.onrender.com
   ```
5. **Crear Static Site**

### 3️⃣ Migrar Base de Datos
```powershell
# Conectar a la DB de Render
psql "[DATABASE_URL de Render]"

# Ejecutar schema
\i C:\TESCHA\backend\database\schema.sql

# Salir
\q
```

### 4️⃣ Verificar
- Frontend: `https://tescha-frontend.onrender.com`
- Backend: `https://tescha-backend.onrender.com/api/health`

## 🎉 ¡Listo!

Tu aplicación está en la nube y funcionando.

## 📚 Documentación Completa

Ver: [`GUIA-DEPLOY-RENDER.md`](./GUIA-DEPLOY-RENDER.md)

## ⚠️ Importante

- El servicio gratuito se "duerme" después de 15 min de inactividad
- Primera carga puede tardar 30-60 segundos
- Base de datos expira cada 90 días (renovar gratis)

## 🔧 Troubleshooting

**Error de conexión a DB:**
- Verifica que `DATABASE_URL` esté correcto en variables de entorno

**CORS Error:**
- Verifica que `FRONTEND_URL` en backend sea correcto
- Verifica que `VITE_API_URL` en frontend sea correcto

**Servicio no inicia:**
- Revisa los **Logs** en Render Dashboard
