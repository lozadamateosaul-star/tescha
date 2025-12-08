# 🚀 Guía de Despliegue en Netlify (Solo Frontend)

## ⚠️ Advertencia Importante

Esta guía es para desplegar **SOLO EL FRONTEND** como demostración visual. 

**NO funcionará:**
- ❌ Login/Autenticación
- ❌ Conexión a base de datos
- ❌ Cualquier funcionalidad que requiera el backend
- ❌ Guardado de datos

**SÍ funcionará:**
- ✅ Visualización de la interfaz
- ✅ Navegación entre páginas (rutas del frontend)
- ✅ Diseño y estilos

## 📋 Pasos para Desplegar en Netlify

### 1️⃣ Preparar el Frontend

```powershell
# Ir a la carpeta del frontend
cd C:\TESCHA\frontend

# Instalar dependencias (si no están instaladas)
npm install

# Construir para producción
npm run build
```

Esto creará una carpeta `dist/` con los archivos estáticos.

### 2️⃣ Crear archivo de configuración de Netlify

Crea un archivo `netlify.toml` en la raíz del proyecto frontend:

```toml
[build]
  command = "npm run build"
  publish = "dist"

[[redirects]]
  from = "/*"
  to = "/index.html"
  status = 200
```

### 3️⃣ Desplegar en Netlify

#### Opción A: Desde la interfaz web de Netlify

1. Ve a [netlify.com](https://netlify.com) y crea una cuenta
2. Click en "Add new site" → "Deploy manually"
3. Arrastra la carpeta `dist/` a la zona de drop
4. ¡Listo! Netlify te dará una URL

#### Opción B: Usando Netlify CLI

```powershell
# Instalar Netlify CLI
npm install -g netlify-cli

# Login en Netlify
netlify login

# Desplegar
cd C:\TESCHA\frontend
netlify deploy --prod --dir=dist
```

### 4️⃣ Configurar Variables de Entorno (Opcional)

Si quieres que el frontend intente conectarse a un backend en otro lugar:

1. En Netlify Dashboard → Site settings → Environment variables
2. Agregar:
   - `VITE_API_URL` = URL de tu backend (si lo despliegas en otro lado)

## 🎨 Solo para Demostración Visual

Si solo quieres mostrar la interfaz sin funcionalidad:

### Modificar el frontend para modo demo

Crea un archivo `frontend/src/config/demo.js`:

```javascript
// Modo demo - datos de ejemplo sin backend
export const DEMO_MODE = true;

export const DEMO_DATA = {
  user: {
    nombre: "Coordinador Demo",
    rol: "coordinador",
    email: "demo@tescha.edu.mx"
  },
  alumnos: [
    { id: 1, nombre: "Juan Pérez", nivel: "A1", grupo: "101" },
    { id: 2, nombre: "María García", nivel: "A2", grupo: "102" },
    // ... más datos de ejemplo
  ],
  // ... más datos de demostración
};
```

Y modificar tus componentes para usar estos datos cuando `DEMO_MODE` esté activo.

## 🌐 Alternativas Mejores para Full-Stack

Si quieres desplegar el sistema completo (frontend + backend + base de datos):

### **Opción 1: Render.com** (Recomendado)
- ✅ Gratis para proyectos pequeños
- ✅ Soporta Node.js + PostgreSQL
- ✅ Fácil de configurar

### **Opción 2: Railway.app**
- ✅ Gratis con límites generosos
- ✅ Soporta Node.js + PostgreSQL
- ✅ Deploy automático desde Git

### **Opción 3: Vercel + Supabase**
- ✅ Vercel para frontend y backend (serverless)
- ✅ Supabase para PostgreSQL
- ✅ Gratis con buenos límites

### **Opción 4: Heroku**
- ✅ Soporta Node.js + PostgreSQL
- ⚠️ Ya no tiene plan gratuito

## 📝 Resumen

**Para Netlify (solo frontend):**
```powershell
cd frontend
npm run build
# Subir carpeta dist/ a Netlify
```

**Para sistema completo:**
- Usa Render.com o Railway.app
- Necesitarás configurar backend + base de datos

## 🤔 ¿Qué te recomiendo?

- **Solo quieres mostrar la interfaz:** → Netlify ✅
- **Quieres que funcione completamente:** → Render.com o Railway.app ✅
- **Es para producción real:** → Mantén el servidor local como está ✅

¿Necesitas ayuda para configurar alguna de estas opciones?
