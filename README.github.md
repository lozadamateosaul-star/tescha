# 🎓 TESCHA - Sistema de Coordinación de Inglés

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com)

Sistema completo de gestión para coordinación de inglés desarrollado para el Tecnológico de Estudios Superiores de Chalco.

## 🚀 Características

- ✅ **Gestión de Alumnos** - Control completo de estudiantes por nivel
- ✅ **Control de Pagos** - Sistema de pagos y finanzas
- ✅ **Dashboard Interactivo** - Métricas y estadísticas en tiempo real
- ✅ **Generación de PDFs** - Reportes automáticos
- ✅ **Notificaciones Automáticas** - Alertas por email
- ✅ **Sistema de Seguridad** - 10 capas de seguridad (A+ rating)
- ✅ **Responsive Design** - Funciona en cualquier dispositivo

## 🛠️ Tecnologías

### Backend
- Node.js + Express
- PostgreSQL
- JWT Authentication
- PM2 Process Manager

### Frontend
- React + Vite
- React Router
- Axios
- CSS Modules

## 📦 Despliegue en Render

### Opción 1: Deploy Automático (Recomendado)

1. Haz fork de este repositorio
2. Ve a [Render Dashboard](https://dashboard.render.com)
3. Click en "New" → "Blueprint"
4. Conecta este repositorio
5. Render creará automáticamente:
   - Base de datos PostgreSQL
   - Backend (Web Service)
   - Frontend (Static Site)

### Opción 2: Deploy Manual

Ver la guía completa: [`docs/guias/RENDER-PASO-A-PASO.md`](./docs/guias/RENDER-PASO-A-PASO.md)

**Pasos rápidos:**

1. **Crear PostgreSQL Database**
   - Name: `tescha-db`
   - Plan: Free

2. **Crear Web Service (Backend)**
   - Root Directory: `backend`
   - Build: `npm install`
   - Start: `npm start`
   - Variables de entorno: Ver `.env.render.example`

3. **Crear Static Site (Frontend)**
   - Root Directory: `frontend`
   - Build: `npm install && npm run build`
   - Publish: `dist`

## 🔧 Instalación Local

### Requisitos
- Node.js 18+
- PostgreSQL 15+
- Git

### Pasos

```bash
# Clonar repositorio
git clone https://github.com/TU_USUARIO/TESCHA.git
cd TESCHA

# Instalar dependencias del backend
cd backend
npm install
cp .env.example .env
# Editar .env con tus credenciales

# Crear base de datos
psql -U postgres -c "CREATE DATABASE tescha;"
psql -U postgres -d tescha -f database/schema.sql

# Iniciar backend
npm start

# En otra terminal - Frontend
cd ../frontend
npm install
npm run dev
```

## 📚 Documentación

Toda la documentación está en la carpeta [`/docs`](./docs):

- **[Guías de Instalación](./docs/guias)** - Instalación local y en la nube
- **[Guías de Despliegue](./docs/guias/RENDER-PASO-A-PASO.md)** - Deploy en Render
- **[Seguridad](./docs/seguridad)** - Auditorías y certificaciones
- **[Análisis Técnico](./docs/analisis)** - Documentación técnica

## 🔒 Seguridad

El sistema incluye 10 capas de seguridad:

1. ✅ Autenticación JWT
2. ✅ Protección SQL Injection
3. ✅ Protección XSS
4. ✅ Rate Limiting
5. ✅ Sistema de Detección de Intrusos
6. ✅ Protección CSRF
7. ✅ Encriptación AES-256-GCM
8. ✅ Logging y Auditoría
9. ✅ Security Headers (Helmet.js)
10. ✅ Notificaciones Seguras

**Calificación de Seguridad:** A+ (95/100)

Ver: [`docs/seguridad/CERTIFICACION-SEGURIDAD.md`](./docs/seguridad/CERTIFICACION-SEGURIDAD.md)

## 🧪 Testing

```bash
# Backend tests
cd backend
npm test

# Frontend tests
cd frontend
npm test
```

## 📝 Variables de Entorno

### Backend (.env)
```env
NODE_ENV=production
DATABASE_URL=postgresql://user:password@host:5432/tescha
JWT_SECRET=tu-secret-seguro
FRONTEND_URL=https://tu-frontend.com
```

Ver archivo completo: [`backend/.env.render.example`](./backend/.env.render.example)

### Frontend (.env.production)
```env
VITE_API_URL=https://tu-backend.com
```

## 🤝 Contribuir

1. Fork el proyecto
2. Crea una rama (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto fue desarrollado para el Tecnológico de Estudios Superiores de Chalco.

## 👥 Autores

- **Coordinación TESCHA** - Sistema de gestión de inglés

## 🆘 Soporte

Para soporte técnico:
- Ver documentación en [`/docs`](./docs)
- Abrir un Issue en GitHub
- Consultar las guías de troubleshooting

## 🎯 Roadmap

- [x] Sistema de gestión de alumnos
- [x] Control de pagos
- [x] Dashboard con métricas
- [x] Generación de PDFs
- [x] Notificaciones automáticas
- [x] Sistema de seguridad completo
- [ ] App móvil
- [ ] Integración con WhatsApp
- [ ] Sistema de calificaciones

## ⭐ Agradecimientos

Desarrollado con ❤️ para mejorar la gestión educativa en TESCHA.

---

**🚀 Deploy to Render:** [![Deploy](https://render.com/images/deploy-to-render-button.svg)](https://render.com)
