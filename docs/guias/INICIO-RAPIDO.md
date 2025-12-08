# 🚀 INICIO RÁPIDO - Sistema TESCHA

## ⚡ Instalación Express (5 minutos)

### 1️⃣ Instalar Dependencias del Backend
```powershell
cd backend
npm install
```

### 2️⃣ Configurar Base de Datos

Crear base de datos en PostgreSQL:
```sql
CREATE DATABASE tescha_db;
```

Copiar archivo de configuración:
```powershell
Copy-Item .env.example .env
```

Editar `backend\.env` con tus credenciales de PostgreSQL.

Inicializar base de datos:
```powershell
npm run init-db
```

### 3️⃣ Instalar Dependencias del Frontend
```powershell
cd ..\frontend
npm install
```

### 4️⃣ Iniciar el Sistema

**Terminal 1 - Backend:**
```powershell
cd backend
npm run dev
```

**Terminal 2 - Frontend:**
```powershell
cd frontend
npm run dev
```

### 5️⃣ Acceder al Sistema

Abrir navegador en: **http://localhost:3000**

**Usuario inicial:**
- Usuario: `coordinador`
- Contraseña: `admin123`

---

## 📋 Checklist de Configuración

- [ ] Node.js v18+ instalado
- [ ] PostgreSQL v14+ instalado y corriendo
- [ ] Base de datos `tescha_db` creada
- [ ] Archivo `.env` configurado con credenciales correctas
- [ ] Dependencias del backend instaladas (`npm install`)
- [ ] Base de datos inicializada (`npm run init-db`)
- [ ] Dependencias del frontend instaladas
- [ ] Backend corriendo en http://localhost:5000
- [ ] Frontend corriendo en http://localhost:3000
- [ ] Login exitoso con usuario coordinador

---

## 🔧 Comandos Útiles

### Backend
```powershell
cd backend
npm run dev        # Modo desarrollo con auto-reload
npm start          # Modo producción
npm run init-db    # Reinicializar base de datos
```

### Frontend
```powershell
cd frontend
npm run dev        # Modo desarrollo
npm run build      # Compilar para producción
npm run preview    # Ver build de producción
```

---

## ❗ Problemas Comunes

### "Cannot connect to database"
✅ Verificar que PostgreSQL esté corriendo
✅ Revisar credenciales en `backend\.env`
✅ Confirmar que existe la base de datos `tescha_db`

### "Port 5000 already in use"
✅ Cambiar `PORT=5000` a otro puerto en `backend\.env`

### "Port 3000 already in use"
✅ El frontend te preguntará automáticamente si usar otro puerto

### Error al importar módulos
✅ Ejecutar `npm install` en la carpeta correspondiente
✅ Eliminar `node_modules` y volver a instalar

---

## 📊 Estructura de la Base de Datos

El sistema crea automáticamente:

- ✅ 20+ tablas con relaciones completas
- ✅ Índices optimizados para búsquedas
- ✅ Triggers para auditoría automática
- ✅ Usuario coordinador inicial

---

## 🎯 Próximos Pasos

1. **Cambiar contraseña del coordinador**
2. **Crear período académico actual**
3. **Registrar salones del TESCHA**
4. **Dar de alta maestros**
5. **Configurar tarifas del período**
6. **Comenzar a registrar alumnos**

---

## 📞 Soporte

Si tienes problemas durante la instalación:

1. Revisa el archivo `README.md` completo
2. Verifica los logs en la terminal
3. Contacta al equipo de desarrollo

---

**¡Todo listo para usar el Sistema TESCHA! 🎓**
