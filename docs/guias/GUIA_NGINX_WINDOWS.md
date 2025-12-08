# 🚀 GUÍA COMPLETA: NGINX PARA TESCHA
# Configuración profesional para acceder con coordinacion-tescha.local

## 📥 PASO 1: DESCARGAR NGINX

1. Ve a: http://nginx.org/en/download.html
2. Descarga la versión estable para Windows:
   nginx/Windows-1.24.0 (o la última versión)
3. Extrae el ZIP en: C:\nginx

## 📁 PASO 2: ESTRUCTURA DE ARCHIVOS

Después de extraer, deberías tener:
```
C:\nginx\
├── conf\
│   └── nginx.conf
├── html\
├── logs\
└── nginx.exe
```

## ⚙️ PASO 3: CONFIGURAR NGINX

Abre: C:\nginx\conf\nginx.conf

Reemplaza TODO el contenido con esto:

```nginx
worker_processes  1;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;
    
    sendfile        on;
    keepalive_timeout  65;
    
    # Configuración para TESCHA
    server {
        listen       80;
        server_name  coordinacion-tescha.local;
        
        # Logs
        access_log  logs/tescha-access.log;
        error_log   logs/tescha-error.log;
        
        # FRONTEND - React/Vue/HTML
        location / {
            proxy_pass http://127.0.0.1:3000;
            proxy_http_version 1.1;
            
            # Headers para WebSocket (si usas React)
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_cache_bypass $http_upgrade;
            
            # Headers adicionales
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }
        
        # BACKEND API - Node.js
        location /api {
            proxy_pass http://127.0.0.1:5000;
            proxy_http_version 1.1;
            
            # Headers
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
            
            # CORS (si es necesario)
            add_header 'Access-Control-Allow-Origin' '*' always;
            add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
            add_header 'Access-Control-Allow-Headers' 'Authorization, Content-Type' always;
        }
        
        # Health check
        location /health {
            proxy_pass http://127.0.0.1:5000/health;
        }
    }
}
```

## 💾 GUARDAR Y CERRAR

## 🧪 PASO 4: PROBAR CONFIGURACIÓN

Abre PowerShell como Administrador:

```powershell
cd C:\nginx
.\nginx.exe -t
```

Deberías ver:
```
nginx: the configuration file C:\nginx/conf/nginx.conf syntax is ok
nginx: configuration file C:\nginx/conf/nginx.conf test is successful
```

## 🚀 PASO 5: INICIAR NGINX

```powershell
cd C:\nginx
start nginx
```

Verificar que está corriendo:
```powershell
tasklist /fi "imagename eq nginx.exe"
```

Deberías ver 2 procesos nginx.exe

## 📝 PASO 6: CONFIGURAR HOSTS

Abre como Administrador:
```powershell
notepad C:\Windows\System32\drivers\etc\hosts
```

Agrega al final:
```
127.0.0.1    coordinacion-tescha.local
```

Guardar y cerrar.

## ✅ PASO 7: PROBAR

1. Asegúrate de que tu frontend esté corriendo en puerto 3000
2. Asegúrate de que tu backend esté corriendo en puerto 5000
3. Abre el navegador:
   http://coordinacion-tescha.local

¡Debería funcionar sin puerto!

## 🔄 COMANDOS ÚTILES DE NGINX

### Iniciar Nginx:
```powershell
cd C:\nginx
start nginx
```

### Detener Nginx:
```powershell
cd C:\nginx
.\nginx.exe -s stop
```

### Reiniciar Nginx (después de cambios):
```powershell
cd C:\nginx
.\nginx.exe -s reload
```

### Ver si está corriendo:
```powershell
tasklist /fi "imagename eq nginx.exe"
```

### Matar procesos (si hay problemas):
```powershell
taskkill /f /im nginx.exe
```

## 📊 VERIFICACIÓN FINAL

### 1. Verificar Nginx:
```powershell
curl http://localhost:80
```

### 2. Verificar dominio local:
```powershell
ping coordinacion-tescha.local
```

### 3. Abrir en navegador:
```
http://coordinacion-tescha.local
```

## 🌐 PARA OTROS MAESTROS EN LA RED

Cada maestro debe agregar en su archivo hosts:
```
192.168.1.132    coordinacion-tescha.local
```

Donde 192.168.1.132 es la IP de TU computadora.

## 🎯 RESULTADO FINAL

✅ Frontend: http://coordinacion-tescha.local
✅ Backend API: http://coordinacion-tescha.local/api
✅ Sin puertos visibles
✅ Profesional y limpio

## ⚠️ SOLUCIÓN DE PROBLEMAS

### Error: "nginx: [emerg] bind() to 0.0.0.0:80 failed"
Puerto 80 ocupado. Detén otros servicios (IIS, Apache, Skype).

```powershell
# Ver qué usa el puerto 80
netstat -ano | findstr :80

# Matar el proceso (reemplaza PID)
taskkill /F /PID <numero_pid>
```

### Error: "No se puede acceder"
1. Verifica que Nginx esté corriendo
2. Verifica que frontend y backend estén corriendo
3. Verifica el archivo hosts

### Error: "502 Bad Gateway"
El backend no está corriendo. Inicia:
```powershell
cd C:\Users\dush3\Downloads\TESCHA\backend
npm run pm2:status
```

## 🎉 ¡LISTO!

Ahora todos pueden acceder con:
http://coordinacion-tescha.local

Sin ver tu IP ni los puertos. Profesional y seguro.
