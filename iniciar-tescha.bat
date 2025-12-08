@echo off
echo ========================================
echo   INICIANDO TESCHA
echo   Sistema de Coordinacion de Ingles
echo ========================================
echo.

REM Verificar que estamos en el directorio correcto
cd /d "%~dp0"

echo [1/4] Iniciando Backend...
cd backend
call npm run pm2:start
timeout /t 2 /nobreak >nul

echo [2/4] Construyendo Frontend (si es necesario)...
cd ..\frontend
if not exist "dist\index.html" (
    echo      Construyendo por primera vez...
    call npm run build
)

echo [3/4] Iniciando Frontend...
start /min cmd /c "npx serve -s dist -l 3000"
timeout /t 3 /nobreak >nul

echo [4/4] Iniciando Nginx...
cd C:\nginx
start /min nginx.exe
timeout /t 2 /nobreak >nul

echo.
echo Verificando servicios...
timeout /t 2 /nobreak >nul
echo.

REM Verificar Backend
netstat -ano | findstr ":5000" >nul
if %errorlevel% equ 0 (
    echo [OK] Backend corriendo en puerto 5000
) else (
    echo [ERROR] Backend NO esta corriendo
)

REM Verificar Frontend
netstat -ano | findstr ":3000" >nul
if %errorlevel% equ 0 (
    echo [OK] Frontend corriendo en puerto 3000
) else (
    echo [ERROR] Frontend NO esta corriendo
)

REM Verificar Nginx
tasklist /fi "imagename eq nginx.exe" | findstr "nginx.exe" >nul
if %errorlevel% equ 0 (
    echo [OK] Nginx corriendo
) else (
    echo [ERROR] Nginx NO esta corriendo
)

echo.
echo ========================================
echo   TESCHA INICIADO CORRECTAMENTE
echo ========================================
echo.
echo Accede desde cualquier navegador:
echo.
echo   http://coordinacion-tescha.local
echo.
echo Desde otras PCs en la red:
echo   http://192.168.1.132
echo.
echo ========================================
echo.
echo Presiona cualquier tecla para abrir el navegador...
pause >nul

start http://coordinacion-tescha.local

echo.
echo TESCHA esta corriendo.
echo.
echo Para detener TESCHA, ejecuta: detener-tescha.bat
echo.
pause
