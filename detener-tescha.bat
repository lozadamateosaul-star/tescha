@echo off
echo ========================================
echo   DETENIENDO TESCHA
echo ========================================
echo.

echo [1/3] Deteniendo Backend (PM2)...
cd /d "%~dp0\backend"
call pm2 stop all >nul 2>&1
timeout /t 1 /nobreak >nul

echo [2/3] Deteniendo Nginx...
taskkill /f /im nginx.exe >nul 2>&1
timeout /t 1 /nobreak >nul

echo [3/3] Deteniendo Frontend (Node.js)...
taskkill /f /im node.exe >nul 2>&1
timeout /t 1 /nobreak >nul

echo.
echo ========================================
echo   TESCHA DETENIDO
echo ========================================
echo.
echo Todos los servicios han sido detenidos.
echo.
pause
