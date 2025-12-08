# 🧪 Tests y Verificaciones TESCHA

Esta carpeta contiene todos los scripts de pruebas, verificaciones y tests del sistema TESCHA.

## 📂 Estructura

### 🔒 `/security-tests`
Scripts automatizados para pruebas de seguridad:
- Pruebas de autenticación
- Pruebas de inyección SQL
- Pruebas de XSS
- Pruebas de rate limiting
- Verificación de headers de seguridad

## 🚀 Uso

### Ejecutar pruebas de seguridad

```powershell
cd tests/security-tests
# Ejecutar scripts de prueba individuales según necesidad
```

## 📝 Notas

- Las pruebas deben ejecutarse en un entorno de desarrollo
- No ejecutar pruebas de seguridad en producción sin supervisión
- Revisar los logs después de cada ejecución

## ✅ Checklist de Pruebas

Antes de cada despliegue, verificar:
- [ ] Pruebas de seguridad pasadas
- [ ] Verificación de rendimiento
- [ ] Tests de integración
- [ ] Validación de base de datos
- [ ] Verificación de backups

## 🔍 Reportes

Los reportes de pruebas se encuentran en [`/docs/seguridad`](../docs/seguridad):
- REPORTE-PRUEBAS-SEGURIDAD.md
- REPORTE-PRUEBAS-LOGS.md
- RESULTADOS-ESPERADOS-PRUEBAS.md
