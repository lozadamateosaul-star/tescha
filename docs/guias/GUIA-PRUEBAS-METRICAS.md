# 🧪 GUÍA DE PRUEBAS EXHAUSTIVAS - MÉTRICAS FINANCIERAS

## 📋 OBJETIVO
Verificar que TODAS las métricas financieras (Hoy, Semana, Mes, Periodo) sumen correctamente con diferentes fechas.

---

## 🚀 CÓMO EJECUTAR LAS PRUEBAS

### Opción 1: pgAdmin (RECOMENDADO)

1. Abre **pgAdmin**
2. Conéctate a la base de datos `tescha_db`
3. Abre el Query Tool (F5)
4. Carga el archivo: `backend/database/test_exhaustivo_metricas.sql`
5. Ejecuta el script completo (F5)
6. Revisa los resultados

### Opción 2: psql (Línea de comandos)

```powershell
cd c:\Users\dush3\Downloads\TESCHA\backend
$env:PGPASSWORD='Dush3'
psql -U postgres -d tescha_db -f database/test_exhaustivo_metricas.sql
```

---

## ✅ VALORES ESPERADOS

El script inserta pagos de prueba y verifica:

| Métrica | Valor Esperado | Descripción |
|---------|---------------|-------------|
| **HOY** | $1,500.00 | 2 pagos de hoy (5 dic) |
| **SEMANA** | $4,250.00 | 4 pagos en últimos 7 días |
| **MES ACTUAL** | $4,250.00 | Todos los pagos de diciembre |
| **MES ANTERIOR** | $10,500.00 | 3 pagos de noviembre |

---

## 📊 PAGOS DE PRUEBA INSERTADOS

```
HOY (5 dic 2025):
  - $1,000.00 - PRUEBA - Pago Hoy 1
  - $500.00   - PRUEBA - Pago Hoy 2
  Total: $1,500.00

AYER (4 dic 2025):
  - $750.00   - PRUEBA - Pago Ayer

HACE 3 DÍAS (2 dic 2025):
  - $2,000.00 - PRUEBA - Hace 3 días

HACE 10 DÍAS (25 nov 2025):
  - $3,000.00 - PRUEBA - Hace 10 días

MES PASADO (nov 2025):
  - $5,000.00 - PRUEBA - Mes pasado 1
  - $2,500.00 - PRUEBA - Mes pasado 2

HACE 2 MESES (oct 2025):
  - $1,000.00 - PRUEBA - Hace 2 meses
```

---

## 🔍 QUÉ VERIFICA EL SCRIPT

### 1. Ingresos de HOY
```sql
SELECT SUM(monto) FROM pagos 
WHERE estatus = 'completado' 
  AND DATE(fecha_pago) = CURRENT_DATE
```
**Esperado**: $1,500.00 ✅

### 2. Ingresos de la SEMANA
```sql
SELECT SUM(monto) FROM pagos 
WHERE estatus = 'completado' 
  AND fecha_pago >= CURRENT_DATE - INTERVAL '7 days'
```
**Esperado**: $4,250.00 ✅

### 3. Ingresos del MES ACTUAL
```sql
SELECT SUM(monto) FROM pagos 
WHERE estatus = 'completado' 
  AND EXTRACT(MONTH FROM fecha_pago) = EXTRACT(MONTH FROM CURRENT_DATE)
  AND EXTRACT(YEAR FROM fecha_pago) = EXTRACT(YEAR FROM CURRENT_DATE)
```
**Esperado**: $4,250.00 ✅

### 4. Ingresos del MES ANTERIOR
```sql
SELECT SUM(monto) FROM pagos 
WHERE estatus = 'completado' 
  AND EXTRACT(MONTH FROM fecha_pago) = EXTRACT(MONTH FROM CURRENT_DATE - INTERVAL '1 month')
  AND EXTRACT(YEAR FROM fecha_pago) = EXTRACT(YEAR FROM CURRENT_DATE - INTERVAL '1 month')
```
**Esperado**: $10,500.00 ✅

---

## 🎯 INTERPRETACIÓN DE RESULTADOS

Si ves:
- ✅ **CORRECTO** → La métrica suma bien
- ❌ **ERROR** → Hay un problema en la query

---

## 🧹 LIMPIAR PAGOS DE PRUEBA

Después de verificar, ejecuta:

```sql
DELETE FROM pagos WHERE concepto LIKE '%PRUEBA%';
```

---

## 📝 NOTAS IMPORTANTES

1. Los pagos de prueba tienen `concepto LIKE '%PRUEBA%'` para identificarlos fácilmente
2. Todos tienen `estatus = 'completado'` para que cuenten en las métricas
3. Las fechas están calculadas dinámicamente con `CURRENT_DATE`
4. El script NO afecta tus datos reales (solo inserta pagos de prueba)

---

## 🔄 DESPUÉS DE VERIFICAR

1. Si todas las pruebas pasan (✅ CORRECTO), las métricas funcionan perfectamente
2. Limpia los pagos de prueba con el DELETE
3. Recarga el frontend y verás las métricas reales actualizadas
4. Las métricas se actualizan automáticamente cada vez que:
   - Se completa un pago
   - Se cambia la fecha de un pago
   - Se actualiza el estatus de un pago

---

## 🎉 RESULTADO ESPERADO

```
1. INGRESOS DE HOY:
   valor_real: 1500.00
   valor_esperado: 1500.00
   resultado: ✅ CORRECTO

2. INGRESOS DE LA SEMANA:
   valor_real: 4250.00
   valor_esperado: 4250.00
   resultado: ✅ CORRECTO

3. INGRESOS DEL MES ACTUAL:
   valor_real: 4250.00
   valor_esperado: 4250.00
   resultado: ✅ CORRECTO

4. INGRESOS DEL MES ANTERIOR:
   valor_real: 10500.00
   valor_esperado: 10500.00
   resultado: ✅ CORRECTO
```

Si ves esto, **¡TODO FUNCIONA PERFECTO!** 🎯
