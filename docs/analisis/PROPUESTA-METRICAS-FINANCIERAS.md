# 💰 PROPUESTA: MÉTRICAS FINANCIERAS CON FECHAS

## 🎯 OBJETIVO
Tener control total de ingresos con fechas claras y lógicas para análisis financiero.

---

## 📊 MÉTRICAS PROPUESTAS

### 1️⃣ **Ingresos del Día (Hoy)**
- **Qué muestra**: Pagos completados HOY
- **Útil para**: Control diario de caja
- **Ejemplo**: "Hoy 5 de diciembre: $5,200.00"

### 2️⃣ **Ingresos de la Semana**
- **Qué muestra**: Pagos completados en los últimos 7 días
- **Útil para**: Tendencia semanal
- **Ejemplo**: "Esta semana: $28,400.00"

### 3️⃣ **Ingresos del Mes Actual**
- **Qué muestra**: Pagos completados en el mes calendario actual (Diciembre 2025)
- **Útil para**: Control mensual
- **Ejemplo**: "Diciembre 2025: $99,040.00"

### 4️⃣ **Ingresos del Periodo/Semestre Activo**
- **Qué muestra**: Pagos completados del periodo académico activo
- **Útil para**: Análisis por semestre
- **Ejemplo**: "Ago-Dic 2024: $450,000.00"

### 5️⃣ **Ingresos del Año**
- **Qué muestra**: Pagos completados en el año calendario (2025)
- **Útil para**: Reportes anuales
- **Ejemplo**: "2025: $1,200,000.00"

---

## 🎨 DISEÑO PROPUESTO PARA PÁGINA DE PAGOS

```
┌─────────────────────────────────────────────────────────────┐
│  💰 RESUMEN FINANCIERO                                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │   HOY    │  │  SEMANA  │  │   MES    │  │  PERIODO │   │
│  │ 5 Dic    │  │ 7 días   │  │ Dic 2025 │  │ Ago-Dic  │   │
│  │          │  │          │  │          │  │   2024   │   │
│  │ $5,200   │  │ $28,400  │  │ $99,040  │  │ $450,000 │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  📈 COMPARATIVA                                       │  │
│  │  • Mes anterior: $85,200 → +16.2% ✅                 │  │
│  │  • Mismo mes año pasado: $92,000 → +7.7% ✅          │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 💡 MÉTRICAS ADICIONALES ÚTILES

### **Por Cobrar (Pendientes)**
- Total de pagos pendientes
- Desglosado por urgencia:
  - 🔴 Vencidos (pasó la fecha límite)
  - 🟡 Por vencer (próximos 3 días)
  - 🟢 Vigentes (tienen tiempo)

### **Proyecciones**
- Ingresos esperados del mes (basado en pendientes)
- Ingresos proyectados del periodo

### **Análisis de Tendencias**
- Gráfica de ingresos por día/semana/mes
- Comparativa año a año
- Tasa de crecimiento

---

## 🔧 IMPLEMENTACIÓN TÉCNICA

### Backend (SQL)
```sql
-- Ingresos del día
SELECT COALESCE(SUM(monto), 0) as ingresos_hoy
FROM pagos 
WHERE estatus = 'completado' 
  AND DATE(fecha_pago) = CURRENT_DATE;

-- Ingresos de la semana
SELECT COALESCE(SUM(monto), 0) as ingresos_semana
FROM pagos 
WHERE estatus = 'completado' 
  AND fecha_pago >= CURRENT_DATE - INTERVAL '7 days';

-- Ingresos del mes
SELECT COALESCE(SUM(monto), 0) as ingresos_mes
FROM pagos 
WHERE estatus = 'completado' 
  AND EXTRACT(MONTH FROM fecha_pago) = EXTRACT(MONTH FROM CURRENT_DATE)
  AND EXTRACT(YEAR FROM fecha_pago) = EXTRACT(YEAR FROM CURRENT_DATE);

-- Ingresos del periodo activo
SELECT COALESCE(SUM(p.monto), 0) as ingresos_periodo
FROM pagos p
JOIN inscripciones i ON p.inscripcion_id = i.id
JOIN periodos per ON i.periodo_id = per.id
WHERE p.estatus = 'completado' 
  AND per.activo = true;
```

### Frontend (React)
```javascript
const [metricas, setMetricas] = useState({
  hoy: 0,
  semana: 0,
  mes: 0,
  periodo: 0,
  ano: 0,
  comparativas: {
    mesAnterior: { monto: 0, cambio: 0 },
    anoAnterior: { monto: 0, cambio: 0 }
  }
});
```

---

## 📅 RANGOS DE FECHAS CLAROS

### Mes Actual
- **Inicio**: 1 de diciembre 2025
- **Fin**: 31 de diciembre 2025
- **Muestra**: Todos los pagos completados en diciembre

### Periodo Activo
- **Inicio**: Fecha de inicio del periodo (ej: 1 agosto 2024)
- **Fin**: Fecha de fin del periodo (ej: 31 diciembre 2024)
- **Muestra**: Todos los pagos del semestre actual

### Año Fiscal
- **Inicio**: 1 enero 2025
- **Fin**: 31 diciembre 2025
- **Muestra**: Todos los pagos del año

---

## ✅ BENEFICIOS

1. **Claridad Total**: Sabes exactamente qué periodo estás viendo
2. **Comparativas**: Puedes ver si estás creciendo o no
3. **Proyecciones**: Puedes estimar ingresos futuros
4. **Control Diario**: Monitoreo en tiempo real
5. **Reportes**: Datos listos para reportes financieros

---

## 🚀 PRÓXIMOS PASOS

¿Quieres que implemente:
1. ✅ Las 4 tarjetas de métricas (Hoy, Semana, Mes, Periodo)
2. ✅ Las comparativas (mes anterior, año anterior)
3. ✅ Gráfica de tendencias
4. ✅ Proyecciones de ingresos

¿Por dónde empezamos?
