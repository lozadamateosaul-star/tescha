# Lógica del Sistema de Pagos - TESCHA

## Documentación para Finanzas

### 1. CONCEPTOS Y PRECIOS OFICIALES

Todos los pagos deben usar uno de estos 10 conceptos oficiales de Celex:

| Concepto | Precio (MXN) |
|----------|--------------|
| Constancia de Inglés - Celex | $40.00 |
| Credencial para Alumnos Externos - Celex | $93.00 |
| Curso de Idiomas - Celex - Cónyuge e hijos de Docentes y Administrativos | $2,227.00 |
| Curso de Idiomas - Celex - Docentes y Administrativos | $1,238.00 |
| Curso de Idiomas - Celex - Egresados | $2,103.00 |
| Curso de Idiomas - Celex - Estudiantes | $1,857.00 |
| Curso de Idiomas - Celex - Externos | $2,476.00 |
| Curso de Idiomas - Celex - Sector con convenio con el TESCHA | $2,227.00 |
| Examen Escrito para Acreditación - Celex | $914.00 |
| Examen de Colocación - Celex | $187.00 |

**Importante:** El sistema calcula automáticamente el monto al seleccionar el concepto.

---

### 2. MÉTODO DE PAGO

**ÚNICO MÉTODO ACEPTADO:** Formato Universal

Todos los pagos se realizan en ventanilla bancaria usando el Formato Universal de Pago emitido por el Gobierno del Estado de México.

---

### 3. ESTADOS DE PAGO

El sistema maneja 3 estados principales:

#### **COMPLETADO** (✅ Color Verde)
- **Significado:** El pago YA FUE REALIZADO por el alumno
- **Cuándo se usa:** Al registrar un pago que el alumno ya pagó en ventanilla
- **Requisitos obligatorios:**
  - ✅ Línea de captura (referencia)
  - ✅ Monto correcto según concepto
  - ✅ Fecha de pago (se registra automáticamente)
- **Efecto contable:** Se suma a los INGRESOS del mes

#### **PENDIENTE** (⚠️ Color Amarillo)
- **Significado:** El alumno DEBE el pago pero se le dio prórroga
- **Cuándo se usa:** Cuando se otorga plazo adicional para pagar
- **Requisitos obligatorios:**
  - ✅ Fecha límite de prórroga
  - ✅ Monto según concepto
- **Efecto contable:** Se suma a "POR COBRAR"

#### **CANCELADO** (❌ Color Rojo)
- **Significado:** El pago fue anulado o rechazado
- **Cuándo se usa:** Errores, devoluciones, o cancelaciones administrativas
- **Efecto contable:** NO se cuenta en ingresos ni por cobrar

---

### 4. FLUJO DE REGISTRO DE PAGOS

#### **Escenario A: Alumno Ya Pagó (CASO NORMAL)**
1. Coordinador recibe comprobante de pago del alumno
2. En el sistema: "Registrar Pago"
3. Selecciona alumno, concepto (calcula monto automático)
4. Captura la **línea de captura** (referencia del formato universal)
5. **NO marca** la casilla de prórroga
6. Registra → Estado: **COMPLETADO**

#### **Escenario B: Alumno Aún No Paga (Prórroga)**
1. Alumno solicita plazo para pagar
2. En el sistema: "Registrar Pago"
3. Selecciona alumno, concepto
4. **SÍ marca** la casilla "Registrar como pago pendiente con prórroga"
5. Define fecha límite de prórroga
6. Registra → Estado: **PENDIENTE**
7. Cuando el alumno pague:
   - Editar el pago
   - Cambiar estado a "Completado"
   - Agregar línea de captura
   - Desmarcar prórroga

---

### 5. CÁLCULOS FINANCIEROS

#### **Ingresos del Mes**
```
SUMA de todos los pagos con:
- estatus = 'completado'
- fecha_pago del mes actual
```

#### **Por Cobrar**
```
SUMA de todos los pagos con:
- estatus = 'pendiente'
```

#### **Prórrogas Activas**
```
CANTIDAD de pagos con:
- tiene_prorroga = true
- estatus = 'pendiente'
```

#### **Prórrogas Por Vencer**
```
Pagos con prórroga donde:
- fecha_limite_prorroga entre HOY y HOY+3 días
```

---

### 6. VALIDACIONES DEL SISTEMA

✅ **Al registrar pago COMPLETADO:**
- Referencia (línea de captura) es **OBLIGATORIA**
- Mínimo 10 caracteres
- Ejemplo: `970000211032384748063237267`

✅ **Al registrar pago PENDIENTE:**
- Fecha límite de prórroga es **OBLIGATORIA**
- Debe ser fecha futura

✅ **Al seleccionar concepto:**
- Monto se calcula **automáticamente**
- Puede editarse manualmente si hay excepciones

---

### 7. REPORTES PARA FINANZAS

#### **Disponibles en el sistema:**
1. **Ingresos del mes** - Total cobrado en el mes actual
2. **Pagos por cobrar** - Total de deudas pendientes
3. **Prórrogas activas** - Alumnos con plazo vigente
4. **Historial completo** - Todos los pagos con filtros

#### **Información exportable:**
- Fecha de pago
- Alumno (nombre y matrícula)
- Concepto
- Monto
- Método (Formato Universal)
- Referencia (línea de captura)
- Estado

---

### 8. CASOS ESPECIALES

#### **¿Qué hacer si el alumno pagó pero no tengo la referencia?**
- NO registrar como completado sin referencia
- Registrar como pendiente con prórroga
- Solicitar al alumno el comprobante
- Una vez obtenido, editar y completar

#### **¿Qué hacer si se capturó mal un monto?**
- Editar el pago
- Corregir el monto
- Agregar nota explicando el ajuste

#### **¿Qué hacer si se venció una prórroga?**
- El sistema alerta automáticamente
- Contactar al alumno
- Si pagó: editar y marcar como completado
- Si no pagó: puede extender prórroga o cancelar

---

### 9. INTEGRIDAD CONTABLE

El sistema garantiza:

✅ **Trazabilidad:** Cada pago tiene fecha, hora, usuario que lo registró  
✅ **Validación:** No permite pagos completados sin referencia  
✅ **Cálculos automáticos:** Suma correcta de ingresos y por cobrar  
✅ **Alertas:** Notifica prórrogas por vencer  
✅ **Auditoría:** Todos los cambios quedan registrados en logs  

---

### 10. PREGUNTAS FRECUENTES

**P: ¿Por qué no hay opción de "Efectivo" o "Tarjeta"?**  
R: Porque TODOS los pagos se hacen con Formato Universal en ventanilla bancaria.

**P: ¿Puedo cambiar el precio de un concepto?**  
R: No sin autorización. Los precios son oficiales del catálogo Celex.

**P: ¿Cómo sé si un pago realmente se hizo?**  
R: Verificando la línea de captura en el sistema bancario del gobierno.

**P: ¿Qué pasa si registro mal un pago?**  
R: Puedes editarlo desde la columna "Acción". Todos los cambios quedan en el log de auditoría.

**P: ¿Puedo borrar un pago?**  
R: No. Solo se pueden cancelar (cambiando estado a "Cancelado") para mantener trazabilidad.

---

## RESUMEN EJECUTIVO

**El sistema está diseñado para:**
1. ✅ Registrar pagos ya realizados (con línea de captura)
2. ✅ Dar seguimiento a pagos pendientes (con prórrogas)
3. ✅ Calcular automáticamente montos según conceptos oficiales
4. ✅ Generar reportes precisos para finanzas
5. ✅ Mantener integridad contable y trazabilidad completa

**NO es para:**
- ❌ Pagos en efectivo o tarjeta
- ❌ Conceptos fuera del catálogo oficial
- ❌ Modificar precios sin autorización

---

**Última actualización:** 3 de diciembre de 2025  
**Versión del sistema:** 2.0  
**Contacto técnico:** Coordinación de Inglés - TESCHA
