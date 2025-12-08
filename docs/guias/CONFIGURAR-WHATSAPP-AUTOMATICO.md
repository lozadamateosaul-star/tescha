# 🚀 Configurar WhatsApp Automático con Twilio

## Paso 1: Crear cuenta en Twilio (GRATIS)

1. Ve a: https://www.twilio.com/try-twilio
2. Regístrate con tu correo
3. Verifica tu número de teléfono
4. **Obtienes $15 USD de crédito gratis** (suficiente para ~500 mensajes)

## Paso 2: Obtener credenciales

1. En el Dashboard de Twilio verás:
   - **Account SID**: algo como `ACxxxxxxxxxxxxxxxxx`
   - **Auth Token**: haz clic en "Show" para verlo

2. Anota estos valores

## Paso 3: Configurar WhatsApp Sandbox

1. En Twilio Console, ve a: **Messaging** → **Try it out** → **Send a WhatsApp message**
2. Verás un número de WhatsApp de Twilio: `+1 415 523 8886`
3. **IMPORTANTE**: Debes enviar un mensaje desde tu WhatsApp personal a ese número con el código que te muestra (ejemplo: `join <código>`)
4. Esto activa el sandbox de prueba

## Paso 4: Configurar variables de entorno

Crea o edita el archivo `.env` en la carpeta `backend`:

```env
# Twilio WhatsApp
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=tu_auth_token_aqui
TWILIO_WHATSAPP_FROM=whatsapp:+14155238886
TWILIO_WHATSAPP_TO=whatsapp:+525519060013
```

## Paso 5: Reiniciar el servidor

```bash
cd backend
npm start
```

Verás:
```
✅ Cliente Twilio inicializado
```

## Paso 6: ¡Probar!

Ejecuta:
```bash
curl http://localhost:5000/api/test-notificaciones
```

O espera 1 minuto y recibirás el mensaje automáticamente.

---

## 📱 Sin Twilio (Modo Manual)

Si NO configuras Twilio, el sistema seguirá funcionando en **modo manual**:

1. Cada minuto verás en la consola un enlace como:
   ```
   https://wa.me/525519060013?text=...
   ```

2. **Copia el enlace completo** de la consola
3. Pégalo en tu navegador
4. Se abrirá WhatsApp Web con el mensaje listo
5. Haz clic en "Enviar"

---

## 💰 Costos de Twilio

- **Cuenta gratis**: $15 USD de crédito
- **Cada mensaje WhatsApp**: ~$0.005 USD
- **Con $15 puedes enviar**: ~3,000 mensajes
- **Suficiente para**: Meses o años de uso del sistema

---

## 🔄 CallMeBot - 100% GRATIS (RECOMENDADO PARA TI)

### Configuración en 3 pasos (2 minutos):

#### Paso 1: Agregar el bot a WhatsApp
1. Guarda este número en tus contactos: **+34 644 44 64 61** (nómbralo "CallMeBot")
2. Abre WhatsApp y envía este mensaje exacto al número:
   ```
   I allow callmebot to send me messages
   ```
3. En segundos recibirás tu **API Key** (algo como: `123456`)

#### Paso 2: Configurar en el sistema
Edita el archivo `.env` en la carpeta `backend` y agrega:

```env
CALLMEBOT_APIKEY=123456
```
(Reemplaza `123456` con tu API Key real)

#### Paso 3: Reiniciar el servidor
```bash
cd backend
npm start
```

Verás:
```
✅ CallMeBot configurado - envío automático ACTIVO
```

### ✅ ¡Listo! Ya recibirás mensajes automáticos GRATIS

**Límites**: 1 mensaje por minuto (perfecto para tu caso de uso)

**Ventajas**:
- ✅ 100% Gratis, sin tarjeta de crédito
- ✅ Sin límite de mensajes totales
- ✅ Configuración en 2 minutos
- ✅ Funciona inmediatamente

### 2. Usar WhatsApp Business API (Oficial pero complejo)

Requiere:
- Cuenta Facebook Business
- Verificación de negocio
- Más configuración

---

## ✅ Recomendación

**Para empezar**: Usa el **modo manual** (sin Twilio) - funciona perfecto

**Para producción**: Configura **Twilio** ($15 gratis es suficiente)

**100% Gratis**: Investiga **CallMeBot** (límite de 1 mensaje por minuto)
