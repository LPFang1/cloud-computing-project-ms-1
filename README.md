# MS1 - Customer Service 🏦

**Microservicio para gestión de clientes, onboarding e identidad**

MS1 es el microservicio responsable del onboarding de clientes, gestión de identidades y actualización de perfiles en el sistema bancario. Proporciona APIs REST para el registro de clientes, validación KYC (Know Your Customer), y integración con otros microservicios del ecosistema.

## 🚀 Características Principales

- ✅ **Registro de Clientes**: Onboarding completo con validación de datos personales
- ✅ **Gestión de Identidad**: Verificación de documentos de identidad (cédula, pasaporte)
- ✅ **Know Your Customer (KYC)**: Almacenamiento y gestión de documentos de verificación
- ✅ **Actualización de Perfiles**: Modificación de información de contacto y preferencias
- ✅ **Integración MS2**: Consulta de cuentas asociadas al cliente
- ✅ **Integración MS4**: Verificación automática de compliance
- ✅ **Seguridad**: Rate limiting, validación, sanitización y headers de seguridad
- ✅ **Validación Robusta**: Esquemas de validación con Joi para todos los endpoints
- ✅ **Base de Datos**: MongoDB con esquemas flexibles para documentos KYC

## 🛠 Tecnologías Utilizadas

- **Runtime**: Node.js 20 + TypeScript
- **Framework**: Express.js con middleware de seguridad
- **Base de Datos**: MongoDB con Mongoose ODM
- **Validación**: Joi para validación de esquemas
- **Seguridad**: Helmet, CORS, Rate Limiting, Input Sanitization
- **Comunicación**: REST APIs con integración HTTP a otros microservicios
- **Contenedores**: Docker + Docker Compose para desarrollo

## 📋 Reglas de Negocio Implementadas

### Validación de Unicidad
- ✅ Email único en el sistema
- ✅ Número de identificación nacional único
- ✅ Validación de formato de documentos

### Gestión KYC
- ✅ Almacenamiento flexible de documentos (imágenes, PDFs)
- ✅ Estados de verificación por documento
- ✅ Integración automática con MS4 para compliance

### Integración de Servicios
- ✅ Consulta automática de cuentas en MS2
- ✅ Trigger automático de verificación de compliance en MS4
- ✅ Manejo de errores y timeouts de servicios externos

## 🏗 Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                    MS1 - Customer Service                   │
├─────────────────────────────────────────────────────────────┤
│  Controllers  │  Routes  │  Middleware  │  Validators      │
├─────────────────────────────────────────────────────────────┤
│            Services (External Integration)                  │
├─────────────────────────────────────────────────────────────┤
│                    MongoDB (Mongoose)                      │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
        ┌──────────────────────────────────────────┐
        │     Integración con Microservicios       │
        ├──────────────────┬───────────────────────┤
        │  MS2 - Accounts  │  MS4 - Compliance     │
        │  (Cuentas)       │  (Cumplimiento)       │
        └──────────────────┴───────────────────────┘
```

## 🔧 Configuración e Instalación

### Prerrequisitos
- Node.js 20+
- MongoDB 7+
- Docker & Docker Compose (opcional)

### Instalación Local

```bash
# Clonar el repositorio
git clone <repository-url>
cd cloud-computing-project-ms-1

# Instalar dependencias
npm install

# Configurar variables de entorno
cp .env.example .env
# Editar .env con tus configuraciones

# Iniciar MongoDB (si no tienes Docker)
mongod

# Compilar TypeScript
npm run build

# Iniciar en modo desarrollo
npm run dev

# O iniciar en producción
npm start
```

### Instalación con Docker

```bash
# Iniciar todos los servicios (MS1 + MongoDB)
docker-compose up -d

# Con simuladores de MS2 y MS4 para testing
docker-compose --profile simulators up -d

# Con interfaz admin de MongoDB
docker-compose --profile admin up -d

# Ver logs
docker-compose logs -f ms1-customer-service
```

## 📡 API Endpoints

### 🏥 Health & Status
```http
GET  /health                 # Estado de salud del servicio
GET  /                       # Información general del servicio
```

### 👤 Gestión de Clientes
```http
POST   /api/customers        # Registrar nuevo cliente
GET    /api/customers/:id    # Obtener detalles de cliente
PUT    /api/customers/:id    # Actualizar información de cliente
DELETE /api/customers/:id    # Desactivar cliente (soft delete)
GET    /api/customers        # Buscar/listar clientes (con paginación)
```

### 🔗 Integraciones
```http
GET  /api/customers/:id/accounts   # Obtener cuentas del cliente (MS2)
```

### 📄 Documentos KYC
```http
POST /api/customers/:id/documents  # Agregar documento KYC
```

## 💼 Ejemplos de Uso

### Registrar un Nuevo Cliente

```bash
curl -X POST http://localhost:3000/api/customers \
  -H "Content-Type: application/json" \
  -d '{
    "firstName": "Juan",
    "lastName": "Pérez",
    "email": "juan.perez@email.com",
    "phone": "+57 300 123 4567",
    "dateOfBirth": "1990-05-15",
    "nationalId": "1234567890",
    "address": {
      "street": "Calle 123 #45-67",
      "city": "Bogotá",
      "state": "Cundinamarca",
      "postalCode": "110001",
      "country": "Colombia"
    },
    "preferences": {
      "language": "es",
      "currency": "COP",
      "notificationPreferences": {
        "email": true,
        "sms": true,
        "push": false
      },
      "marketingConsent": false
    }
  }'
```

### Obtener Cuentas de un Cliente

```bash
curl -X GET http://localhost:3000/api/customers/605c72ef1532071f38c51f8a/accounts
```

### Buscar Clientes

```bash
# Buscar por nombre
curl "http://localhost:3000/api/customers?q=Juan&page=1&limit=10"

# Filtrar por estado
curl "http://localhost:3000/api/customers?status=active&complianceStatus=approved"

# Filtrar por país
curl "http://localhost:3000/api/customers?country=Colombia"
```

## 🔒 Seguridad

### Implementaciones de Seguridad
- ✅ **Rate Limiting**: 100 requests/15min general, 10 registros/hora
- ✅ **Input Sanitization**: Limpieza automática de scripts maliciosos
- ✅ **CORS**: Configuración restrictiva para dominios permitidos
- ✅ **Security Headers**: Helmet.js con CSP, HSTS, etc.
- ✅ **Request Validation**: Validación exhaustiva con Joi
- ✅ **Error Handling**: No exposición de información sensible

### Variables de Entorno Críticas

```env
# Seguridad
JWT_SECRET=your_strong_jwt_secret_here
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Base de datos
MONGODB_URI=mongodb://localhost:27017/customer_service_db

# Microservicios
MS2_ACCOUNTS_URL=http://localhost:3001
MS4_COMPLIANCE_URL=http://localhost:3003
```

## 🧪 Testing

```bash
# Ejecutar tests (cuando estén configurados)
npm test

# Verificar build
npm run build

# Health check
curl http://localhost:3000/health
```

## 📊 Monitoreo

### Health Checks
- **Endpoint**: `GET /health`
- **Database Status**: Estado de conexión a MongoDB
- **External Services**: Estado de MS2 y MS4
- **Response Time**: Tiempo de respuesta promedio

### Logging
- ✅ Request logging con duración y status
- ✅ Security alerts para requests sospechosos
- ✅ Error logging detallado
- ✅ Integration status logging

## 🔄 Integración con Otros Microservicios

### MS2 - Accounts Service
**Propósito**: Consultar cuentas bancarias asociadas al cliente

```http
GET /api/customers/{customerId}/accounts
```

**Respuesta esperada de MS2**:
```json
{
  "success": true,
  "data": [
    {
      "id": "acc123",
      "accountNumber": "1234567890",
      "accountType": "checking",
      "balance": 1000.00,
      "currency": "COP",
      "status": "active"
    }
  ]
}
```

### MS4 - Compliance Service
**Propósito**: Verificación automática de compliance tras registro

**Request enviado a MS4**:
```json
{
  "customerId": "customer123",
  "customerData": {
    "nationalId": "1234567890",
    "email": "juan@email.com",
    "fullName": "Juan Pérez",
    "address": {...},
    "documents": [...]
  },
  "checkType": "onboarding"
}
```

## 🚀 Deployment

### Producción con Docker

```bash
# Build imagen de producción
docker build -t ms1-customer-service:latest .

# Ejecutar en producción
docker run -d \
  --name ms1-customer-service \
  -p 3000:3000 \
  -e NODE_ENV=production \
  -e MONGODB_URI=mongodb://prod-mongo:27017/customer_service_db \
  -e MS2_ACCOUNTS_URL=http://ms2-service:3001 \
  -e MS4_COMPLIANCE_URL=http://ms4-service:3003 \
  ms1-customer-service:latest
```

### Environment Variables de Producción

```env
NODE_ENV=production
PORT=3000
MONGODB_URI=mongodb://prod-mongo:27017/customer_service_db
MS2_ACCOUNTS_URL=http://ms2-service:3001
MS4_COMPLIANCE_URL=http://ms4-service:3003
JWT_SECRET=your_production_secret_very_long_and_secure
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
LOG_LEVEL=warn
```

## 🐛 Troubleshooting

### Problemas Comunes

**Error de conexión a MongoDB**:
```bash
# Verificar que MongoDB esté corriendo
mongosh mongodb://localhost:27017/customer_service_db

# En Docker
docker-compose logs mongodb
```

**Error de conexión a MS2/MS4**:
```bash
# Verificar conectividad
curl http://localhost:3001/health  # MS2
curl http://localhost:3003/health  # MS4

# Verificar configuración
echo $MS2_ACCOUNTS_URL
echo $MS4_COMPLIANCE_URL
```

**Error de compilación TypeScript**:
```bash
# Limpiar y recompilar
npm run clean
npm run build
```

## 📈 Métricas de Rendimiento

### Objetivos de Performance
- **Response Time**: < 200ms para operaciones CRUD
- **Throughput**: 1000+ requests/minuto
- **Availability**: 99.9% uptime
- **Database**: < 100ms query time promedio

### Limits y Rate Limiting
- **General**: 100 requests / 15 minutos por IP
- **Customer Creation**: 10 registros / hora por IP+email
- **Request Size**: Máximo 10MB por request
- **Database**: Pool de 10 conexiones

## 🔍 Logs y Debug

### Estructura de Logs
```
[TIMESTAMP] [LEVEL] MESSAGE
2024-01-01T12:00:00Z INFO  Server started on port 3000
2024-01-01T12:00:01Z WARN  MS4 compliance service unavailable
2024-01-01T12:00:02Z ERROR Database connection failed
```

### Debug Mode
```bash
# Activar logs detallados
export LOG_LEVEL=debug
npm run dev
```

## 📚 Documentación Adicional

- [API Documentation](./docs/api.md) - Documentación detallada de API
- [Database Schema](./docs/database.md) - Esquemas de base de datos
- [Integration Guide](./docs/integrations.md) - Guía de integración
- [Deployment Guide](./docs/deployment.md) - Guía de deployment

## 🤝 Contribución

1. Fork el repositorio
2. Crear feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit cambios (`git commit -m 'Add AmazingFeature'`)
4. Push al branch (`git push origin feature/AmazingFeature`)
5. Abrir Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE.md](LICENSE.md) para detalles.

## 👥 Team

- **Desarrollador Principal**: [Tu Nombre]
- **Arquitecto de Microservicios**: [Nombre del Arquitecto]
- **DevOps**: [Nombre DevOps]

---

**MS1 - Customer Service v1.0.0**  
*Parte del ecosistema de microservicios bancarios*  
🏦 *Banking Microservices Architecture Project*

## 📈 Database ER Diagram (Mermaid)

A continuación se muestra el diagrama entidad-relación (ER) del modelo principal `Customer` en formato Mermaid. En MongoDB estos son subdocumentos embebidos pero se representan aquí como entidades para mayor claridad.

```mermaid
erDiagram
  CUSTOMER {
    ObjectId id PK
    string firstName
    string lastName
    string email UNIQUE
    string phone
    date dateOfBirth
    string nationalId UNIQUE
    string passportNumber
    date registrationDate
    date lastLoginDate
    enum status {"active","inactive","suspended","pending_verification"}
    enum complianceStatus {"pending","approved","rejected","under_review"}
    string complianceNotes
    date complianceCheckedAt
    boolean emailVerified
    boolean phoneVerified
    boolean identityVerified
    date createdAt
    date updatedAt
  }

  ADDRESS {
    string street
    string city
    string state
    string postalCode
    string country
  }

  KYCDOCUMENT {
    ObjectId docId
    enum type {"national_id","passport","driving_license","address_proof","income_proof","other"}
    string filename
    date uploadDate
    boolean verified
    string verifiedBy
    date verifiedAt
  }

  PREFERENCES {
    string language
    string currency
    boolean marketingConsent
    boolean notify_email
    boolean notify_sms
    boolean notify_push
  }

  %% Relaciones
  CUSTOMER ||--|| ADDRESS : "has address"
  CUSTOMER ||--|| PREFERENCES : "has preferences"
  CUSTOMER ||--o{ KYCDOCUMENT : "has documents"

  %% Notas / índices
  note for CUSTOMER "Índices: phone, status, complianceStatus, address.country" 
```
