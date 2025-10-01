# Implementación de Protección CSRF en Greenity

## Resumen
Se ha implementado protección CSRF (Cross-Site Request Forgery) en el proyecto Greenity para prevenir ataques de falsificación de solicitudes entre sitios.

## Archivos Modificados

### 1. `app.py`
- **Importaciones agregadas**: `session`, `abort`, `secrets`
- **Configuración**: Clave secreta para sesiones usando `secrets.token_hex(32)`
- **Funciones CSRF**:
  - `generate_csrf_token()`: Genera un token CSRF único para cada sesión
  - `validar_csrf()`: Valida el token CSRF recibido contra el de la sesión
- **Rutas de autenticación**:
  - `/login` (POST): Procesa el login con validación CSRF
  - `/register` (POST): Procesa el registro con validación CSRF
  - `/logout`: Limpia la sesión del usuario

### 2. `Login.html`
- **Campos ocultos agregados**: Tokens CSRF en ambos formularios
- **Atributos name agregados**: A todos los inputs para el envío de datos
- **Tokens**: Se pasan desde el backend usando `{{ csrf_token }}`

### 3. `Login.js`
- **Función `submitForm()` actualizada**: Ahora envía peticiones reales al backend
- **Protección CSRF**: Incluye el token en el header `X-CSRF-Token`
- **Manejo de respuestas**: Procesa las respuestas JSON del servidor
- **Redirección automática**: Después de login/registro exitoso

## Cómo Funciona

1. **Generación del Token**: Cuando el usuario visita la página de login, se genera un token CSRF único
2. **Inclusión en Formularios**: El token se incluye como campo oculto en ambos formularios
3. **Envío de Peticiones**: Al enviar un formulario, el token se incluye en el header y body
4. **Validación**: El servidor valida que el token coincida con el de la sesión
5. **Protección**: Si el token no es válido, se rechaza la petición con error 403

## Credenciales de Prueba
- **Email**: admin@greenity.com
- **Contraseña**: 123456

## Características de Seguridad

- **Tokens únicos**: Cada sesión tiene un token diferente
- **Validación segura**: Usa `secrets.compare_digest()` para comparación segura
- **Doble validación**: Token en header y en form data
- **Limpieza de sesión**: Al hacer logout se limpia toda la sesión
- **Manejo de errores**: Respuestas apropiadas para diferentes tipos de error

## Uso

1. Ejecutar la aplicación: `python app.py`
2. Visitar `http://localhost:5000`
3. Usar las credenciales de prueba o registrar un nuevo usuario
4. El sistema automáticamente manejará la protección CSRF

## Notas Importantes

- Los tokens CSRF se regeneran automáticamente en cada sesión
- La validación es estricta: cualquier token inválido resulta en error 403
- El sistema es compatible con el diseño existente de la aplicación
- No se requieren cambios adicionales en otros archivos del proyecto
