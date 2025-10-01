# Implementación del Menú de Usuario en Greenity

## Resumen
Se ha implementado un sistema de menú de usuario que muestra el nombre del usuario logueado en lugar del botón "Iniciar Sesión" y permite cerrar sesión.

## Funcionalidades Implementadas

### 1. **Visualización del Token CSRF**
- Los tokens CSRF ahora se muestran en la consola del navegador
- Al cargar la página de login, verás en la consola:
  ```
  🔐 Token CSRF (Login): [token_generado]
  🔐 Token CSRF (Register): [token_generado]
  ```

### 2. **Menú de Usuario Dinámico**
- **Cuando NO está logueado**: Muestra el botón "Iniciar Sesión"
- **Cuando SÍ está logueado**: Muestra el nombre del usuario con un menú desplegable

### 3. **Características del Menú de Usuario**
- **Nombre del usuario**: Se extrae del email (parte antes del @)
- **Icono de usuario**: Ícono de Font Awesome
- **Menú desplegable** con opciones:
  - **Mi Perfil**: Enlace a configuración
  - **Cerrar Sesión**: Cierra la sesión y redirige al login

## Archivos Modificados

### 1. **`Login.js`**
- Agregada función `showCSRFToken()` para mostrar tokens en consola
- Los tokens se muestran automáticamente al cargar la página

### 2. **`navbar.html`**
- Agregada lógica condicional para mostrar menú de usuario o botón de login
- Implementado menú desplegable con opciones de usuario

### 3. **`navbar.css`**
- Estilos para el menú de usuario
- Animaciones y efectos hover
- Diseño responsive para móviles

### 4. **`app.py`**
- Todas las rutas ahora pasan información del usuario a las plantillas
- Variables disponibles: `user_authenticated` y `user_email`

## Cómo Funciona

### **Flujo de Autenticación:**
1. Usuario hace login con credenciales válidas
2. Se guarda `user_authenticated = True` y `user_email` en la sesión
3. Al navegar a cualquier página, el navbar detecta que está logueado
4. Muestra el nombre del usuario en lugar de "Iniciar Sesión"

### **Flujo de Cierre de Sesión:**
1. Usuario hace clic en "Cerrar Sesión"
2. Se limpia toda la sesión (`session.clear()`)
3. Se redirige a la página de login
4. El navbar vuelve a mostrar "Iniciar Sesión"

## Estilos y Diseño

### **Menú de Usuario:**
- **Color**: Gradiente verde (mismo que el botón de login)
- **Efectos**: Hover con elevación y rotación del ícono
- **Animación**: Efecto de brillo deslizante
- **Responsive**: Se adapta a pantallas móviles

### **Menú Desplegable:**
- **Posición**: Aparece debajo del nombre del usuario
- **Efectos**: Fade in/out suave
- **Opciones**: Con íconos y efectos hover

## Credenciales de Prueba
- **Email**: `admin@greenity.com`
- **Contraseña**: `123456`
- **Resultado**: El navbar mostrará "admin" como nombre de usuario

## Verificación

### **Para ver el Token CSRF:**
1. Abre las herramientas de desarrollador (F12)
2. Ve a la pestaña "Console"
3. Recarga la página de login
4. Verás los tokens CSRF en la consola

### **Para probar el menú de usuario:**
1. Haz login con las credenciales de prueba
2. Navega a cualquier página (Main, Mapa, etc.)
3. Verás tu nombre en el navbar en lugar de "Iniciar Sesión"
4. Haz hover sobre tu nombre para ver el menú desplegable
5. Haz clic en "Cerrar Sesión" para volver al estado inicial

## Notas Técnicas

- **Extracción del nombre**: Se usa `session.user_email.split('@')[0]` para obtener la parte antes del @
- **Capitalización**: El nombre se muestra con la primera letra en mayúscula
- **Sesión persistente**: La sesión se mantiene hasta que el usuario cierre sesión o cierre el navegador
- **Compatibilidad**: Funciona en todas las páginas del sitio
