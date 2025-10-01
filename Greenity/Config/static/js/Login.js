// Login animado y moderno para Greenity
document.addEventListener('DOMContentLoaded', function() {
    // Elementos del DOM
    const tabButtons = document.querySelectorAll('.tab-btn');
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const loginFormElement = document.getElementById('loginForm');
    const registerFormElement = document.getElementById('registerForm');
    const togglePasswordButtons = document.querySelectorAll('.toggle-password');
    
    // Variables de estado
    let currentTab = 'login';
    let isSubmitting = false;

    // Inicialización
    init();

    function init() {
        setupTabSwitching();
        setupPasswordToggles();
        setupFormValidation();
        setupFormSubmissions();
        setupAnimations();
        showCSRFToken();
    }

    // Mostrar el token CSRF en la consola
    function showCSRFToken() {
        const loginToken = document.getElementById('login-csrf-token');
        const registerToken = document.getElementById('register-csrf-token');
        
        if (loginToken) {
            console.log('🔐 Token CSRF (Login):', loginToken.value);
        }
        if (registerToken) {
            console.log('🔐 Token CSRF (Register):', registerToken.value);
        }
    }

    // Cambio de tabs con animaciones
    function setupTabSwitching() {
        tabButtons.forEach(button => {
            button.addEventListener('click', function() {
                const targetTab = this.getAttribute('data-tab');
                if (targetTab !== currentTab) {
                    switchTab(targetTab);
                }
            });
        });
    }

    function switchTab(tabName) {
        // Remover clase active de todos los tabs
        tabButtons.forEach(btn => btn.classList.remove('active'));
        
        // Agregar clase active al tab seleccionado
        const activeButton = document.querySelector(`[data-tab="${tabName}"]`);
        activeButton.classList.add('active');
        
        // Ocultar formulario actual con animación
        const currentForm = tabName === 'login' ? registerForm : loginForm;
        const newForm = tabName === 'login' ? loginForm : registerForm;
        
        currentForm.style.opacity = '0';
        currentForm.style.transform = 'translateX(30px)';
        
        setTimeout(() => {
            currentForm.classList.add('hidden');
            newForm.classList.remove('hidden');
            newForm.style.opacity = '0';
            newForm.style.transform = 'translateX(30px)';
            
            // Animar entrada del nuevo formulario
            requestAnimationFrame(() => {
                newForm.style.transition = 'all 0.5s ease-out';
                newForm.style.opacity = '1';
                newForm.style.transform = 'translateX(0)';
            });
        }, 250);
        
        currentTab = tabName;
    }

    // Toggle de visibilidad de contraseñas
    function setupPasswordToggles() {
        togglePasswordButtons.forEach(button => {
            button.addEventListener('click', function() {
                const inputId = this.id.replace('toggle-', '');
                const input = document.getElementById(inputId);
                const icon = this;
                
                if (input.type === 'password') {
                    input.type = 'text';
                    icon.classList.remove('fa-eye');
                    icon.classList.add('fa-eye-slash');
                } else {
                    input.type = 'password';
                    icon.classList.remove('fa-eye-slash');
                    icon.classList.add('fa-eye');
                }
                
                // Efecto de animación en el icono
                icon.style.transform = 'scale(1.2)';
                setTimeout(() => {
                    icon.style.transform = 'scale(1)';
                }, 150);
            });
        });
    }

    // Validación de formularios
    function setupFormValidation() {
        const inputs = document.querySelectorAll('input[required]');
        
        inputs.forEach(input => {
            // Validación en tiempo real
            input.addEventListener('blur', function() {
                validateInput(this);
            });
            
            input.addEventListener('input', function() {
                clearValidation(this);
            });
        });
    }

    function validateInput(input) {
        const wrapper = input.closest('.input-wrapper');
        const value = input.value.trim();
        let isValid = true;
        let message = '';

        // Limpiar clases anteriores
        wrapper.classList.remove('error', 'success');
        
        // Validaciones específicas
        if (input.type === 'email') {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            isValid = emailRegex.test(value);
            message = 'Por favor ingresa un email válido';
        } else if (input.type === 'password') {
            if (input.id.includes('confirm')) {
                const password = document.getElementById(input.id.replace('confirm-', ''));
                isValid = value === password.value;
                message = 'Las contraseñas no coinciden';
            } else {
                isValid = value.length >= 6;
                message = 'La contraseña debe tener al menos 6 caracteres';
            }
        } else if (input.type === 'text') {
            isValid = value.length >= 2;
            message = 'El nombre debe tener al menos 2 caracteres';
        }

        if (!isValid && value !== '') {
            wrapper.classList.add('error');
            showTooltip(input, message);
        } else if (isValid && value !== '') {
            wrapper.classList.add('success');
        }
        
        return isValid;
    }

    function clearValidation(input) {
        const wrapper = input.closest('.input-wrapper');
        wrapper.classList.remove('error', 'success');
        hideTooltip(input);
    }

    function showTooltip(input, message) {
        hideTooltip(input); // Remover tooltip existente
        
        const tooltip = document.createElement('div');
        tooltip.className = 'validation-tooltip';
        tooltip.textContent = message;
        tooltip.style.cssText = `
            position: absolute;
            top: -35px;
            left: 0;
            background: #e74c3c;
            color: white;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 0.8rem;
            white-space: nowrap;
            z-index: 1000;
            animation: fadeInDown 0.3s ease-out;
        `;
        
        const wrapper = input.closest('.input-wrapper');
        wrapper.style.position = 'relative';
        wrapper.appendChild(tooltip);
    }

    function hideTooltip(input) {
        const tooltip = input.closest('.input-wrapper').querySelector('.validation-tooltip');
        if (tooltip) {
            tooltip.remove();
        }
    }

    // Envío de formularios
    function setupFormSubmissions() {
        loginFormElement.addEventListener('submit', function(e) {
            e.preventDefault();
            handleFormSubmission(this, 'login');
        });

        registerFormElement.addEventListener('submit', function(e) {
            e.preventDefault();
            handleFormSubmission(this, 'register');
        });
    }

    function handleFormSubmission(form, type) {
        if (isSubmitting) return;
        
        const inputs = form.querySelectorAll('input[required]');
        let allValid = true;
        
        // Validar todos los campos
        inputs.forEach(input => {
            if (!validateInput(input)) {
                allValid = false;
            }
        });
        
        if (!allValid) {
            showNotification('Por favor corrige los errores antes de continuar', 'error');
            return;
        }
        
        // Validación adicional para registro
        if (type === 'register') {
            const password = document.getElementById('register-password').value;
            const confirmPassword = document.getElementById('register-confirm-password').value;
            
            if (password !== confirmPassword) {
                showNotification('Las contraseñas no coinciden', 'error');
                return;
            }
        }
        
        // Simular envío
        submitForm(form, type);
    }

    function submitForm(form, type) {
        isSubmitting = true;
        const submitBtn = form.querySelector('.submit-btn');
        const originalText = submitBtn.innerHTML;
        
        // Estado de carga
        submitBtn.classList.add('loading');
        submitBtn.innerHTML = '<i class="fas fa-spinner"></i> Procesando...';
        


        
        // Obtener datos del formulario
        const formData = new FormData(form);
        const token = formData.get('csrf_token');
        
        // Determinar la URL del endpoint
        const endpoint = type === 'login' ? '/login' : '/register';
        
        // Realizar petición con protección CSRF
        console.log('Enviando petición a:', endpoint);
        console.log('Token CSRF:', token);
        console.log('Datos del formulario:', Object.fromEntries(formData));
        
        fetch(endpoint, {
            method: 'POST',
            body: formData,
            headers: {
                'X-CSRF-Token': token
            }
        })
        .then(response => response.json())
        .then(data => {
            isSubmitting = false;
            submitBtn.classList.remove('loading');
            submitBtn.innerHTML = originalText;
            
            if (data.status === 200) {
                // Mostrar éxito
                showNotification(data.message, 'success');
                
                // Resetear formulario
                form.reset();
                clearAllValidations();
                
                // Redirigir si hay URL
                if (data.url) {
                    setTimeout(() => {
                        window.location.href = data.url;
                    }, 1500);
                }
            } else {
                // Mostrar error
                showNotification(data.message, 'error');
            }
        })
        .catch(error => {
            isSubmitting = false;
            submitBtn.classList.remove('loading');
            submitBtn.innerHTML = originalText;
            
            console.error('Error:', error);
            showNotification('Error de conexión. Inténtalo de nuevo.', 'error');
        });
    }

    function clearAllValidations() {
        const wrappers = document.querySelectorAll('.input-wrapper');
        wrappers.forEach(wrapper => {
            wrapper.classList.remove('error', 'success');
            const tooltip = wrapper.querySelector('.validation-tooltip');
            if (tooltip) tooltip.remove();
        });
    }

    // Notificaciones
    function showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
            <span>${message}</span>
        `;
        
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${type === 'success' ? '#20bf6b' : type === 'error' ? '#e74c3c' : '#3498db'};
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            display: flex;
            align-items: center;
            gap: 10px;
            z-index: 10000;
            animation: slideInRight 0.5s ease-out;
            max-width: 300px;
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remover después de 4 segundos
        setTimeout(() => {
            notification.style.animation = 'slideOutRight 0.5s ease-out';
            setTimeout(() => notification.remove(), 500);
        }, 4000);
    }

    // Animaciones adicionales
    function setupAnimations() {
        // Animación de entrada para inputs
        const inputs = document.querySelectorAll('input');
        inputs.forEach((input, index) => {
            input.addEventListener('focus', function() {
                this.parentElement.style.transform = 'scale(1.02)';
            });
            
            input.addEventListener('blur', function() {
                this.parentElement.style.transform = 'scale(1)';
            });
        });
        
        // Efecto de hover en botones
        const buttons = document.querySelectorAll('button, .submit-btn');
        buttons.forEach(button => {
            button.addEventListener('mouseenter', function() {
                this.style.transform = 'translateY(-2px)';
            });
            
            button.addEventListener('mouseleave', function() {
                if (!this.classList.contains('loading')) {
                    this.style.transform = 'translateY(0)';
                }
            });
        });
    }

    // Agregar estilos CSS para animaciones adicionales
    const additionalStyles = `
        @keyframes slideInRight {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        @keyframes slideOutRight {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
        
        @keyframes fadeInDown {
            from { transform: translateY(-10px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        
        .input-wrapper {
            transition: transform 0.3s ease;
        }
        
        .notification {
            font-family: 'Inter', sans-serif;
            font-weight: 500;
        }
    `;
    
    const styleSheet = document.createElement('style');
    styleSheet.textContent = additionalStyles;
    document.head.appendChild(styleSheet);
});

// Función para enlace "¿Olvidaste tu contraseña?"
document.addEventListener('DOMContentLoaded', function() {
    const forgotPasswordLink = document.querySelector('.forgot-password');
    if (forgotPasswordLink) {
        forgotPasswordLink.addEventListener('click', function(e) {
            e.preventDefault();
            alert('Funcionalidad de recuperación de contraseña próximamente disponible');
        });
    }
});
