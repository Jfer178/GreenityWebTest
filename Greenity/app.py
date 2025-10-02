from flask import Flask, request, jsonify, redirect, render_template, session, abort
from Config.db import app
import secrets
import json
import os

# La clave secreta ya está configurada en db.py

# Funciones CSRF
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

def validar_csrf(token_from_request):
    token_session = session.get('csrf_token')
    return token_session and secrets.compare_digest(token_session, token_from_request or "")

@app.route("/")
def index():
    csrf_token = generate_csrf_token()
    return render_template("views/Login.html", csrf_token=csrf_token)

@app.route("/Main")
def main():
    return render_template("views/index.html", user_authenticated=session.get('user_authenticated', False), user_email=session.get('user_email', ''))

@app.route("/Mapa")
def mapa():
    return render_template("views/Mapa.html", user_authenticated=session.get('user_authenticated', False), user_email=session.get('user_email', ''))

@app.route("/Configuracion")
def config():
    return render_template("views/Configuracion.html", user_authenticated=session.get('user_authenticated', False), user_email=session.get('user_email', ''))

@app.route("/Contacto")
def contacto():
    return render_template("views/Contacto.html", user_authenticated=session.get('user_authenticated', False), user_email=session.get('user_email', ''))

@app.route("/Educativo")
def edu():
    return render_template("views/Educativo.html", user_authenticated=session.get('user_authenticated', False), user_email=session.get('user_email', ''))

@app.route("/Reciclaje")
def rec():
    return render_template("views/SugerirPunto.html", user_authenticated=session.get('user_authenticated', False), user_email=session.get('user_email', ''))

# Rutas de autenticación con protección CSRF
@app.route("/login", methods=['POST'])
def login():
    token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    if not validar_csrf(token):
        print(f"CSRF Token inválido. Token recibido: {token}")
        abort(403, description="CSRF Token Inválido")
    
    data = request.form.to_dict()
    email = data.get('email', '')
    password = data.get('password', '')
    
    print(f"Intentando login con email: {email}, password: {password}")
    
    # Aquí puedes agregar tu lógica de validación de credenciales
    # Por ahora, un ejemplo básico
    if email == "admin@greenity.com" and password == "123456":
        session['user_authenticated'] = True
        session['user_email'] = email
        print("Login exitoso")
        return jsonify({
            "status": 200,
            "message": "Login exitoso",
            "url": "/Main"
        })
    else:
        print(f"Credenciales inválidas. Email: {email}, Password: {password}")
        return jsonify({
            "status": 401,
            "message": "Credenciales inválidas"
        })

@app.route("/register", methods=['POST'])
def register():
    token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    if not validar_csrf(token):
        abort(403, description="CSRF Token Inválido")
    
    data = request.form.to_dict()
    name = data.get('name', '')
    email = data.get('email', '')
    password = data.get('password', '')
    confirm_password = data.get('confirm_password', '')
    
    # Validaciones básicas
    if password != confirm_password:
        return jsonify({
            "status": 400,
            "message": "Las contraseñas no coinciden"
        })
    
    if len(password) < 6:
        return jsonify({
            "status": 400,
            "message": "La contraseña debe tener al menos 6 caracteres"
        })
    
    # Aquí puedes agregar tu lógica de registro en base de datos
    # Por ahora, solo confirmamos el registro
    return jsonify({
        "status": 200,
        "message": "Usuario registrado exitosamente",
        "url": "/Main"
    })

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# API para obtener datos de puntos de reciclaje
@app.route("/api/puntos-reciclaje")
def get_puntos_reciclaje():
    """Endpoint para obtener los datos del scraping de puntos de reciclaje"""
    try:
        # Ruta al archivo JSON generado por el scraping
        json_file_path = os.path.join(os.path.dirname(__file__), 'puntos_reciclaje_barranquilla.json')
        
        # Verificar si el archivo existe
        if not os.path.exists(json_file_path):
            return jsonify({
                "success": False,
                "error": "Archivo de datos no encontrado",
                "data": []
            }), 404
        
        # Leer y retornar los datos
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        return jsonify(data)
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Error al cargar datos: {str(e)}",
            "data": []
        }), 500

@app.route("/api/ejecutar-scraping", methods=['POST'])
def ejecutar_scraping():
    """Endpoint para ejecutar el scraping y actualizar los datos"""
    try:
        # Importar y ejecutar el scraper
        from scraping import RecyclingPointsScraper
        
        scraper = RecyclingPointsScraper()
        data = scraper.scrape()
        
        if data.get('success'):
            # Guardar los datos actualizados
            scraper.save_to_json(data)
            return jsonify({
                "success": True,
                "message": "Scraping ejecutado exitosamente",
                "estadisticas": data.get('estadisticas', {})
            })
        else:
            return jsonify({
                "success": False,
                "error": data.get('error', 'Error desconocido')
            }), 500
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Error ejecutando scraping: {str(e)}"
        }), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000, host='0.0.0.0')
    