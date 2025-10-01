from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import secrets

app = Flask(__name__)

#creamos las credenciales para conectarnos a la bd
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost/greenity_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Clave secreta más segura para las sesiones
app.secret_key = secrets.token_hex(32)

#creamos los objetos de bd

db = SQLAlchemy(app)
ma = Marshmallow(app)