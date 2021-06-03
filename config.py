from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import datetime

# global variable determines the time it takes for basic authentication token to expire
TOKEN_EXP = datetime.timedelta(minutes=30)
# should get this from an environment variable
SECRET_KEY = 'samplesecretkey'

# configure flask app and SQLAlchemy Database
app = Flask(__name__)
#app.config['SECRET_KEY'] = 'samplesecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# init database
db = SQLAlchemy(app)
