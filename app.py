from dataclasses import dataclass
from flask import Flask, jsonify, make_response, request
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import jwt
import uuid


TOKEN_EXP = datetime.timedelta(minutes=30)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'samplesecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# defines User class
@dataclass
class User(db.Model):
    id: int
    public_id: str
    username: str
    password: str
    longest_streak: int
    admin: bool

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(50))
    longest_streak = db.Column(db.Integer)
    admin = db.Column(db.Boolean)


# defines Mood class
@dataclass
class Mood(db.Model):
    id: int
    value: str
    user_id: int

    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(50))
    user_id = db.Column(db.Integer)


# wrapper for routes requiring authentication
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')


# login route using http basic authentication
@app.route('/login')
def login():
    auth = request.authorization

    if auth and auth.password == 'password':
        token = jwt.encode(
            {'user': auth.username, 'exp': datetime.datetime.utcnow() + TOKEN_EXP}, app.config['SECRET_KEY'])
        return jsonify({'token': token})

    return make_response('Could not verify!', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})


# defines /user and /user/<public_id> endpoints
user = '/user'
user_id = '/user/<public_id>'


# 'user' resource methods defined below
@app.route(user, methods=['GET'])
def get_all_users():
    return ''


@app.route(user_id, methods=['GET'])
def get_one_user():
    return ''


@app.route(user, methods=['POST'])
def create_user():
    data = request.get_json()
    hashed = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(
        uuid.uuid1()), username=data['username'], password=hashed, longest_streak=0, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify(new_user)
    # return jsonify(vars(new_user))


@app.route(user_id, methods=['PUT'])
def promote_to_admin():
    return ''


@app.route(user_id, methods=['DELETE'])
def delete_user():
    return ''


if __name__ == '__main__':
    app.run(debug=True)
