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
public_id = '/user/<public_id>'


# user resource methods defined below
@app.route(user, methods=['GET'])
def get_all_users():
    users = User.query.all()
    return make_response(jsonify({"users": users}), 200)


@app.route(public_id, methods=['GET'])
def get_one_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return make_response(jsonify({"message": "User not found."}), 404)

    return make_response(jsonify({"user": user}), 200)


@app.route(user, methods=['POST'])
def create_user():
    data = request.get_json()

    # check that the username is not a duplicate
    user = User.query.filter_by(username=data['username']).first()
    if user:
        return make_response(jsonify({"message": "This username is taken."}), 409)

    hashed = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(
        uuid.uuid1()), username=data['username'], password=hashed, longest_streak=0, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return make_response(jsonify({"user": new_user}), 201)


@app.route(public_id, methods=['PUT'])
def promote_to_admin(public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return make_response(jsonify({"message": "User not found."}), 404)

    user.admin = True
    db.session.commit()

    return make_response(jsonify({"user": user}), 200)


@app.route(public_id, methods=['DELETE'])
def delete_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return make_response(jsonify({"message": "User not found."}), 404)

    db.session.delete(user)
    db.session.commit()

    return make_response(jsonify({"message": "User deleted successfully."}), 200)


if __name__ == '__main__':
    app.run(debug=True)
