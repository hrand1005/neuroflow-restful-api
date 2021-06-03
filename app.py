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
    user_id: str

    id = db.Column(db.Integer, primary_key=True)
    # date -- string? Whatever sqlite supports
    # streak -- int
    value = db.Column(db.String(50))
    user_id = db.Column(db.String(50))


# wrapper for routes requiring authentication
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return make_response(jsonify({'message': 'Authentication token required.'}), 401)

        data = jwt.decode(token, app.config['SECRET_KEY'])
        try:

            this_user = User.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return make_response(jsonify({'message': 'Invalid token.'}), 401)

        return f(this_user, *args, **kwargs)

    return decorated


# login route using http basic authentication
@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Authentication required.', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Authentication required.', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow(
        ) + TOKEN_EXP}, app.config['SECRET_KEY']).decode('UTF-8')
        return make_response(jsonify({'token': token}), 200)

    return make_response('Authentication required.', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})


# defines /mood and /mood/<id> endpoints
mood = '/mood'
mood_id = '/mood/<id>'


@ app.route(mood, methods=['GET'])
@ token_required
def get_all_moods(this_user):
    # returns all moods for this_user
    moods = Mood.query.filter_by(user_id=this_user.public_id).all()
    if not moods:
        return make_response(jsonify({"message": "You have no posted moods."}))
    return make_response(jsonify({"moods": moods}), 200)


@ app.route(mood_id, methods=['GET'])
@ token_required
def get_one_mood(this_user, id):
    # returns mood of mood_id for this_user
    mood = Mood.query.filter_by(
        user_id=this_user.public_id, id=id).first()

    if not mood:
        return make_response(jsonify({"message": "Mood not found."}), 404)

    return make_response(jsonify({"mood": mood}), 200)


@ app.route(mood, methods=['POST'])
@ token_required
def create_mood(this_user):
    data = request.get_json()
    new_mood = Mood(value=data['value'],
                    user_id=this_user.public_id)  # date=date.now

    db.session.add(new_mood)
    db.session.commit()

    return make_response(jsonify({"mood": new_mood}), 201)


@ app.route(mood_id, methods=['DELETE'])
@ token_required
def delete_mood(this_user, id):
    mood = Mood.query.filter_by(user_id=this_user.public_id, id=id).first()

    if not mood:
        return make_response(jsonify({"message": "Mood not found."}), 404)

    db.session.delete(mood)
    db.session.commit()

    return make_response(jsonify({"message": "Mood deleted successfully."}), 200)

    # defines /user and /user/<public_id> endpoints
user = '/user'
public_id = '/user/<public_id>'


# user resource methods defined below
@ app.route(user, methods=['GET'])
@ token_required
def get_all_users(this_user):
    if not this_user.admin:
        return make_response(jsonify({"message": "You do not have the necessary privileges for this action."}), 401)
    users = User.query.all()
    return make_response(jsonify({"users": users}), 200)


@ app.route(public_id, methods=['GET'])
@ token_required
def get_one_user(this_user, public_id):
    if not this_user.admin:
        return make_response(jsonify({"message": "You do not have the necessary privileges for this action."}), 401)
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return make_response(jsonify({"message": "User not found."}), 404)

    return make_response(jsonify({"user": user}), 200)


@ app.route(user, methods=['POST'])
@ token_required
def create_user(this_user):
    if not this_user.admin:
        return make_response(jsonify({"message": "You do not have the necessary privileges for this action."}), 401)
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


@ app.route(public_id, methods=['PUT'])
@ token_required
def promote_to_admin(this_user, public_id):
    if not this_user.admin:
        return make_response(jsonify({"message": "You do not have the necessary privileges for this action."}), 401)
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return make_response(jsonify({"message": "User not found."}), 404)

    user.admin = True
    db.session.commit()

    return make_response(jsonify({"user": user}), 200)


@ app.route(public_id, methods=['DELETE'])
@ token_required
def delete_user(this_user, public_id):
    if not this_user.admin:
        return make_response(jsonify({"message": "You do not have the necessary privileges for this action."}), 401)
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return make_response(jsonify({"message": "User not found."}), 404)

    db.session.delete(user)
    db.session.commit()

    return make_response(jsonify({"message": "User deleted successfully."}), 200)


if __name__ == '__main__':
    #hashed = generate_password_hash(data['admin'], method='sha256')
    # admin_user = User(public_id=str(
    #    uuid.uuid1()), username="admin", password=hashed, longest_streak=0, admin=True)
    # db.session.add(admin_user)
    # db.session.commit()
    app.run(debug=True)
