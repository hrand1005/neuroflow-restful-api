from api.model.user import User
from config import TOKEN_EXP, SECRET_KEY
from flask import Blueprint, jsonify, make_response, request
from functools import wraps
from werkzeug.security import check_password_hash
import datetime
import jwt

# LOGIN AND TOKEN AUTHENTICATION METHODS

# wrapper for routes requiring authentication

login_api = Blueprint('login_api', __name__)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # if auth header exists, init token, else return 401
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        else:
            return make_response(jsonify({'message': 'Authentication token required.'}), 401)

        # try to decode token and find related user in db
        try:
            data = jwt.decode(token, SECRET_KEY)
            this_user = User.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return make_response(jsonify({'message': 'Invalid token.'}), 401)

        # returns user corresponding to given token to wrapped functions
        return f(this_user, *args, **kwargs)

    return decorated


# REQUIRED ENDPOINT
@login_api.route('/login')
def login():
    # parse authorization from request header
    auth = request.authorization

    # check auth credentials exist before querying db
    if not auth or not auth.username or not auth.password:
        return make_response('Authentication required.', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

    # query db by username, which should be unique. if doesn't exist, return 401
    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Authentication required.', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

    # if password is correct, return token and response code 200, else return 401
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow(
        ) + TOKEN_EXP}, SECRET_KEY).decode('UTF-8')
        return make_response(jsonify({'token': token}), 200)

    return make_response('Authentication required.', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})
