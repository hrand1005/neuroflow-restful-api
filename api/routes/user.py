from api.model.user import User
from api.routes.login import token_required
from config import db
from flask import Blueprint, jsonify, make_response, request
from werkzeug.security import generate_password_hash
import uuid

user_api = Blueprint('user_api', __name__)

# USER RESOURCE AND ASSOCIATED METHODS
# defines /user and /user/<public_id> endpoints
user = '/user'
public_id = '/user/<public_id>'


# common response for no admin privileges
def not_allowed():
    return make_response(jsonify({"message": "You do not have the necessary privileges for this action."}), 401)


# common response for user not found
def not_found():
    return make_response(jsonify({"message": "User not found."}), 404)


# DEBUGGING/EXTENDING ENDPOINT
@ user_api.route(user, methods=['GET'])
@ token_required
def get_all_users(this_user):
    if not this_user.admin:
        return not_allowed()
    users = User.query.all()
    return make_response(jsonify({"users": users}), 200)


# DEBUGGING/EXTENDING ENDPOINT
@ user_api.route(public_id, methods=['GET'])
@ token_required
def get_one_user(this_user, public_id):
    if not this_user.admin:
        return not_allowed()
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return not_found()

    return make_response(jsonify({"user": user}), 200)


# DEBUGGING/EXTENDING ENDPOINT
@ user_api.route(user, methods=['POST'])
@ token_required
def create_user(this_user):
    if not this_user.admin:
        return not_allowed()
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


# DEBUGGING/EXTENDING ENDPOINT
@ user_api.route(public_id, methods=['PUT'])
@ token_required
def promote_to_admin(this_user, public_id):
    if not this_user.admin:
        return not_allowed()
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return not_found()

    user.admin = True
    db.session.commit()

    return make_response(jsonify({"user": user}), 200)


# DEBUGGING/EXTENDING ENDPOINT
@ user_api.route(public_id, methods=['DELETE'])
@ token_required
def delete_user(this_user, public_id):
    if not this_user.admin:
        return not_allowed()
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return not_found()

    db.session.delete(user)
    db.session.commit()

    return make_response(jsonify({"message": "User deleted successfully."}), 200)
