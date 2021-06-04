from flask import Blueprint, jsonify, make_response

home_api = Blueprint('home_api', __name__)


@ home_api.route('/', methods=['GET'])
def home():
    # returns simple project details
    project = {"version": "1.0",
               "owner": "Herbie",
               "name": "Simple Restful API"}

    return make_response(jsonify(project), 200)
