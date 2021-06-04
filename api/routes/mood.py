from api.model.mood import Mood
from api.model.user import User
from api.routes.login import token_required
from config import db
from flask import Blueprint, jsonify, make_response, request
import datetime


mood_api = Blueprint('mood_api', __name__)

# MOOD RESOURCE AND ASSOCIATED METHODS
# defines /mood and /mood/<id> endpoints
mood = '/mood'
mood_id = '/mood/<mood_id>'


# helper function manually calculates user percentile so I don't have to import numpy
def get_user_percentile(all_streaks, user_streak):
    min_value = min(all_streaks)
    max_value = max(all_streaks)
    return (100 * float(user_streak - min_value)/(max_value-min_value))


# REQUIRED ENDPOINT
@ mood_api.route(mood, methods=['GET'])
@ token_required
def get_all_moods(this_user):
    # returns all moods for this_user
    moods = Mood.query.filter_by(user_id=this_user.id).all()
    if not moods:
        return make_response(jsonify({"message": "You have no posted moods."}))

    # queries db to check this user's longest streak percentile. if > 50.0, returns percentile in response body
    users = User.query.all()
    user_percentile = get_user_percentile(
        [user.longest_streak for user in users], this_user.longest_streak)

    if user_percentile >= 50.0:
        return make_response(jsonify({"moods": moods, "streak_percentile": user_percentile}), 200)

    return make_response(jsonify({"moods": moods}), 200)


# REQUIRED ENDPOINT
@ mood_api.route(mood, methods=['POST'])
@ token_required
def create_mood(this_user):
    data = request.get_json()

    # check whether this mood is part of a larger streak
    current_time = datetime.datetime.utcnow()
    one_day_ago = current_time - datetime.timedelta(days=1)
    two_days_ago = current_time - datetime.timedelta(days=2)

    # query db for mood posts from yesterday. if found, add to streak, else streak = 1
    yesterday = Mood.query.filter(Mood.date_posted < one_day_ago).filter(
        Mood.date_posted > two_days_ago).first()

    if yesterday:
        streak = yesterday.streak + 1
    else:
        streak = 1

    # creates new mood object with streak
    new_mood = Mood(value=data['value'], streak=streak,
                    user_id=this_user.id)

    # check user's longest streak, update if necessary
    user = User.query.filter_by(id=this_user.id).first()
    if user.longest_streak < streak:
        user.longest_streak = streak

    # commit changes to db, return 201
    db.session.add(new_mood)
    db.session.commit()

    # check user's streak percentile, return if >= 50.0
    # queries db to check this user's longest streak percentile. if > 50.0, returns percentile in response body
    users = User.query.all()
    user_percentile = get_user_percentile(
        [user.longest_streak for user in users], this_user.longest_streak)

    if user_percentile >= 50.0:
        return make_response(jsonify({"moods": mood, "streak_percentile": user_percentile}), 201)

    return make_response(jsonify({"mood": new_mood}), 201)


# DEBUGGING/EXTENDING ENDPOINT
@ mood_api.route(mood_id, methods=['GET'])
@ token_required
def get_one_mood(this_user, mood_id):
    # returns mood of mood_id for this_user
    # queries db for this user's mood post with url mood_id, if none found returns 404, else 200
    mood = Mood.query.filter_by(
        user_id=this_user.id, mood_id=mood_id).first()

    if not mood:
        return make_response(jsonify({"message": "Mood not found."}), 404)

    return make_response(jsonify({"mood": mood}), 200)


# DEBUGGING/EXTENDING ENDPOINT
@ mood_api.route(mood_id, methods=['DELETE'])
@ token_required
def delete_mood(this_user, mood_id):
    # delete's posted mood by mood_id from url mood/<mood_id>
    mood = Mood.query.filter_by(user_id=this_user.id, mood_id=mood_id).first()

    if not mood:
        return make_response(jsonify({"message": "Mood not found."}), 404)

    db.session.delete(mood)
    db.session.commit()

    return make_response(jsonify({"message": "Mood deleted successfully."}), 200)
