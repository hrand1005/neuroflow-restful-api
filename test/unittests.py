"""
INSTRUCTIONS:

While app is running, to run all tests...

    pyhton3 -m unittest -v <path/unittests.py>

To run individual cases...

    python3 -m unittest -v <path/unittests.py>.<TestClass>

To run individual methods...

    python3 -m unittest -v <path/unittests.py>.<TestClass>.<test_method>

"""
from api.model.mood import Mood
from api.model.user import User
from config import db
from flask import jsonify
from werkzeug.security import generate_password_hash
import json
import requests
import unittest
import uuid


BASE = 'http://127.0.0.1:5000/'


# COMMONLY USED HELPER METHODS
def add_user_to_db(username, password, is_admin):
    # tries to add User to db
    exists = True
    user = User.query.filter_by(username=username).first()
    if not user:
        hashed = generate_password_hash(password, method='sha256')
        user = User(public_id=str(uuid.uuid1()), username=username,
                    password=hashed, longest_streak=0, admin=is_admin)
        exists = False

    # returns bool indicating whether user exists, and user object
    return exists, user


def add_mood_to_db(user):
    # helper function adds a mood to the db for the given user without invoking POST on /mood endpoint
    # for the given user. For simplicity, creates mood with value '<username> mood here.'
    new_mood = Mood(value=f'{user.username} mood here.',
                    streak=1, user_id=user.id)

    if user.longest_streak < new_mood.streak:
        user.longest_streak = new_mood.streak

    db.session.add(new_mood)
    db.session.commit()

    return new_mood


class LoginTestCase(unittest.TestCase):
    def setUp(self):
        # creates admin user in db with username, password: 'admin', 'admin' if one doesn't exist
        self.admin_exists, self.admin_user = add_user_to_db(
            'admin', 'admin', True)

        if not self.admin_exists:
            db.session.add(self.admin_user)
            db.session.commit()

    def tearDown(self):
        # removes admin user from setUp if the unittest added it
        if not self.admin_exists:
            db.session.delete(self.admin_user)
            db.session.commit()

    def test_login_no_credentials(self):
        response = requests.get(BASE + 'login')
        self.assertEqual(response.status_code, 401)
        with self.assertRaises(json.decoder.JSONDecodeError):
            response.json()

    def test_login_false_credentials(self):
        response = requests.get(BASE + 'login', auth=('username', 'password'))
        self.assertEqual(response.status_code, 401)
        with self.assertRaises(json.decoder.JSONDecodeError):
            response.json()

    def test_login_valid_credentials(self):
        response = requests.get(BASE + 'login', auth=('admin', 'admin'))
        self.assertEqual(response.status_code, 200)
        self.assertTrue("token" in response.json())


class GetMoodsTestCase(unittest.TestCase):
    def setUp(self):
        # creates admin user in db with username, password: 'admin', 'admin' if one doesn't exist
        self.admin_exists, self.admin_user = add_user_to_db(
            'admin', 'admin', True)

        if not self.admin_exists:
            db.session.add(self.admin_user)
            db.session.commit()

        # creates user 'GetMoodsTestCase', non-admin
        self.test_user_exists, self.test_user = add_user_to_db(
            'GetMoodsTestCase', 'password', False)

        if not self.test_user_exists:
            db.session.add(self.test_user)
            db.session.commit()

    def tearDown(self):
        # removes added users
        if not self.admin_exists:
            db.session.delete(self.admin_user)

        if not self.test_user_exists:
            db.session.delete(self.test_user)

        db.session.commit()

    def test_get_mood_no_token(self):
        # tries to retrieve data from mood endpoints with no auth token
        response = requests.get(BASE + 'mood')
        self.assertEqual(response.status_code, 401)
        self.assertTrue(response.json()["message"]
                        == "Authentication token required.")
        self.assertFalse("moods" in response.json())

    def test_get_mood_invalid_token(self):
        # tries to retrieve data from mood endpoints with invalid auth token
        response = requests.get(
            BASE + 'mood', headers={"X-Access-Token": "Dummy token"})
        self.assertEqual(response.status_code, 401)
        self.assertTrue(response.json()["message"] == "Invalid token.")
        self.assertFalse("moods" in response.json())

    def test_get_mood_valid_user(self):
        # adds mood directly to db, then tries to retrieve data from mood endpoints
        admin_mood = add_mood_to_db(self.admin_user)

        # login with self.admin_user, get token
        login_response = requests.get(
            BASE + 'login', auth=('admin', 'admin'))
        token = json.loads(login_response.text)["token"]
        # check that admin_mood can be retrieved by the admin user
        mood_response = requests.get(
            BASE + 'mood', headers={"X-Access-Token": token})

        # check expected fields
        self.assertEqual(json.loads(mood_response.text)[
            "moods"][0]["mood_id"], admin_mood.mood_id)
        self.assertEqual(json.loads(mood_response.text)[
            "moods"][0]["streak"], admin_mood.streak)
        self.assertEqual(json.loads(mood_response.text)[
            "moods"][0]["user_id"], self.admin_user.id)
        self.assertEqual(json.loads(mood_response.text)[
            "moods"][0]["value"], admin_mood.value)

        # remove added admin_mood
        db.session.delete(admin_mood)
        db.session.commit()

    """
    def test_get_mood_invalid_user(self):
        # tries to retrieve data from mood endpoints with the wrong user's credentials
        # first, let's add a mood posting from the admin user
        admin_mood = add_mood_to_db(self.admin_user)

        # login with self.test_user, get token
        login_response = requests.get(
            BASE + 'login', auth=(self.test_user.username, self.test_user.password))
        token = login_response.json()["token"]

        # check if admin_mood can be retrieved with the wrong user (test_user)
        mood_response = requests.get(
            BASE + 'mood', headers={"X-Access-Token": token})
        self.assertEqual()
    """
    #
# TODO: Check that users can't get each other's mood postings...


# TODO: PostMoodsTestCase, including percentile and streak checking

if __name__ == '__main__':
    unittest.main()
