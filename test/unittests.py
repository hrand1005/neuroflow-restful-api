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
from werkzeug.security import generate_password_hash
import json
import requests
import unittest
import uuid


BASE = 'http://127.0.0.1:5000/'


# COMMONLY USED HELPER METHODS
def add_user_to_db(username, password, is_admin):
    # tries to add User to db
    exists = False
    user = User.query.filter_by(username=username).first()
    if not user:
        hashed = generate_password_hash(password, method='sha256')
        user = User(public_id=str(uuid.uuid1()), username=username,
                    password=hashed, longest_streak=0, admin=is_admin)
        exists = True

    # returns bool indicating whether user exists, and user object
    return exists, user


def add_mood_to_db(user):
    # helper function adds a mood to the db for the given user without invoking POST on /mood endpoint
    # for the given user. For simplicity, creates mood with value '<username> mood here.'
    new_mood = Mood(value=f'{user.username} mood here.',
                    streak=user.streak, user_id=user.id)

    # check user's longest streak, update if necessary
    user = User.query.filter_by(id=user.id).first()
    if user.longest_streak < user.streak:
        user.longest_streak = user.streak

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

# TODO: Check that users can't get each other's mood postings...


# TODO: PostMoodsTestCase, including percentile and streak checking

if __name__ == '__main__':
    unittest.main()
