"""
INSTRUCTIONS:

While app is running, in any dir..

    pyhton3 -m unittest -v <path/unittests.py> 

...to run all tests. To run individual cases...

    python3 -m unittest -v <path/unittests.py>.<TestClass>

...or even individual methods...

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


class LoginTestCase(unittest.TestCase):
    def setUp(self):
        # creates admin user in db with username, password: 'admin', 'admin' if one doesn't exist
        self.added_admin = False
        admin = User.query.filter_by(username='admin', password=generate_password_hash(
            'admin', method='sha256')).first()
        if not admin:
            hashed = generate_password_hash('admin', method='sha256')
            self.admin_user = admin_user = User(public_id=str(
                uuid.uuid1()), username='admin', password=hashed, longest_streak=0, admin=True)
            db.session.add(admin_user)
            db.session.commit()
            self.added_admin = True
        else:
            self.admin_user = admin
        self.db = db
        self.admin_user = admin_user

    def tearDown(self):
        # removes admin user from setUp if the unittest added it
        if self.added_admin:
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
        self.added_admin = False
        admin = User.query.filter_by(username='admin', password=generate_password_hash(
            'admin', method='sha256')).first()
        if not admin:
            hashed = generate_password_hash('admin', method='sha256')
            self.admin_user = admin_user = User(public_id=str(
                uuid.uuid1()), username='admin', password=hashed, longest_streak=0, admin=True)
            db.session.add(admin_user)
            self.added_admin = True
        else:
            self.admin_user = admin
        self.admin_user = admin_user

        # creates user 'GetMoodsTestCase', non-admin
        test_hashed = generate_password_hash('password', method='sha256')
        test_user = User(public_id=str(uuid.uuid1(
        )), username='GetMoodsTestCase', password=test_hashed, longest_streak=1, admin=False)
        db.session.add(test_user)
        db.session.commit()
        self.db = db
        self.test_user = test_user

    def tearDown(self):
        # removes added users
        if self.added_admin:
            self.db.session.delete(self.admin_user)

        self.db.session.delete(self.test_user)
        self.db.session.commit()

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
