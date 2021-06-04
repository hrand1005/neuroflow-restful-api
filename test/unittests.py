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
        # creates admin user in db with username, password: 'admin', 'admin'
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            hashed = generate_password_hash('admin', method='sha256')
            admin_user = User(public_id=str(
                uuid.uuid1()), username='admin', password=hashed, longest_streak=0, admin=True)
            db.session.add(admin_user)
            db.session.commit()
        self.db = db

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


if __name__ == '__main__':
    unittest.main()
