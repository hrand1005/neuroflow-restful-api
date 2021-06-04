from api.model.mood import Mood
from api.model.user import User
from config import db
from werkzeug.security import generate_password_hash
import os
import uuid

if __name__ == '__main__':
    if os.path.exists('db.sqlite'):
        os.remove('db.sqlite')
    db.create_all()
    # check if admin user exists in db, for debugging
    # creates admin user in db with username, password: 'admin', 'admin' for testing purposes
    # admin = User.query.filter_by(username='admin').first()
    # if not admin:
    #    hashed = generate_password_hash('admin', method='sha256')
    #    admin_user = User(public_id=str(
    #        uuid.uuid1()), username='admin', password=hashed, longest_streak=0, admin=True)
    #    db.session.add(admin_user)
    #    db.session.commit()
