from app import db
import os

if __name__ == '__main__':
    if os.path.exists('db.sqlite'):
        os.remove('db.sqlite')
    db.create_all()
