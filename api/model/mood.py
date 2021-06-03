from dataclasses import dataclass
from config import db
import datetime


# defines Mood schema
@dataclass
class Mood(db.Model):
    mood_id: int
    value: str
    streak: int
    user_id: int

    mood_id = db.Column(db.Integer, primary_key=True)
    date_posted = db.Column(
        db.DateTime, default=datetime.datetime.utcnow())
    streak = db.Column(db.Integer)
    value = db.Column(db.String(50))
    user_id = db.Column(db.Integer)
