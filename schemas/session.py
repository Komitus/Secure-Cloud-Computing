from sqlalchemy.dialects.sqlite import JSON
from schemas import db


class Session(db.Model):
    session_token = db.Column(db.String, primary_key=True)
    payload = db.Column(JSON, nullable=False)


class Keys(db.Model):
    session_token = db.Column(db.String, primary_key=True)
    key_idx = db.Column(db.Integer, primary_key=True)
    key0_val = db.Column(db.String)
    key1_val = db.Column(db.String)
