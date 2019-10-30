from sqlalchemy.dialects.sqlite import JSON

from schemas import db

class Session(db.Model):
    session_token = db.Column(db.String, primary_key=True)
    payload = db.Column(JSON, nullable=False)
