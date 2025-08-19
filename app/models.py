from . import db

class Placeholder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
