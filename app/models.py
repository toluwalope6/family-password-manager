from flask_sqlalchemy import SQLAlchemy 
from flask_login import UserMixin
from datetime import datetime
import bcrypt

from . import db

class User(db.Model, UserMixin):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(150), unique = True, nullable = False)
    phone_number = db.Column(db.String(15), unique = True, nullable = True)
    email = db.Column(db.String(150), unique = True, nullable = False)
    password_hash = db.Column(db.String(200),nullable = False)
    created_at = db.Column(db.DateTime, default = datetime.utcnow)
    role = db.Column(db.String(50), default="guest")  # default role

    def set_password(self, password):
        # convert password to bytes(convert password string to bytes)
        password_bytes = password.encode('utf-8')

        #Generate salt and hash the password
        #The number 12 is the rounds - higher rounds = more secure but slower
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password_bytes, salt)

        # Store as string in database (decodes bytes back to String)
        self.password_hash = hashed.decode('utf-8')

        print(f"Original password: {password}")
        print(f"Hashed password: {self.password_hash}")


    def check_password(self, password):
        """
        Check if the provided password matches the stored hash
        
        Returns True if password is correct, False if not
        """

        # convert password to bytes
        password_bytes = password.encode('utf-8')
        # conert stored hash back to bytes
        stored_hash = self.password_hash.encode('utf-8')
        # use bcrypt to check if password matches
        is_correct = bcrypt.checkpw(password_bytes, stored_hash)

        print(f"Checking password: {password}")
        print(f"Password is correct: {is_correct}")

        return is_correct

