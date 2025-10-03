from flask_sqlalchemy import SQLAlchemy 
from flask_login import UserMixin
from datetime import datetime
from cryptography.fernet import Fernet
from flask import current_app
import base64
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

    owned_passwords = db.relationship('PasswordEntry', backref='owner', lazy = True, foreign_keys = 'PasswordEntry.user_id')

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
    
    def get_shared_passwords(self): # getting all the password shared with the user NOP OWNED BY THEM
        return PasswordEntry.query.join(shared_passwords).filter(
            shared_passwords.c.user_id == self.id,
            PasswordEntry.user_id != self.id
        ).all()
    
# Association table for sharing passwords
shared_passwords = db.Table('shared_passwords',
    db.Column('password_id', db.Integer, db.ForeignKey('passwordentries.id'), primary_key= True),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'),primary_key = True),
    db.Column('shared_at', db.DateTime, default=datetime.utcnow),
    db.Column('can_edit', db.Boolean, default = False) #This is for future updates
)

#  model for storing password 
class PasswordEntry(db.Model):

    __tablename__ = 'passwordentries'

    # link to users
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable = False)

    # account details
    id = db.Column(db.Integer, primary_key = True)
    service_name = db.Column(db.String(150), unique = False, nullable = False)
    login_name = db.Column(db.String(150), unique = False, nullable = False) # login name to service example the email to the netflix account or the username 
    url = db.Column(db.String(2048), unique = False, nullable = True)
    created_at = db.Column(db.DateTime, default = datetime.utcnow)
    updated_at = db.Column(db.DateTime, default = datetime.utcnow)   
    notes = db.Column(db.String(2048), unique = False, nullable = True)
    encrypted_password = db.Column(db.Text, nullable = False)


    # for sharing passwords
    shared_with = db.relationship('User',
        secondary = shared_passwords, 
        backref = db.backref('shared_passwords', lazy = 'dynamic'),
        lazy = 'dynamic'                             
    )
    def _get_key(self):
        # Generate encryption key from Flask's SECRET_KEY
        # Not the safest option but will suffice for now

        secret_key = current_app.config['SECRET_KEY']
        # convert to proper Fernet key format
        key = base64.urlsafe_b64encode(secret_key.encode('utf-8').ljust(32)[:32])
        return key

    def set_password(self, plain_password):
        # encrypyt plain password and store it in the database
        key = self._get_key()
        cipher = Fernet(key)

        # encrypt password 
        encrypted_password = cipher.encrypt(plain_password.encode('utf-8'))
        self.encrypted_password = encrypted_password.decode('utf-8')

    def get_password(self):
        # decrypt the encrypted password
        key = self._get_key()
        cipher = Fernet(key)

        # decrypt password
        decrypted_password = cipher.decrypt(self.encrypted_password.encode('utf-8'))
        return decrypted_password.decode('utf-8')
    
    def is_owner(self,user): # this is to check if the user owns this password
        return self.user_id == user.id
    
    def is_accessible_by(self, user): # This is tocheck if the userr has access to the password
        if self.is_owner(user):
            return True
        return self.shared_with.filter_by(id = user.id).first() is not None
    
    def is_shared_with(self,user): # this checks if a password is shared with a specific user
        return self.shared_with.filter_by(id = user.id).first() is not None

    def log_password_access(user, password_entry, action="viewed"):
        log = AccessLog(
            user_id=user.id,
            password_id=password_entry.id,
            action=action
        )
        db.session.add(log)
        db.session.commit()

#  model for access logs
class AccessLog(db.Model):

    __tablename__ = 'accesslogs'

    # link to users
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable = False)

    # link to passwordentries
    password_id = db.Column(db.Integer, db.ForeignKey('passwordentries.id'), nullable = False)

    # log details
    id = db.Column(db.Integer, primary_key = True)
    accessed_at = db.Column(db.DateTime, default = datetime.utcnow)
    action = db.Column(db.String(50), default = "viewed")

    user = db.relationship('User', backref = 'AccesslLogs')
    password_entry = db.relationship('PasswordEntry',backref = 'Accesslogs')
    
    