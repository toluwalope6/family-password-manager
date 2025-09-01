import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
# from .import models

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    # Load environment variables
    load_dotenv()

    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-key")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///app.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)


    # configure Flask-Login settings
    login_manager.login_view = 'routes.login'
    login_manager.login_message = 'Please log in to access this page'
    login_manager.login_message_category = 'info'

    # Register blueprints (routes)
    from .routes import bp as routes_bp
    app.register_blueprint(routes_bp)

   # Add debug prints
    print("About to import models...")
    from .models import User, PasswordEntry, AccessLog
    print("Models imported successfully!")
    print("User model:", User)
    print("PasswordEntry model:", PasswordEntry) 
    print("AccessLog model:", AccessLog)

    # Create tables if not exist
    with app.app_context():
        print("Creating tables...")
        print("Database URI:", app.config["SQLALCHEMY_DATABASE_URI"])
        print("Database file path:", db.engine.url.database)
        
        db.create_all()
        print("Database tables created/verified!")

    # Check what was created
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        print("Actual tables in database:", tables)

    return app

@login_manager.user_loader
def load_user(user_id):
    """
    This function tells Flask-Login how to find a user
    
    Flask-Login stores the user ID in the session (browser cookie)
    When it needs the actual user object, it calls this function
    
    """
    # Import here to avoid circular imports
    from .models import User
    
    # Find and return the user by ID
    # get() returns the user if found, None if not found
    return User.query.get(int(user_id))


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)