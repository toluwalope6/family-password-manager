from flask import Blueprint, request, jsonify
from flask_login import login_user, logout_user, login_required
from . import db
from .models import User

bp = Blueprint("routes", __name__)

@bp.route("/register", methods=["POST"])
def register():
    try: 
        data = request.get_json()
        # checking if we got the JSON data
        if not data:
            return jsonify({
                "error": "No json data provided",
                "message": "Please send data as JSON"
            }), 400

        # Extract required fields from the JSON
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        phone_number = data.get('phone_number')

        # Check if any required field is missing or empty
        if not username or not email or not password:
            return jsonify({
                "error": "Missing required fields",
                "message": "Username, email, and password are required",
                "received": {
                    "username": bool(username),
                    "email": bool(email),
                    "password": bool(password)
                }
            }), 400
        
        # Validating data format
        if len(username) < 3:
            return jsonify({
                "error": "Username too short",
                "message": "Username must be at least 3 characters long"
            }), 400
        
        if len(password) < 6:
            return jsonify({
                "error": "Password too short",
                "message": "Password must be at least 6 characters long"
            }), 400
        
        if '@' not in email or '.' not in email:
            return jsonify({
                "error": "Invalid email format",
                "message": "Please provide a valid email address"
            }), 400
        
        # checking both email and username for uniqueness
        existing_user_by_username = User.query.filter_by(username=username).first()
        existing_user_by_email = User.query.filter_by(email=email).first()

        if existing_user_by_username:
            return jsonify({
                "error": "Username already exists",
                "message": f"User with username '{username}' already exists"
            }), 409
        
        if existing_user_by_email:
            return jsonify({
                "error": "Email already exists",
                "message": f"User with username '{email}' already exists"
            }), 409

        # If phone nuber is given check uniqueness
        if phone_number:
            existing_user_by_phone = User.query.filter_by(phone_number=phone_number).first()
            if existing_user_by_phone:
                return jsonify({
                    "error": "Phone number already exists",
                    "message": f"User with phone number '{phone_number}' already exists"
                }), 409
            
        # Create new user object
        new_user = User(
            username = username,
            email = email,
            phone_number = phone_number,
            role = "guest" 
        )

        # Hash and set the password
        # set_password method from "models.py"
        new_user.set_password(password)

        # Adding the user to the database session
        db.session.add(new_user)

        # Saving it to the database
        db.session.commit()

        # Return success response
        return jsonify({
            "message": "User registered succesfully",
            "user": {
                "id": new_user.id,
                "username": new_user.username,
                "email": new_user.email,
                "phone_number": new_user.phone_number,
                "role": new_user.role,
                "created_at": new_user.created_at.isoformat()
            }
        }), 201

    except Exception as e:
        # rolling back db transaction if anything goes wrong
        db.session.rollback()
        print(f"Registration error: {str(e)}")

        # Generic error message
        return jsonify({
            "error": "Registration failed",
            "message": "Something went wrong during registration. Please try again."
        }), 500
    

@bp.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        # checking if we got the JSON data
        if not data:
            return jsonify({
                "error": "No json data provided",
                "message": "Please send data as JSON"
            }), 400

        # Extract required fields from the JSON
        email = data.get('email')
        password = data.get('password')

        # Check if any required field is missing or empty
        if not email or not password:
            return jsonify({
                "error": "Missing required fields",
                "message": "Login with email and password",
                "received": {
                    "email": bool(email),
                    "password": bool(password)
                }
            }), 400
        
        find_user_by_email = User.query.filter_by(email=email).first()

        if not find_user_by_email:
            return jsonify({
                "error": "User not found"
                "message" f"No account found with this email address '{email}'"
            }), 401
        
        if not find_user_by_email.check_password(password):
            return jsonify({
                "error": "Invalid password"
                "message" f"Incorrect password"
            }), 401
        
        # If we get here, email and password are correct!
        # Log the user in using Flask-Login
        login_user(find_user_by_email)

        return jsonify({
            "message": "Logged in successfully",
            "user": {
                "id": find_user_by_email.id,
                "username": find_user_by_email.username,
                "email": find_user_by_email.email,
                "role": find_user_by_email.role
            }
        }), 200

    
    except Exception as e:
    # Log error and return generic message
        print(f"Login error: {str(e)}")
        return jsonify({
            "error": "Login failed",
            "message": "Something went wrong during login. Please try again."
        }), 500
    
@bp.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out"}), 200
