from flask import Blueprint, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
from . import db
from .models import User, PasswordEntry

bp = Blueprint("routes", __name__)

#  register route
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
    
# login route
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
    
# logout route 
@bp.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out"}), 200

# add password route to create and store new password
@bp.route("/addpassword", methods=["POST"])
@login_required
def add_password():
    try:
        # checking if we got the JSON data
        data = request.get_json()
        if not data:
            return jsonify({
                "error": "No json data provided",
                "message": "Please send data as JSON"
            }), 400
        
        # Extract fields from the JSON
        service_name = data.get('service_name')
        login_name = data.get('login_name')
        url = data.get('url')
        notes = data.get('notes')
        password = data.get('password')

        # check if any required fileds is missing or empty
        if not service_name or not login_name or not password:
            return jsonify({
                "error": "Missing required fields",
                "message": "Service name, login name and password are required",
                "received": {
                    "service_name": bool(service_name),
                    "login_name": bool(login_name),
                    "password": bool(password)
                }
            }),400
        
        # create new password object
        new_password_entry = PasswordEntry(
            user_id = current_user.id,
            service_name = service_name,
            login_name = login_name,
            url = url,
            notes = notes
        )

        # encrypt password
        new_password_entry.set_password(password)

        # Adding the user to the database session
        db.session.add(new_password_entry)

        # Saving it to the database
        db.session.commit()

        # Return success response
        return jsonify({
            "message": "Password entry created successfully!",
            "passwordentry": {
                "id": new_password_entry.id,
                "service_name": new_password_entry.service_name,
                "login_name": new_password_entry.login_name,
                "url": new_password_entry.url,
                "notes": new_password_entry.notes,
                "created_at": new_password_entry.created_at.isoformat(),
                "updated_at": new_password_entry.updated_at.isoformat()
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
    

# Read (get all passwords for current user)
@bp.route('/passwords', methods=['GET'])
@login_required
def get_passwords():
    try:
        # storing result in a variable like password_entries
        password_entries = PasswordEntry.query.filter_by(
            user_id=current_user.id
        ).all()

        # convert each entry to a dictionary
        entries_list = []
        for entry in password_entries:
            entry_dict = {
               "id": entry.id,
                "service_name": entry.service_name,
                "login_name": entry.login_name,
                "url": entry.url,
                "notes": entry.notes,
                "created_at": entry.created_at.isoformat(),
                "updated_at": entry.updated_at.isoformat() 
            }
            entries_list.append(entry_dict)

        return jsonify({
            "message": "Password entries retrieved successfully",
            "count": len(entries_list),
            "passwordentries": entries_list
        }), 200

    except Exception as e:    
        print(f"Get passwords error: {str(e)}")
        return jsonify({
            "error": "Failed to retrieve passwords",
            "message": "Something went wrong. Please try again."
        }), 500
    
# Update (edit a password entry)
@bp.route('/passwords/<int:entry_id>', methods=['PUT'])
@login_required
def update_password(entry_id): 
    try:
        # finding the passwword entry
        password_entry = PasswordEntry.query.filter_by(
            id = entry_id,
            user_id = current_user.id
        ).first()

        # checking if entry exist and it belongs to the current user
        if not password_entry:
            return jsonify({
                "error": "Password entry not found",
                "message": "No password entry found with that ID, or you don't have permission to access it"
            }), 404
        
        # get JSON data
        data = request.get_json()
        if not data:
            return jsonify({
                "error": "No JSON data provided",
                "message": "Please send data as JSON"
            }), 400

        # Update fields (only if provided)
        # This allows partial updates - user can update just service name, or just password, etc.
        updated_fields = []
        
        if 'service_name' in data and data['service_name']:
            password_entry.service_name = data['service_name']
            updated_fields.append('service_name')
        
        if 'login_name' in data and data['login_name']:
            password_entry.login_name = data['login_name']
            updated_fields.append('login_name')
        
        if 'url' in data:  # URL can be empty string, so we check for presence, not truthiness
            password_entry.url = data['url']
            updated_fields.append('url')
        
        if 'notes' in data:  # Notes can be empty string too
            password_entry.notes = data['notes']
            updated_fields.append('notes')
        
        if 'password' in data and data['password']:
            # Re-encrypt the new password
            password_entry.set_password(data['password'])
            updated_fields.append('password')
        
        # Step 5: Update the timestamp
        password_entry.updated_at = datetime.utcnow()
        
        # Step 6: Save changes
        db.session.commit()

        # return success response
        return jsonify({
            "message": "Password entry updated successfully!",
            "updated_fields": updated_fields,  # Tell user what was changed
            "passwordentry": {
                "id": password_entry.id,
                "service_name": password_entry.service_name,
                "login_name": password_entry.login_name,
                "url": password_entry.url,
                "notes": password_entry.notes,
                "created_at": password_entry.created_at.isoformat(),
                "updated_at": password_entry.updated_at.isoformat()
                # Notice: We don't return the actual password for security
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        print(f"Update error: {str(e)}")
        return jsonify({
            "error": "Update failed",
            "message": "Something went wrong during update. Please try again."
        }), 500

# Delete (remove a password entry)
@bp.route('/passwords/<int:entry_id>', methods=['DELETE'])
@login_required
def delete_password(entry_id):
    try:
        # finding the passwword entry
        password_entry = PasswordEntry.query.filter_by(
            id = entry_id,
            user_id = current_user.id
        ).first()

        # checking if entry exist and it belongs to the current user
        if not password_entry:
            return jsonify({
                "error": "Password entry not found",
                "message": "No password entry found with that ID, or you don't have permission to access it"
            }), 404    
        
        # Store entry details for response (before deletion)
        deleted_entry = {
            "id": password_entry.id,
            "service_name": password_entry.service_name,
            "login_name": password_entry.login_name,
            "url": password_entry.url,
            "notes": password_entry.notes,
            "created_at": password_entry.created_at.isoformat(),
            "updated_at": password_entry.updated_at.isoformat()
        }

        # Delete the entry
        db.session.delete(password_entry)
        db.session.commit()

        # Return success response
        return jsonify({
            "message": "Password entry deleted successfully!",
            "deleted_entry": deleted_entry
        }), 200
    
    except Exception as e:
        db.session.rollback()
        print(f"Delete error: {str(e)}")
        return jsonify({
            "error": "Delete failed",
            "message": "Something went wrong during the delete. Please try again."
        }), 500