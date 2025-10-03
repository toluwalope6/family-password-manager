from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from . import db
from .models import User, PasswordEntry, AccessLog

bp = Blueprint("routes", __name__)

# This is to add logs when a password is accessed
def log_password_access(user, password_entry, action = "accessed"):
        
        access_log = AccessLog(
            user_id = user.id,
            password_id = password_entry.id,
            action = action
        )
        db.session.add(access_log)
        db.session.commit()

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
    
# Sharing password route
@bp.route('/passwords/<int:password_id>/share', methods=['POST'])
@login_required
def share_password(password_id):
    try:
        # finding the password entry
        password_entry = PasswordEntry.query.filter_by(
            id = password_id,
            user_id = current_user.id
        ).first()

        if not password_entry:
            return jsonify({
                "error": "Password entry not found",
                "message": "No password entry found with that ID, or you don't have permission to share"
            }), 404
        
        data = request.get_json()
        if not data:
            return jsonify({
                "error": "No JSON data provided",
                "message": "Please send data as JSON with 'share_with' field"
            }), 400
        
        if 'share_with' not in data or not data['share_with']:
            return jsonify({
                "error": "Missing required field",
                "message": "Please provide 'share_with' email address"
            }), 400
        
        share_with_email = data['share_with'].strip().lower()

        # finding target user
        target_user = User.query.filter_by(email=share_with_email).first()
        if not target_user:
            return jsonify({
                "error": "User not found",
                "message": f"No user found with email: {share_with_email}"
            }), 404
        
        # check if the user is trying to share password with themselves
        if target_user.id == current_user.id:
            return jsonify({
                "error": "Invalid sharing target",
                "message": "You cannot share a password with yourself"
            }), 400
        
        # check if password is already been shared
        if password_entry.is_shared_with(target_user):
            return jsonify({
                "error": "Already shared",
                "message": f"This password is already shared with {target_user.email}"
            }), 409

        #  Add to sharing relationship
        password_entry.shared_with.append(target_user)
        db.session.commit()

        # Return success response
        return jsonify({
            "message": "Password shared successfully!",
            "shared_password": {
                "id": password_entry.id,
                "service_name": password_entry.service_name,
                "login_name": password_entry.login_name,
                "url": password_entry.url,
                "notes": password_entry.notes
            },
            "shared_with": {
                "email": target_user.email,
                "username": target_user.username
            },
            "shared_at": datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        db.session.rollback()
        print(f"Share password error: {str(e)}")
        return jsonify({
            "error": "Sharing failed",
            "message": "Something went wrong while sharing the password. Please try again."
        }), 500
    
# getting all shared passwords with current user
@bp.route('/passwords/shared', methods=['GET'])
@login_required
def get_shared_passwords():
    try:
        # Get passwords shared with current user (not owned by them)
        shared_passwords = current_user.get_shared_passwords()

        # Convert to JSON format
        passwords_list = []
        for password in shared_passwords:
            passwords_list.append({
                "id": password.id,
                "service_name": password.service_name,
                "login_name": password.login_name,
                "url": password.url,
                "notes": password.notes,
                "created_at": password.created_at.isoformat(),
                "updated_at": password.updated_at.isoformat(),
                "owner": {
                    "username": password.owner.username,
                    "email": password.owner.email
                },
                "access_type": "shared"  # Indicates this is shared, not owned
            })

        return jsonify({
            "message": f"Found {len(passwords_list)} shared passwords",
            "shared_passwords": passwords_list,
            "total_count": len(passwords_list)
        }), 200

    except Exception as e:
        print(f"Get shared passwords error: {str(e)}")
        return jsonify({
            "error": "Failed to retrieve shared passwords",
            "message": "Something went wrong while getting shared passwords. Please try again."
        }), 500
    
# route to view password
@bp.route('/passwords/<int:entry_id>/view', methods=['GET'])
@login_required
def view_password(entry_id):
    try:
        #getting password entry
        password_entry = PasswordEntry.query.get(entry_id)

        if not password_entry:
            return jsonify({
                "error": "Password entry not found",
                "message": "No password entry found with that ID"
            }), 404
        
        # decrypting the actual password
        actual_password = password_entry.get_password()

        # logging here
        log_password_access(current_user, password_entry)

        # Determine acces type for response
        is_owner = password_entry.is_owner(current_user)
        access_type = "owner" if is_owner else "shared"

        return jsonify({
            "message": "Password retrieved successfully",
            "password_entry":{
                "id": password_entry.id,
                "service_name": password_entry.service_name,
                "login_name": password_entry.login_name,
                "password": actual_password,  # The decrypted password
                "url": password_entry.url,
                "notes": password_entry.notes,
                "access_type": access_type,
                "owner": {
                    "username": password_entry.owner.username,
                    "email": password_entry.owner.email
                } if not is_owner else None
            }
        }), 200

    except Exception as e:
        print(f"View password error: {str(e)}")
        return jsonify({
            "error": "Failed to retrieve password",
            "message": "Something went wrong while retrieving the password. Please try again."
        }), 500
    
#  route to view access logs
@bp.route('/logs', methods=['GET'])
@login_required
def get_access_logs():
    try:
        # showing current users logs
        logs = AccessLog.query.filter_by(user_id=current_user.id).all()

        # conert to JSON
        logs_list = []
        for log in logs:
            logs_list.append({
                "id": log.id,
                "password_service": log.password_entry.service_name,
                "accessed_at": log.accessed_at.isoformat()
            })

            return jsonify({
                "message": f"Found {len(logs_list)} access logs",
                "logs": logs_list
            }), 200
    except Exception as e:
        print(f"Get logs error: {str(e)}")
        return jsonify({
            "error": "Failed to retrieve logs",
            "message": "Something went wrong while getting logs. Please try again."
        }), 500

# ============ FRONTEND ROUTES ============    

# -------------------------
# UI ROUTES (Day 6 Frontend)
# -------------------------

# from flask import render_template, redirect, url_for, flash, request
# from flask_login import login_user, logout_user, login_required, current_user
# from .models import User, PasswordEntry, AccessLog
# from . import db


# UI: Register
@bp.route("/register-ui", methods=["GET", "POST"])
def register_ui():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already taken.", "danger")
            return redirect(url_for("routes.register_ui"))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("routes.login_ui"))

    return render_template("register.html")


# UI: Login
@bp.route("/login-ui", methods=["GET", "POST"])
def login_ui():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("routes.dashboard"))
        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html")


# UI: Logout
@bp.route("/logout-ui")
@login_required
def logout_ui():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("routes.login_ui"))


# UI: Dashboard
@bp.route("/dashboard")
@login_required
def dashboard():
    passwords = PasswordEntry.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", passwords=passwords)


# UI: Add Password
@bp.route("/add-password-ui", methods=["GET", "POST"])
@login_required
def add_password_ui():
    if request.method == "POST":
        service_name = request.form.get("service_name")
        login_name = request.form.get("login_name")
        url_value = request.form.get("url")
        notes = request.form.get("notes")
        plain_password = request.form.get("password")

        entry = PasswordEntry(
            user_id=current_user.id,
            service_name=service_name,
            login_name=login_name,
            url=url_value,
            notes=notes
        )
        entry.set_password(plain_password)
        db.session.add(entry)
        db.session.commit()

        flash("Password saved successfully!", "success")
        return redirect(url_for("routes.dashboard"))

    return render_template("add_password.html")


# UI: Share Password
@bp.route("/share-password-ui", methods=["GET", "POST"])
@login_required
def share_password_ui():
    if request.method == "POST":
        password_id = request.form.get("password_id")
        target_username = request.form.get("username")

        password_entry = PasswordEntry.query.filter_by(
            id=password_id, user_id=current_user.id
        ).first()
        target_user = User.query.filter_by(username=target_username).first()

        if not password_entry:
            flash("Password not found or not yours to share.", "danger")
            return redirect(url_for("routes.share_password_ui"))

        if not target_user:
            flash("Target user not found.", "danger")
            return redirect(url_for("routes.share_password_ui"))

        password_entry.shared_with.append(target_user)
        db.session.commit()

        flash(f"Password shared with {target_username}.", "success")
        return redirect(url_for("routes.dashboard"))

    # Pre-fill dropdown with current user’s passwords
    user_passwords = PasswordEntry.query.filter_by(user_id=current_user.id).all()
    return render_template("share_password.html", passwords=user_passwords)

# UI: View Shared Passwords
@bp.route("/shared-passwords-ui", methods=["GET"])
@login_required
def shared_passwords_ui():
    try:
        # Get passwords shared with current user (not owned by them)
        shared_passwords = current_user.get_shared_passwords()
        
        return render_template("shared_passwords.html", passwords=shared_passwords)
    
    except Exception as e:
        print(f"Shared passwords UI error: {str(e)}")
        flash("Failed to retrieve shared passwords.", "danger")
        return redirect(url_for("routes.dashboard"))

# UI: View Access Logs
@bp.route("/logs-ui")
@login_required
def logs_ui():
    logs = AccessLog.query.join(PasswordEntry).filter(
        (PasswordEntry.user_id == current_user.id) | (AccessLog.user_id == current_user.id)
    ).all()
    return render_template("logs.html", logs=logs)

# UI: View a password entry (decrypt + log)
@bp.route("/passwords/<int:entry_id>/view-ui")
@login_required
def view_password_ui(entry_id):
    try:
        password_entry = PasswordEntry.query.get(entry_id)

        if not password_entry or not password_entry.is_accessible_by(current_user):
            flash("You do not have access to this password.", "danger")
            return redirect(url_for("routes.dashboard"))

        # Decrypt password
        actual_password = password_entry.get_password()

        # Log access
        log_password_access(current_user, password_entry, action="viewed")

        return render_template("view_password.html", password_entry=password_entry, actual_password=actual_password)

    except Exception as e:
        print(f"View password UI error: {str(e)}")
        flash("Something went wrong while retrieving the password.", "danger")
        return redirect(url_for("routes.dashboard"))

# ui copy passwords
@bp.route("/copy_password/<int:password_id>", methods=["POST"])
@login_required
def copy_password(password_id):
    password_entry = PasswordEntry.query.get_or_404(password_id)

    if not password_entry.is_accessible_by(current_user):
        return {"error": "Unauthorized"}, 403

    # Log a copy event
    log_password_access(current_user, password_entry, action="copied")

    return {"status": "success"}