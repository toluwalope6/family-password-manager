# family-password-manager

A secure, multi-user "password manager" built with "FlasK (Python)" that allows family, friends, partners to safely store, share, and manage passwords in one place.

This project emphasizes both on software engineering best practices and cybersecurity principles including password hashing, encryption, and secure access logging.

## Preview:

## Login Page  
#<img width="1889" height="777" alt="Screenshot 2025-10-07 162525" src="https://github.com/user-attachments/assets/7625de6f-e87b-4f21-bf7b-6a422f1fcc26" />

### Dashboard  
<img width="1919" height="778" alt="Screenshot 2025-10-07 162959" src="https://github.com/user-attachments/assets/01ba5211-f53b-4ad4-a9f4-8e49e1e0b70a" />

### 📤 Password Sharing  
<img width="1886" height="697" alt="Screenshot 2025-10-07 184605" src="https://github.com/user-attachments/assets/5d1b2a67-cc3b-476e-b835-771b01cfde70" />

### 🧾 Access Logs  
<img width="1916" height="674" alt="Screenshot 2025-10-07 163009" src="https://github.com/user-attachments/assets/dd907008-f29b-4b14-8d20-96df8d2f65a6" />


## Features

### User Management
- Register and log in securely (Flask-Login)
- Passwords hashed using **bcrypt**

### Password Storage
- Passwords are encrypted before being stored
- Each entry includes: service name, login, URL, and notes
- Users can **view**, **copy** passwords securely

### Password Sharing
- Share passwords with other registered users
- Access permissions (view-only for now)
- Shared password tracking via SQLAlchemy association table

### Access Logs
- Every password **view** and **copy** event is logged
- Logs include user, password entry, action type, and timestamp
- Simple UI to view activity history

### Web UI + API
- Frontend built with **Flask Jinja2 + Bootstrap**
- REST-style API endpoints (JSON-based) for integration/testing
- Fully functional **web interface** for everyday use(Going to work on the UI Later)


## Tech Stack
**Backend** - Python Flask, Flask_Login, Flask_SQlAlchemy
**DB** - SQLite (development)
**Frontend** - Jinja2 Templates, HTML
**Security** - Bcrypt (password hashing), AES encryptiong
**Version Control** - Git/Github
**Testing Tools** - Postman(Majorly for API testing(routes))




## Setup Instructions

1. Clone this repo:
git clone https://github.com/<your-username>/family-password-manager.git
cd family-password-manager

2. Create a virtual environment:
python -m venv .venv
.\.venv\Scripts\Activate.ps1

![Uploading Screenshot 2025-10-07 141715.png…]()

3. Install dependencies
pip install -r requirements.txt

4. Run the app
python run.py

5. Open in browser
Go to: http://127.0.0.1:5000/"route"
Example: http://127.0.0.1:5000/register (do this after all steps above been completed)

