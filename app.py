import os
import sqlite3
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, url_for, make_response, flash
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity,
    unset_jwt_cookies, verify_jwt_in_request
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

# ---- CONFIG ----
app.config["SECRET_KEY"] = os.urandom(24)
app.config["JWT_SECRET_KEY"] = os.urandom(24)
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False      # Set to True in production
app.config["JWT_ACCESS_COOKIE_PATH"] = "/"
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

jwt = JWTManager(app)
DB_NAME = "database.db"

# ---- DATABASE HELPERS ----

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database with the Users table."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Create Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize DB on start
with app.app_context():
    init_db()


# ---- ROUTES ----

@app.route("/", methods=["GET", "POST"])
def login():
    """
    Handles user login.
    GET: Renders login page.
    POST: Verifies credentials and sets JWT cookie.
    """
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            # Create JWT Token
            access_token = create_access_token(identity=user['id'])
            
            # Create response and set cookie
            response = make_response(redirect(url_for('dashboard')))
            response.set_cookie('access_token_cookie', access_token)
            return response
        else:
            flash("Invalid email or password.", "error")

    return render_template("login.html") #


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Handles user registration.
    GET: Renders register page.
    POST: Hashes password and creates new user.
    """
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")

        hashed_password = generate_password_hash(password)

        try:
            conn = get_db()
            conn.execute(
                'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
                (name, email, hashed_password)
            )
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Email already registered.", "error")
        except Exception as e:
            flash(f"An error occurred: {e}", "error")

    return render_template("register.html") #


@app.route("/logout")
def logout():
    """Logs the user out by clearing the JWT cookie."""
    response = make_response(redirect(url_for("login")))
    unset_jwt_cookies(response)
    return response


# ---- DASHBOARD STUB (Protected) ----

@app.route("/dashboard")
@jwt_required()
def dashboard():
    """
    Protected route. Only accessible with valid JWT.
    """
    current_user_id = get_jwt_identity()
    
    # Fetch user details for display (optional)
    conn = get_db()
    user = conn.execute('SELECT name FROM users WHERE id = ?', (current_user_id,)).fetchone()
    conn.close()

    # Stub data for dashboard template
    stats = {"total": 0, "completed": 0, "overdue": 0}
    tasks = [] 
    
    return render_template("dashboard.html", stats=stats, tasks=tasks, user=user)


if __name__ == "__main__":
    app.run(debug=True)