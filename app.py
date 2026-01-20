import os
import sqlite3
from datetime import datetime, timedelta, date

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
    """Initializes the database with Users and Tasks tables."""
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

    # Create Tasks Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'Pending',
            priority TEXT DEFAULT 'Medium',
            deadline DATE,
            tags TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize DB on start
with app.app_context():
    init_db()


# ---- AUTH ROUTES ----

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            access_token = create_access_token(identity=str(user['id']))
            response = make_response(redirect(url_for('dashboard')))
            response.set_cookie('access_token_cookie', access_token)
            return response
        else:
            flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
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
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Email already registered.", "error")
        except Exception as e:
            flash(f"An error occurred: {e}", "error")

    return render_template("register.html")


@app.route("/logout")
def logout():
    response = make_response(redirect(url_for("login")))
    unset_jwt_cookies(response)
    return response


# ---- TASK ROUTES (Protected) ----

@app.route("/dashboard")
@jwt_required()
def dashboard():
    current_user_id = get_jwt_identity()
    conn = get_db()
    
    # 1. Fetch User Info
    user = conn.execute('SELECT name FROM users WHERE id = ?', (current_user_id,)).fetchone()

    # 2. Handle Filters from URL parameters
    status_filter = request.args.get('status')
    priority_filter = request.args.get('priority')
    search_query = request.args.get('q')

    query = "SELECT * FROM tasks WHERE user_id = ?"
    params = [current_user_id]

    if status_filter:
        query += " AND status = ?"
        params.append(status_filter)
    
    if priority_filter:
        query += " AND priority = ?"
        params.append(priority_filter)
        
    if search_query:
        query += " AND (title LIKE ? OR description LIKE ?)"
        params.append(f"%{search_query}%")
        params.append(f"%{search_query}%")

    query += " ORDER BY deadline ASC"

    # 3. Execute Query
    rows = conn.execute(query, params).fetchall()
    
    # 4. Process Tasks (Calculate Overdue)
    tasks = []
    today = date.today()
    
    stats = {"total": 0, "completed": 0, "overdue": 0}

    for row in rows:
        task = dict(row) # Convert Row to Dict to allow modification
        task_date = datetime.strptime(task['deadline'], '%Y-%m-%d').date() if task['deadline'] else None
        
        # Determine if overdue
        is_overdue = False
        if task_date and task_date < today and task['status'] != 'Completed':
            is_overdue = True
            stats["overdue"] += 1
        
        task['is_overdue'] = is_overdue
        tasks.append(task)

        # Update stats
        stats["total"] += 1
        if task['status'] == 'Completed':
            stats["completed"] += 1

    conn.close()
    return render_template("dashboard.html", stats=stats, tasks=tasks, user=user)


@app.route("/task/create", methods=["GET", "POST"])
@jwt_required()
def create_task():
    if request.method == "POST":
        current_user_id = get_jwt_identity()
        title = request.form.get("title")
        description = request.form.get("description")
        priority = request.form.get("priority")
        status = request.form.get("status")
        deadline = request.form.get("deadline")
        tags = request.form.get("tags")

        conn = get_db()
        conn.execute('''
            INSERT INTO tasks (user_id, title, description, priority, status, deadline, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (current_user_id, title, description, priority, status, deadline, tags))
        conn.commit()
        conn.close()
        
        flash("Task created successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template("task_create.html")


@app.route("/task/edit/<int:task_id>", methods=["GET", "POST"])
@jwt_required()
def edit_task(task_id):
    current_user_id = get_jwt_identity()
    conn = get_db()
    
    # Verify task belongs to current user
    task = conn.execute('SELECT * FROM tasks WHERE id = ? AND user_id = ?', 
                        (task_id, current_user_id)).fetchone()

    if not task:
        conn.close()
        flash("Task not found or unauthorized.", "error")
        return redirect(url_for('dashboard'))

    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        priority = request.form.get("priority")
        status = request.form.get("status")
        deadline = request.form.get("deadline")

        conn.execute('''
            UPDATE tasks 
            SET title = ?, description = ?, priority = ?, status = ?, deadline = ?
            WHERE id = ? AND user_id = ?
        ''', (title, description, priority, status, deadline, task_id, current_user_id))
        conn.commit()
        conn.close()
        flash("Task updated.", "success")
        return redirect(url_for('dashboard'))

    conn.close()
    return render_template("task_edit.html", task=task)


@app.route("/task/delete/<int:task_id>")
@jwt_required()
def delete_task(task_id):
    current_user_id = get_jwt_identity()
    conn = get_db()
    conn.execute('DELETE FROM tasks WHERE id = ? AND user_id = ?', (task_id, current_user_id))
    conn.commit()
    conn.close()
    flash("Task deleted.", "info")
    return redirect(url_for('dashboard'))


@app.route("/analytics")
@jwt_required()
def analytics():
    # Placeholder for the link in dashboard footer
    flash("Detailed analytics coming soon!", "info")
    return redirect(url_for('dashboard'))


if __name__ == "__main__":
    app.run(debug=True)