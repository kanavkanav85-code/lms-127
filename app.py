import os
import sqlite3
import datetime
import json
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, flash, g, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

application = Flask(__name__)

# --- Configuration ---
DATABASE = 'lms.db'
UPLOAD_FOLDER = 'uploads'
SUBMISSIONS_FOLDER = 'submissions'
LEAVE_DOCS_FOLDER = 'leave_documents'
application.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
application.config['SUBMISSIONS_FOLDER'] = SUBMISSIONS_FOLDER
application.config['LEAVE_DOCS_FOLDER'] = LEAVE_DOCS_FOLDER
application.config['SECRET_KEY'] = 'a-very-secret-key-that-you-should-change'

# --- AI Configuration (DISABLED) ---
AI_ENABLED = False

# --- Database Setup and Helpers ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@application.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with application.app_context():
        db = get_db()
        with application.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id = 'superadmin'")
        if cursor.fetchone() is None:
            db.execute("INSERT INTO users (id, display_name, email, password, role, campus_id) VALUES (?, ?, ?, ?, ?, ?)",
                       ('superadmin', 'Super Admin', 'super@example.com', generate_password_hash('super123'), 'super_admin', None))
            db.commit()

# --- Force DB Initialization on Startup ---
with application.app_context():
    init_db()

# --- Helper Functions ---
def get_all_users_by_campus(campus_id):
    db = get_db()
    return db.execute("SELECT u.*, c.name as campus_name FROM users u LEFT JOIN campuses c ON u.campus_id = c.id WHERE u.campus_id = ?", (campus_id,)).fetchall()

def get_all_users():
    db = get_db()
    return db.execute("SELECT * FROM users").fetchall()

# --- Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session: return redirect(url_for('login'))
            if session.get('role') not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Context Processors ---
@application.context_processor
def inject_user_and_notifications():
    if 'user_id' in session:
        db = get_db()
        user = db.execute("SELECT u.*, c.name as campus_name FROM users u LEFT JOIN campuses c ON u.campus_id = c.id WHERE u.id = ?", (session['user_id'],)).fetchone()
        unread_messages_count = db.execute("SELECT COUNT(id) FROM messages WHERE recipient_id = ? AND is_read = 0", (session['user_id'],)).fetchone()[0]
        notifications = db.execute("SELECT * FROM notifications WHERE user_id = ? AND is_read = 0 ORDER BY timestamp DESC", (session['user_id'],)).fetchall()
        return dict(current_user=user, unread_messages_count=unread_messages_count, notifications=notifications)
    return dict(current_user=None, unread_messages_count=0, notifications=[])

# --- Core Routes ---
@application.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        password = request.form.get('password')
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['campus_id'] = user['campus_id']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid user ID or password.', 'danger')
    return render_template('login.html')

@application.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@application.route('/forgot_password')
def forgot_password():
    return render_template('forgot_password.html')

@application.route('/')
@application.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    user_role = session['role']
    user_id = session['user_id']
    campus_id = session.get('campus_id')

    subjects = []
    if user_role == 'super_admin':
        subjects = db.execute("SELECT s.*, c.name as campus_name FROM subjects s JOIN campuses c ON s.campus_id = c.id ORDER BY c.name, s.name").fetchall()
    elif user_role == 'admin':
        subjects = db.execute("SELECT * FROM subjects WHERE campus_id = ? ORDER BY name", (campus_id,)).fetchall()
    elif user_role == 'teacher':
        subjects = db.execute("SELECT s.* FROM subjects s JOIN teacher_subjects ts ON s.id = ts.subject_id WHERE ts.teacher_id = ? AND s.campus_id = ? ORDER BY s.name", (user_id, campus_id)).fetchall()
    else: # student
        subjects = db.execute("SELECT * FROM subjects WHERE campus_id = ? ORDER BY name", (campus_id,)).fetchall()
        
    return render_template('dashboard.html', subjects=subjects)

# --- Super Admin & Admin Routes ---
@application.route('/user_management', methods=['GET', 'POST'])
@role_required(['admin', 'super_admin'])
def user_management():
    db = get_db()
    if request.method == 'POST':
        campus_id = session.get('campus_id')
        role = request.form.get('role')
        if session['role'] == 'super_admin':
            campus_id = request.form.get('campus_id')
            if role != 'super_admin' and not campus_id:
                flash('A campus must be selected to create this user.', 'danger')
                return redirect(url_for('user_management'))
        
        user_id, display_name, email, password = request.form.get('user_id'), request.form.get('display_name'), request.form.get('email'), request.form.get('password')
        user_exists = db.execute("SELECT id FROM users WHERE id = ? OR email = ?", (user_id, email)).fetchone()
        if user_exists:
            flash(f'A user with that User ID or Email already exists.', 'danger')
        else:
            db.execute("INSERT INTO users (id, display_name, email, password, role, campus_id) VALUES (?, ?, ?, ?, ?, ?)",
                       (user_id, display_name, email, generate_password_hash(password), role, campus_id))
            db.commit()
            flash(f'User "{display_name}" created successfully.', 'success')
        return redirect(url_for('user_management'))
    
    users, campuses = [], []
    if session['role'] == 'super_admin':
        users = db.execute("SELECT u.*, c.name as campus_name FROM users u LEFT JOIN campuses c ON u.campus_id = c.id").fetchall()
        campuses = db.execute("SELECT * FROM campuses").fetchall()
    else:
        users = get_all_users_by_campus(session['campus_id'])
    return render_template('user_management.html', users=users, campuses=campuses)

@application.route('/reset_password/<user_id_to_reset>', methods=['POST'])
@role_required(['admin', 'super_admin'])
def reset_password(user_id_to_reset):
    db = get_db()
    new_password = request.form.get('new_password')
    if new_password:
        db.execute("UPDATE users SET password = ? WHERE id = ?", (generate_password_hash(new_password), user_id_to_reset))
        db.commit()
        flash(f"Password for user '{user_id_to_reset}' has been reset.", 'success')
    else:
        flash('Password cannot be empty.', 'danger')
    return redirect(url_for('user_management'))

@application.route('/leave_management')
@role_required(['admin', 'super_admin'])
def leave_management():
    db = get_db()
    campus_id = session.get('campus_id')
    if session['role'] == 'super_admin':
        applications = db.execute("SELECT l.*, u.display_name, c.name as campus_name FROM leave_applications l JOIN users u ON l.user_id = u.id LEFT JOIN campuses c ON u.campus_id = c.id ORDER BY l.submitted_at DESC").fetchall()
    else:
        applications = db.execute("SELECT l.*, u.display_name FROM leave_applications l JOIN users u ON l.user_id = u.id WHERE u.campus_id = ? ORDER BY l.submitted_at DESC", (campus_id,)).fetchall()
    return render_template('leave_management.html', applications=applications)

# --- All User Routes ---
@application.route('/apply_for_leave', methods=['GET', 'POST'])
@login_required
def apply_for_leave():
    db = get_db()
    if request.method == 'POST':
        reason, start_date, end_date = request.form.get('reason'), request.form.get('start_date'), request.form.get('end_date')
        document = request.files.get('document')
        doc_path = None
        if document and document.filename != '':
            filename = secure_filename(document.filename)
            doc_path = os.path.join(application.config['LEAVE_DOCS_FOLDER'], filename)
            document.save(doc_path)
        db.execute("INSERT INTO leave_applications (user_id, reason, start_date, end_date, document_path) VALUES (?, ?, ?, ?, ?)",
                   (session['user_id'], reason, start_date, end_date, doc_path))
        db.commit()
        flash('Leave application submitted successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('leave_application.html')

@application.route('/messages')
@login_required
def messages():
    db = get_db()
    db.execute("UPDATE messages SET is_read = 1 WHERE recipient_id = ?", (session['user_id'],))
    db.commit()
    received_messages = db.execute("SELECT m.*, u.display_name as sender_name FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.recipient_id = ? ORDER BY m.timestamp DESC", (session['user_id'],)).fetchall()
    
    users = []
    if session['role'] == 'super_admin':
        users = db.execute("SELECT * FROM users").fetchall()
    else:
        users = get_all_users_by_campus(session.get('campus_id'))
    return render_template('messages.html', received_messages=received_messages, users=users)

# --- This is the final line and it is VERY IMPORTANT for local testing ---
if __name__ == '__main__':
    # Create necessary folders if they don't exist
    for folder in [UPLOAD_FOLDER, SUBMISSIONS_FOLDER, LEAVE_DOCS_FOLDER]:
        if not os.path.exists(folder):
            os.makedirs(folder)
    # Run the app
    application.run(debug=True)
```

### **What to Do Now**

1.  **Save the file** named `application.py`.
2.  **Go to your terminal** and make sure you are in your project folder (`lms_project`).
3.  **Run the application** with the command:
    ```bash
    python application.py
    
