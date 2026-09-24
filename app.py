"""
===============================================================
Login Security Monitoring System
===============================================================
A simple, beginner-friendly Flask web application to monitor
user login activity, track failed and successful login attempts,
and manage cybersecurity events.

Author: College Project Demo
Backend: Python (Flask)
Database: MySQL (XAMPP / mysql-connector-python)
===============================================================
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error
from functools import wraps

app = Flask(__name__)

# Secret key for managing user sessions securely
app.secret_key = 'super_secret_college_project_key_change_in_production'

# -------------------------------------------------------------------
# Database Configuration (Default XAMPP MySQL Settings)
# -------------------------------------------------------------------
DB_CONFIG = {
    'host': 'sql.freedb.tech',
    'user': 'u_WUQumm',
    'password': '4ERLckcLN1YO',          # Default XAMPP MySQL has an empty password
    'database': 'freedb_uoGfExXX',
    'port': 3306
}

def get_db_connection():
    """
    Helper function to establish a connection to MySQL.
    Returns a MySQL connection object or None if connection fails.
    """
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except Error as e:
        print(f"[ERROR] Database connection failed: {e}")
        return None


def get_client_ip():
    """
    Helper function to get client IP address safely.
    Handles proxies if present, otherwise uses remote_addr.
    """
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'


def log_login_attempt(username, status):
    """
    Helper function to log every login attempt into the `login_logs` table.
    - status: 'SUCCESS' or 'FAILED'
    """
    ip_address = get_client_ip()
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            query = "INSERT INTO login_logs (username, status, ip_address) VALUES (%s, %s, %s)"
            cursor.execute(query, (username, status, ip_address))
            conn.commit()
            cursor.close()
        except Error as e:
            print(f"[ERROR] Failed to record login log: {e}")
        finally:
            conn.close()


# -------------------------------------------------------------------
# Login Required Decorator
# Protects routes from unauthorized access
# -------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Please log in first to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# -------------------------------------------------------------------
# Route: Home
# -------------------------------------------------------------------
@app.route('/')
def home():
    """Redirect home to dashboard if logged in, otherwise to login page."""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


# -------------------------------------------------------------------
# Route: User Registration
# -------------------------------------------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles new user registration with secure password hashing."""
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        # Basic Form Validation
        if not username or not password:
            flash("Username and password are required!", "danger")
            return render_template('register.html')

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return render_template('register.html')

        conn = get_db_connection()
        if not conn:
            flash("Database connection failed. Please ensure XAMPP MySQL is running.", "danger")
            return render_template('register.html')

        try:
            cursor = conn.cursor(dictionary=True)

            # Check if username already exists
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            existing_user = cursor.fetchone()

            if existing_user:
                flash("Username is already taken. Please choose another one.", "warning")
                cursor.close()
                conn.close()
                return render_template('register.html')

            # Hash the password securely using Werkzeug
            hashed_password = generate_password_hash(password)

            # Insert new user into database
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (%s, %s)",
                (username, hashed_password)
            )
            conn.commit()
            cursor.close()
            conn.close()

            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('login'))

        except Error as e:
            flash(f"Error registering user: {e}", "danger")
            return render_template('register.html')

    return render_template('register.html')


# -------------------------------------------------------------------
# Route: User Login & Security Monitoring
# -------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login.
    Records every attempt (SUCCESS or FAILED) into login_logs table.
    """
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template('login.html')

        conn = get_db_connection()
        if not conn:
            flash("Database connection failed. Please ensure XAMPP MySQL is running.", "danger")
            return render_template('login.html')

        try:
            cursor = conn.cursor(dictionary=True)
            # Find user by username using parameterized query to prevent SQL injection
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()

            # Verify password using Werkzeug's check_password_hash
            if user and check_password_hash(user['password'], password):
                # LOGIN SUCCESSFUL
                log_login_attempt(username, 'SUCCESS')
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash(f"Welcome back, {user['username']}!", "success")
                return redirect(url_for('dashboard'))
            else:
                # LOGIN FAILED
                log_login_attempt(username if username else 'unknown', 'FAILED')
                flash("Invalid username or password. This attempt has been logged.", "danger")
                return render_template('login.html')

        except Error as e:
            flash(f"Database error: {e}", "danger")
            return render_template('login.html')

    return render_template('login.html')


# -------------------------------------------------------------------
# Route: Logout
# -------------------------------------------------------------------
@app.route('/logout')
def logout():
    """Clears user session and logs them out."""
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('login'))


# -------------------------------------------------------------------
# Route: Dashboard
# -------------------------------------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    """
    Displays summary statistics:
    - Total users count
    - Total successful logins
    - Total failed logins
    - Recent 5 login activities
    """
    conn = get_db_connection()
    if not conn:
        flash("Database connection error.", "danger")
        return render_template('dashboard.html', stats={}, recent_logs=[])

    try:
        cursor = conn.cursor(dictionary=True)

        # 1. Total users
        cursor.execute("SELECT COUNT(*) AS total_users FROM users")
        total_users = cursor.fetchone()['total_users']

        # 2. Total successful logins
        cursor.execute("SELECT COUNT(*) AS total_success FROM login_logs WHERE status = 'SUCCESS'")
        total_success = cursor.fetchone()['total_success']

        # 3. Total failed logins
        cursor.execute("SELECT COUNT(*) AS total_failed FROM login_logs WHERE status = 'FAILED'")
        total_failed = cursor.fetchone()['total_failed']

        # 4. Total security events
        cursor.execute("SELECT COUNT(*) AS total_events FROM security_events")
        total_events = cursor.fetchone()['total_events']

        # 5. Recent 5 login activities
        cursor.execute("SELECT * FROM login_logs ORDER BY login_time DESC LIMIT 5")
        recent_logs = cursor.fetchall()

        cursor.close()
        conn.close()

        stats = {
            'total_users': total_users,
            'total_success': total_success,
            'total_failed': total_failed,
            'total_events': total_events
        }

        return render_template('dashboard.html', stats=stats, recent_logs=recent_logs)

    except Error as e:
        flash(f"Database error fetching dashboard: {e}", "danger")
        return render_template('dashboard.html', stats={}, recent_logs=[])


# -------------------------------------------------------------------
# Route: Login Logs (CRUD - Read and Delete)
# -------------------------------------------------------------------
@app.route('/login-logs')
@login_required
def login_logs():
    """Displays all login logs (success and failed)."""
    conn = get_db_connection()
    logs = []
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM login_logs ORDER BY login_time DESC")
            logs = cursor.fetchall()
            cursor.close()
            conn.close()
        except Error as e:
            flash(f"Error fetching login logs: {e}", "danger")
    return render_template('login_logs.html', logs=logs)


@app.route('/login-logs/delete/<int:id>')
@login_required
def delete_login_log(id):
    """Deletes a specific login log entry."""
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM login_logs WHERE id = %s", (id,))
            conn.commit()
            cursor.close()
            conn.close()
            flash("Login log deleted successfully.", "success")
        except Error as e:
            flash(f"Error deleting log: {e}", "danger")
    return redirect(url_for('login_logs'))


# -------------------------------------------------------------------
# Route: Security Events (CRUD - Read, Create, Update, Delete)
# -------------------------------------------------------------------
@app.route('/security-events')
@login_required
def security_events():
    """Displays all recorded cybersecurity events."""
    conn = get_db_connection()
    events = []
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM security_events ORDER BY created_at DESC")
            events = cursor.fetchall()
            cursor.close()
            conn.close()
        except Error as e:
            flash(f"Error fetching security events: {e}", "danger")
    return render_template('security_events.html', events=events)


@app.route('/security-events/add', methods=['GET', 'POST'])
@login_required
def add_security_event():
    """Creates a new cybersecurity event record."""
    if request.method == 'POST':
        event_type = request.form.get('event_type', '').strip()
        description = request.form.get('description', '').strip()
        severity = request.form.get('severity', 'LOW').strip().upper()

        if not event_type or not description:
            flash("Event type and description are required fields.", "danger")
            return render_template('add_event.html')

        conn = get_db_connection()
        if conn:
            try:
                cursor = conn.cursor()
                query = "INSERT INTO security_events (event_type, description, severity) VALUES (%s, %s, %s)"
                cursor.execute(query, (event_type, description, severity))
                conn.commit()
                cursor.close()
                conn.close()
                flash("Security event added successfully!", "success")
                return redirect(url_for('security_events'))
            except Error as e:
                flash(f"Error adding security event: {e}", "danger")

    return render_template('add_event.html')


@app.route('/security-events/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_security_event(id):
    """Updates an existing cybersecurity event record."""
    conn = get_db_connection()
    if not conn:
        flash("Database connection error.", "danger")
        return redirect(url_for('security_events'))

    try:
        cursor = conn.cursor(dictionary=True)

        if request.method == 'POST':
            event_type = request.form.get('event_type', '').strip()
            description = request.form.get('description', '').strip()
            severity = request.form.get('severity', 'LOW').strip().upper()

            if not event_type or not description:
                flash("Event type and description cannot be empty.", "danger")
            else:
                update_query = """
                    UPDATE security_events
                    SET event_type = %s, description = %s, severity = %s
                    WHERE id = %s
                """
                cursor.execute(update_query, (event_type, description, severity, id))
                conn.commit()
                cursor.close()
                conn.close()
                flash("Security event updated successfully!", "success")
                return redirect(url_for('security_events'))

        # Fetch current record for GET request
        cursor.execute("SELECT * FROM security_events WHERE id = %s", (id,))
        event = cursor.fetchone()
        cursor.close()
        conn.close()

        if not event:
            flash("Security event not found.", "warning")
            return redirect(url_for('security_events'))

        return render_template('edit_event.html', event=event)

    except Error as e:
        flash(f"Error updating security event: {e}", "danger")
        return redirect(url_for('security_events'))


@app.route('/security-events/delete/<int:id>')
@login_required
def delete_security_event(id):
    """Deletes a cybersecurity event record."""
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM security_events WHERE id = %s", (id,))
            conn.commit()
            cursor.close()
            conn.close()
            flash("Security event deleted successfully.", "success")
        except Error as e:
            flash(f"Error deleting event: {e}", "danger")
    return redirect(url_for('security_events'))


# -------------------------------------------------------------------
# Application Entry Point
# -------------------------------------------------------------------
if __name__ == '__main__':
    # Runs the Flask development server on port 5000 in debug mode
    print("\n" + "="*60)
    print(" Login Security Monitoring System is starting...")
    print(" Running locally at: http://127.0.0.1:5000")
    print("="*60 + "\n")
    app.run(debug=True, host='127.0.0.1', port=5000)
