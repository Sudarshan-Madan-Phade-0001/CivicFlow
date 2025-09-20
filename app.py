from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import sqlite3
import os
import random
import string
from functools import wraps
import logging
import traceback

# ----------------- App setup -----------------
app = Flask(__name__)
app.secret_key = 'civic_flow_secret_key_2024'

# Dev settings (turn off in production)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.debug = True
logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)

# ----------------- Database helpers -----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'civic_flow.db')

def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    # return rows as dict-like objects: row['column_name']
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_conn() as conn:
        c = conn.cursor()
        # Create users
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'citizen',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        # Create services
        c.execute('''CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            estimated_time INTEGER DEFAULT 15,
            is_active BOOLEAN DEFAULT 1
        )''')

        # Create queue
        c.execute('''CREATE TABLE IF NOT EXISTS queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            service_id INTEGER,
            queue_number INTEGER,
            status TEXT DEFAULT 'pending',
            priority INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            served_at TIMESTAMP,
            officer_id INTEGER,
            admin_message TEXT,
            preferred_date TEXT,
            preferred_time TEXT,
            validation_token TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (service_id) REFERENCES services (id),
            FOREIGN KEY (officer_id) REFERENCES users (id)
        )''')

        # Seed services
        services = [
            ('Aadhaar Services', 'Enrollment, update, download Aadhaar', 25),
            ('PAN Card Services', 'Apply, update, link with Aadhaar', 20),
            ('Passport Services', 'Apply, renew, track passport', 45),
            ('Property Registration', 'Property registration & mutation', 60),
            ('Driving License', 'Apply, renewal, duplicate DL', 30),
            ('Vehicle Registration', 'RC services and registration', 35),
            ('Income Tax Services', 'Filing & refunds', 40),
            ('Voter Services', 'Registration, correction, status', 15),
            ('Ration Card Services', 'Apply, add/remove members, update', 25),
            ('Pension Services', 'Social security & pension services', 30)
        ]

        # Clear & re-insert (idempotent-ish — adjust if you don't want to wipe)
        c.execute('DELETE FROM services')
        c.executemany('INSERT INTO services (name, description, estimated_time) VALUES (?, ?, ?)', services)

        # Older DBs: try to add columns if not present (safe)
        try:
            c.execute('ALTER TABLE queue ADD COLUMN preferred_date TEXT')
        except sqlite3.OperationalError:
            pass
        try:
            c.execute('ALTER TABLE queue ADD COLUMN preferred_time TEXT')
        except sqlite3.OperationalError:
            pass
        try:
            c.execute('ALTER TABLE queue ADD COLUMN validation_token TEXT')
        except sqlite3.OperationalError:
            pass

        conn.commit()

# ----------------- Error handler for development -----------------
@app.errorhandler(500)
def internal_error_dev(error):
    tb = traceback.format_exc()
    app.logger.error("500 Error on %s\n%s", request.path, tb)
    # Dev-only: show traceback. Remove this in production.
    return "<pre>" + tb + "</pre>", 500

# ----------------- Auth / decorators -----------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ----------------- Routes -----------------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip()
        password = request.form.get('password') or ''
        role = request.form.get('role', 'citizen')

        if not username or not email or not password:
            flash('Please fill all required fields', 'error')
            return render_template('signup.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template('signup.html')

        with get_conn() as conn:
            c = conn.cursor()
            c.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
            if c.fetchone():
                flash('Username or email already exists', 'error')
                return render_template('signup.html')

            hashed_password = generate_password_hash(password)
            c.execute('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
                      (username, email, hashed_password, role))
            conn.commit()

        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        if not username or not password:
            flash('Provide username and password', 'error')
            return render_template('login.html')

        with get_conn() as conn:
            c = conn.cursor()
            c.execute('SELECT id, username, password, role FROM users WHERE username = ?', (username,))
            user = c.fetchone()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    with get_conn() as conn:
        c = conn.cursor()

        if session.get('role') == 'admin':
            c.execute('SELECT COUNT(*) FROM queue WHERE status = "pending"')
            pending_count = c.fetchone()[0]

            c.execute('SELECT COUNT(*) FROM queue WHERE status = "waiting"')
            waiting_count = c.fetchone()[0]

            c.execute('SELECT COUNT(*) FROM queue WHERE status = "serving"')
            serving_count = c.fetchone()[0]

            c.execute('SELECT COUNT(*) FROM queue WHERE DATE(created_at) = DATE("now")')
            today_count = c.fetchone()[0]

            c.execute('''SELECT q.id, q.queue_number, s.name, u.username, q.created_at, q.status, q.preferred_date, q.preferred_time
                         FROM queue q 
                         JOIN services s ON q.service_id = s.id 
                         JOIN users u ON q.user_id = u.id 
                         WHERE q.status = "pending"
                         ORDER BY q.created_at ASC''')
            pending_requests = c.fetchall()

            c.execute('''SELECT s.name, COUNT(q.id) as count 
                         FROM services s LEFT JOIN queue q ON s.id = q.service_id 
                         WHERE DATE(q.created_at) = DATE("now") OR q.created_at IS NULL
                         GROUP BY s.id, s.name''')
            service_stats = c.fetchall()

            return render_template('admin_dashboard.html', 
                                 pending_count=pending_count,
                                 waiting_count=waiting_count,
                                 serving_count=serving_count,
                                 today_count=today_count,
                                 pending_requests=pending_requests,
                                 service_stats=service_stats)

        elif session.get('role') == 'officer':
            c.execute('''SELECT q.id, q.queue_number, s.name, u.username, q.created_at, q.status, s.estimated_time, q.validation_token, q.preferred_date, q.preferred_time
                         FROM queue q 
                         JOIN services s ON q.service_id = s.id 
                         JOIN users u ON q.user_id = u.id 
                         WHERE q.status IN ("waiting", "serving", "completed") 
                         ORDER BY 
                         CASE q.status 
                             WHEN 'serving' THEN 1
                             WHEN 'waiting' THEN 2
                             WHEN 'completed' THEN 3
                         END, q.created_at ASC''')
            queue_items = c.fetchall()
            return render_template('officer_dashboard.html', queue_items=queue_items)

        else:
            # Citizen dashboard
            c.execute('SELECT * FROM services WHERE is_active = 1')
            services = c.fetchall()

            c.execute('''SELECT q.id, q.queue_number, s.name, q.status, q.created_at, q.admin_message
                         FROM queue q 
                         JOIN services s ON q.service_id = s.id 
                         WHERE q.user_id = ? AND DATE(q.created_at) = DATE("now")
                         ORDER BY q.created_at DESC''', (session['user_id'],))
            my_queue = c.fetchall()

            return render_template('citizen_dashboard.html', services=services, my_queue=my_queue)

@app.route('/join_queue/<int:service_id>')
@login_required
def join_queue(service_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute('SELECT id FROM queue WHERE user_id = ? AND service_id = ? AND status NOT IN ("completed", "rejected")', 
                  (session['user_id'], service_id))
        if c.fetchone():
            flash('You are already in queue for this service', 'warning')
            return redirect(url_for('dashboard'))

        c.execute('SELECT name FROM services WHERE id = ?', (service_id,))
        result = c.fetchone()
        if not result:
            flash('Service not found', 'error')
            return redirect(url_for('dashboard'))

        service_name = result['name']

    return render_template('select_datetime.html', service_id=service_id, service_name=service_name)

@app.route('/book_appointment', methods=['POST'])
@login_required
def book_appointment():
    service_id = request.form.get('service_id')
    preferred_date = request.form.get('preferred_date')
    preferred_time = request.form.get('preferred_time')

    if not service_id:
        flash('Missing service_id', 'error')
        return redirect(url_for('dashboard'))

    try:
        service_id_int = int(service_id)
    except ValueError:
        flash('Invalid service id', 'error')
        return redirect(url_for('dashboard'))

    with get_conn() as conn:
        c = conn.cursor()
        c.execute('INSERT INTO queue (user_id, service_id, preferred_date, preferred_time, status) VALUES (?, ?, ?, ?, ?)',
                  (session['user_id'], service_id_int, preferred_date, preferred_time, 'pending'))
        conn.commit()

    flash('Your appointment request has been submitted for admin approval', 'success')
    return redirect(url_for('dashboard'))

@app.route('/cancel_request/<int:queue_id>')
@login_required
def cancel_request(queue_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute('DELETE FROM queue WHERE id = ? AND user_id = ? AND status IN ("pending", "waiting")', 
                  (queue_id, session['user_id']))
        conn.commit()

    flash('Request cancelled successfully', 'info')
    return redirect(url_for('dashboard'))

@app.route('/approve_request/<int:queue_id>')
@admin_required
def approve_request(queue_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute('SELECT service_id FROM queue WHERE id = ?', (queue_id,))
        result = c.fetchone()
        if not result:
            flash('Request not found', 'error')
            return redirect(url_for('dashboard'))

        service_id = result['service_id']

        c.execute('SELECT COALESCE(MAX(queue_number), 0) + 1 FROM queue WHERE service_id = ? AND DATE(created_at) = DATE("now") AND status != "pending"', (service_id,))
        queue_number = c.fetchone()[0]

        validation_token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

        c.execute('UPDATE queue SET status = "waiting", queue_number = ?, validation_token = ? WHERE id = ?', 
                  (queue_number, validation_token, queue_id))
        conn.commit()

    flash(f'Request approved! Token: {queue_number}, Validation ID: {validation_token}', 'success')
    return redirect(url_for('dashboard'))

@app.route('/reject_request/<int:queue_id>')
@admin_required
def reject_request(queue_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute('UPDATE queue SET status = "rejected" WHERE id = ?', (queue_id,))
        conn.commit()

    flash('Request rejected', 'info')
    return redirect(url_for('dashboard'))

@app.route('/alternative_request/<int:queue_id>', methods=['POST'])
@admin_required
def alternative_request(queue_id):
    alternative_message = (request.form.get('alternative_message') or '').strip()
    if not alternative_message:
        flash('Provide an alternative message', 'error')
        return redirect(url_for('dashboard'))

    with get_conn() as conn:
        c = conn.cursor()
        c.execute('UPDATE queue SET status = "alternative", admin_message = ? WHERE id = ?', 
                  (alternative_message, queue_id))
        conn.commit()

    flash('Alternative option provided to citizen', 'info')
    return redirect(url_for('dashboard'))

@app.route('/serve_citizen/<int:queue_id>')
@login_required
def serve_citizen(queue_id):
    if session.get('role') != 'officer':
        flash('Officer access required', 'error')
        return redirect(url_for('dashboard'))

    with get_conn() as conn:
        c = conn.cursor()
        c.execute('UPDATE queue SET status = "serving", officer_id = ? WHERE id = ? AND status = "waiting"', 
                  (session['user_id'], queue_id))
        conn.commit()

    flash('Citizen is now being served', 'success')
    return redirect(url_for('dashboard'))

@app.route('/complete_service/<int:queue_id>')
@login_required
def complete_service(queue_id):
    if session.get('role') != 'officer':
        flash('Officer access required', 'error')
        return redirect(url_for('dashboard'))

    with get_conn() as conn:
        c = conn.cursor()
        c.execute('UPDATE queue SET status = "completed", served_at = CURRENT_TIMESTAMP WHERE id = ? AND officer_id = ?', 
                  (queue_id, session['user_id']))
        conn.commit()

    flash('Service completed successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        if not username or not password:
            flash('Provide username and password', 'error')
            return render_template('admin_login.html')

        with get_conn() as conn:
            c = conn.cursor()
            c.execute('SELECT id, username, password, role FROM users WHERE username = ? AND role = "admin"', (username,))
            user = c.fetchone()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f'Welcome Admin {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid admin credentials', 'error')

    return render_template('admin_login.html')

@app.route('/test_citizen')
@login_required
def test_citizen():
    if session.get('role') != 'citizen':
        return 'Access denied', 403

    return '''<!DOCTYPE html>
<html><head><title>Test Citizen</title>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-100 p-8">
<h1 class="text-2xl font-bold mb-4">Citizen Dashboard Test</h1>
<p>Username: ''' + session.get('username', 'Unknown') + '''</p>
<p>User ID: ''' + str(session.get('user_id', 'Unknown')) + '''</p>
<a href="/logout" class="bg-red-500 text-white px-4 py-2 rounded">Logout</a>
</body></html>'''

@app.route('/validate_token', methods=['POST'])
@login_required
def validate_token():
    if session.get('role') != 'officer':
        flash('Officer access required', 'error')
        return redirect(url_for('dashboard'))

    validation_token = (request.form.get('validation_token') or '').strip().upper()
    if not validation_token:
        flash('Provide a validation token', 'error')
        return redirect(url_for('dashboard'))

    with get_conn() as conn:
        c = conn.cursor()
        c.execute('''SELECT q.id, q.queue_number, s.name, u.username, q.preferred_date, q.preferred_time
                     FROM queue q 
                     JOIN services s ON q.service_id = s.id 
                     JOIN users u ON q.user_id = u.id 
                     WHERE q.validation_token = ? AND q.status = "waiting"''', (validation_token,))
        result = c.fetchone()

    if result:
        queue_id = result['id']
        queue_number = result['queue_number']
        service_name = result['name']
        username = result['username']
        pref_date = result['preferred_date']
        pref_time = result['preferred_time']
        flash(f'Valid token! Citizen: {username}, Service: {service_name}, Queue: #{queue_number}, Scheduled: {pref_date} {pref_time}', 'success')
    else:
        flash('Invalid validation token or citizen not in waiting status', 'error')

    return redirect(url_for('dashboard'))

@app.route('/admin_setup', methods=['GET', 'POST'])
def admin_setup():
    with get_conn() as conn:
        c = conn.cursor()
        c.execute('SELECT COUNT(*) as cnt FROM users WHERE role = "admin"')
        admin_count = c.fetchone()['cnt']

    if admin_count > 0:
        flash('Admin account already exists', 'error')
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        if not username or not password:
            flash('Provide username and password', 'error')
            return render_template('admin_setup.html')

        hashed_password = generate_password_hash(password)
        with get_conn() as conn:
            c = conn.cursor()
            c.execute('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
                      (username, f'{username}@admin.gov', hashed_password, 'admin'))
            conn.commit()

        flash('Admin account created successfully', 'success')
        return redirect(url_for('admin_login'))

    return render_template('admin_setup.html')

@app.route('/create_admin')
def create_admin():
    with get_conn() as conn:
        c = conn.cursor()
        c.execute('SELECT COUNT(*) as cnt FROM users WHERE role = "admin"')
        admin_count = c.fetchone()['cnt']

        if admin_count > 0:
            return 'Admin already exists. <a href="/admin_login">Login here</a>'

        hashed_password = generate_password_hash('admin123')
        c.execute('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
                  ('admin', 'admin@civic.gov', hashed_password, 'admin'))
        conn.commit()

    return 'Admin created successfully! Username: admin, Password: admin123. <a href="/admin_login">Login here</a>'

# ----------------- Start -----------------
if __name__ == '__main__':
    # Ensure DB + tables exist
    init_db()
    port = int(os.environ.get('PORT', 5000))
    # For development: debug True will show detailed errors. Turn off for production.
    app.run(host='0.0.0.0', port=port, debug=True)
else:
    # When imported (e.g., WSGI) ensure DB initialized
    init_db()
