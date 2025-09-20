from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import sqlite3
import os
import random
import string
from functools import wraps

app = Flask(__name__)
app.secret_key = 'civic_flow_secret_key_2024'

def init_db():
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'citizen',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        estimated_time INTEGER DEFAULT 15,
        is_active BOOLEAN DEFAULT 1
    )''')
    
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
    
    c.execute('DELETE FROM services')
    for service in services:
        c.execute('INSERT INTO services (name, description, estimated_time) VALUES (?, ?, ?)', service)
    
    try:
        c.execute('ALTER TABLE queue ADD COLUMN preferred_date TEXT')
        c.execute('ALTER TABLE queue ADD COLUMN preferred_time TEXT')
        c.execute('ALTER TABLE queue ADD COLUMN validation_token TEXT')
    except sqlite3.OperationalError:
        pass
    
    conn.commit()
    conn.close()

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

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role', 'citizen')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template('signup.html')
        
        conn = sqlite3.connect('civic_flow.db')
        c = conn.cursor()
        
        c.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        if c.fetchone():
            flash('Username or email already exists', 'error')
            conn.close()
            return render_template('signup.html')
        
        hashed_password = generate_password_hash(password)
        c.execute('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
                  (username, email, hashed_password, role))
        conn.commit()
        conn.close()
        
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('civic_flow.db')
        c = conn.cursor()
        c.execute('SELECT id, username, password, role FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            flash(f'Welcome back, {user[1]}!', 'success')
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
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    
    if session['role'] == 'admin':
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
        
        conn.close()
        return render_template('admin_dashboard.html', 
                             pending_count=pending_count,
                             waiting_count=waiting_count,
                             serving_count=serving_count,
                             today_count=today_count,
                             pending_requests=pending_requests,
                             service_stats=service_stats)
    
    elif session['role'] == 'officer':
        c.execute('''SELECT q.id, q.queue_number, s.name, u.username, q.created_at, q.status, s.estimated_time, q.validation_token, q.preferred_date, q.preferred_time
                     FROM queue q 
                     JOIN services s ON q.service_id = s.id 
                     JOIN users u ON q.user_id = u.id 
                     WHERE q.status IN ("waiting", "serving", "completed") 
                     AND q.validation_token IS NOT NULL 
                     AND q.validation_token != ''
                     AND q.queue_number IS NOT NULL
                     ORDER BY 
                     CASE q.status 
                         WHEN 'serving' THEN 1
                         WHEN 'waiting' THEN 2
                         WHEN 'completed' THEN 3
                     END, q.created_at ASC''')
        queue_items = c.fetchall()
        conn.close()
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
        
        conn.close()
        return render_template('citizen_dashboard.html', services=services, my_queue=my_queue)

@app.route('/join_queue/<int:service_id>')
@login_required
def join_queue(service_id):
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    
    c.execute('SELECT id FROM queue WHERE user_id = ? AND service_id = ? AND status NOT IN ("completed", "rejected")', 
              (session['user_id'], service_id))
    if c.fetchone():
        flash('You are already in queue for this service', 'warning')
        conn.close()
        return redirect(url_for('dashboard'))
    
    c.execute('SELECT name FROM services WHERE id = ?', (service_id,))
    result = c.fetchone()
    if not result:
        flash('Service not found', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    service_name = result[0]
    conn.close()
    
    return render_template('select_datetime.html', service_id=service_id, service_name=service_name)

@app.route('/book_appointment', methods=['POST'])
@login_required
def book_appointment():
    service_id = request.form['service_id']
    preferred_date = request.form['preferred_date']
    preferred_time = request.form['preferred_time']
    
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    
    c.execute('INSERT INTO queue (user_id, service_id, preferred_date, preferred_time, status) VALUES (?, ?, ?, ?, ?)',
              (session['user_id'], service_id, preferred_date, preferred_time, 'pending'))
    conn.commit()
    conn.close()
    
    flash('Your appointment request has been submitted for admin approval', 'success')
    return redirect(url_for('dashboard'))

@app.route('/cancel_request/<int:queue_id>')
@login_required
def cancel_request(queue_id):
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    c.execute('DELETE FROM queue WHERE id = ? AND user_id = ? AND status IN ("pending", "waiting")', 
              (queue_id, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('Request cancelled successfully', 'info')
    return redirect(url_for('dashboard'))

@app.route('/approve_request/<int:queue_id>')
@admin_required
def approve_request(queue_id):
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    
    c.execute('SELECT service_id FROM queue WHERE id = ?', (queue_id,))
    result = c.fetchone()
    if not result:
        flash('Request not found', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    service_id = result[0]
    
    c.execute('SELECT COALESCE(MAX(queue_number), 0) + 1 FROM queue WHERE service_id = ? AND DATE(created_at) = DATE("now") AND status != "pending"', (service_id,))
    queue_number = c.fetchone()[0]
    
    validation_token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    
    c.execute('UPDATE queue SET status = "waiting", queue_number = ?, validation_token = ? WHERE id = ?', 
              (queue_number, validation_token, queue_id))
    conn.commit()
    conn.close()
    
    flash(f'Request approved! Token: {queue_number}, Validation ID: {validation_token}', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('civic_flow.db')
        c = conn.cursor()
        c.execute('SELECT id, username, password, role FROM users WHERE username = ? AND role = "admin"', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            flash(f'Welcome Admin {user[1]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid admin credentials', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin_setup', methods=['GET', 'POST'])
def admin_setup():
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
    admin_count = c.fetchone()[0]
    conn.close()
    
    if admin_count > 0:
        flash('Admin account already exists', 'error')
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('civic_flow.db')
        c = conn.cursor()
        
        hashed_password = generate_password_hash(password)
        c.execute('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
                  (username, f'{username}@admin.gov', hashed_password, 'admin'))
        conn.commit()
        conn.close()
        
        flash('Admin account created successfully', 'success')
        return redirect(url_for('admin_login'))
    
    return render_template('admin_setup.html')

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True, use_reloader=False)
else:
    init_db()