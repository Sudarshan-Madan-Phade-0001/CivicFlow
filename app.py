from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import sqlite3
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = 'civic_flow_secret_key_2024'

# Database initialization
def init_db():
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'citizen',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Services table
    c.execute('''CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        estimated_time INTEGER DEFAULT 15,
        is_active BOOLEAN DEFAULT 1
    )''')
    
    # Queue table
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
    
    # Insert default services
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
    
    # Admin accounts must be created manually for security
    
    # Add new columns if they don't exist
    try:
        c.execute('ALTER TABLE queue ADD COLUMN preferred_date TEXT')
        c.execute('ALTER TABLE queue ADD COLUMN preferred_time TEXT')
        c.execute('ALTER TABLE queue ADD COLUMN validation_token TEXT')
    except sqlite3.OperationalError:
        pass  # Columns already exist
    
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
        
        # Check if user exists
        c.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        if c.fetchone():
            flash('Username or email already exists', 'error')
            conn.close()
            return render_template('signup.html')
        
        # Create user
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
        # Admin dashboard data
        c.execute('SELECT COUNT(*) FROM queue WHERE status = "pending"')
        pending_count = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM queue WHERE status = "waiting"')
        waiting_count = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM queue WHERE status = "serving"')
        serving_count = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM queue WHERE DATE(created_at) = DATE("now")')
        today_count = c.fetchone()[0]
        
        # Get pending requests
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
        # Officer dashboard
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
        conn.close()
        return render_template('officer_dashboard.html', queue_items=queue_items)
    
    else:
        # Citizen dashboard
        c.execute('SELECT * FROM services WHERE is_active = 1')
        services = c.fetchall()
        
        c.execute('''SELECT q.id, q.queue_number, s.name, q.status, q.created_at
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
    
    # Check if user already in queue for this service
    c.execute('SELECT id FROM queue WHERE user_id = ? AND service_id = ? AND status NOT IN ("completed", "rejected")', 
              (session['user_id'], service_id))
    if c.fetchone():
        flash('You are already in queue for this service', 'warning')
        conn.close()
        return redirect(url_for('dashboard'))
    
    # Get service name
    c.execute('SELECT name FROM services WHERE id = ?', (service_id,))
    service_name = c.fetchone()[0]
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
    
    # Add to queue with preferred date/time
    c.execute('INSERT INTO queue (user_id, service_id, preferred_date, preferred_time) VALUES (?, ?, ?, ?)',
              (session['user_id'], service_id, preferred_date, preferred_time))
    conn.commit()
    conn.close()
    
    flash('Your appointment request has been submitted for admin approval', 'success')
    return redirect(url_for('dashboard'))

@app.route('/api/queue_status')
@login_required
def queue_status():
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    
    c.execute('''SELECT q.id, q.queue_number, s.name, u.username, q.status, q.created_at
                 FROM queue q 
                 JOIN services s ON q.service_id = s.id 
                 JOIN users u ON q.user_id = u.id 
                 WHERE q.status IN ("waiting", "serving") 
                 ORDER BY q.priority DESC, q.created_at ASC''')
    
    queue_data = []
    for row in c.fetchall():
        queue_data.append({
            'id': row[0],
            'queue_number': row[1],
            'service': row[2],
            'citizen': row[3],
            'status': row[4],
            'created_at': row[5]
        })
    
    conn.close()
    return jsonify(queue_data)

@app.route('/serve_next/<int:queue_id>')
@login_required
def serve_next(queue_id):
    if session['role'] not in ['admin', 'officer']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    c.execute('UPDATE queue SET status = "serving", officer_id = ? WHERE id = ?', 
              (session['user_id'], queue_id))
    conn.commit()
    conn.close()
    
    flash('Citizen is now being served', 'success')
    return redirect(url_for('dashboard'))

@app.route('/complete_service/<int:queue_id>')
@login_required
def complete_service(queue_id):
    if session['role'] not in ['admin', 'officer']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    c.execute('UPDATE queue SET status = "completed", served_at = CURRENT_TIMESTAMP WHERE id = ?', 
              (queue_id,))
    conn.commit()
    conn.close()
    
    flash('Service completed successfully', 'success')
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
    import random, string
    
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    
    # Get service_id for this request
    c.execute('SELECT service_id FROM queue WHERE id = ?', (queue_id,))
    service_id = c.fetchone()[0]
    
    # Get next queue number for this specific service
    c.execute('SELECT COALESCE(MAX(queue_number), 0) + 1 FROM queue WHERE service_id = ? AND DATE(created_at) = DATE("now") AND status != "pending"', (service_id,))
    queue_number = c.fetchone()[0]
    
    # Generate validation token
    validation_token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    
    c.execute('UPDATE queue SET status = "waiting", queue_number = ?, validation_token = ? WHERE id = ?', 
              (queue_number, validation_token, queue_id))
    conn.commit()
    conn.close()
    
    flash(f'Request approved! Token: {queue_number}, Validation ID: {validation_token}', 'success')
    return redirect(url_for('dashboard'))

@app.route('/reject_request/<int:queue_id>', methods=['POST'])
@admin_required
def reject_request(queue_id):
    message = request.form.get('message', 'Request rejected')
    
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    c.execute('UPDATE queue SET status = "rejected", admin_message = ? WHERE id = ?', 
              (message, queue_id))
    conn.commit()
    conn.close()
    
    flash('Request rejected with message sent', 'info')
    return redirect(url_for('dashboard'))

@app.route('/approve_service/<service_name>')
@admin_required
def approve_service(service_name):
    import random, string
    
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    
    # Get service ID
    c.execute('SELECT id FROM services WHERE name = ?', (service_name,))
    result = c.fetchone()
    if not result:
        flash(f'Service {service_name} not found', 'error')
        return redirect(url_for('dashboard'))
    
    service_id = result[0]
    
    # Get pending requests for this service (limit to 30 tokens)
    c.execute('''SELECT id FROM queue WHERE service_id = ? AND status = "pending" 
                 ORDER BY created_at ASC LIMIT 30''', (service_id,))
    pending_requests = c.fetchall()
    
    # Approve requests and assign queue numbers with validation tokens
    for request in pending_requests:
        # Sequential queue number for this service (1, 2, 3, 4...)
        c.execute('SELECT COALESCE(MAX(queue_number), 0) + 1 FROM queue WHERE service_id = ? AND DATE(created_at) = DATE("now") AND status != "pending"', (service_id,))
        queue_number = c.fetchone()[0]
        
        # Generate validation token
        validation_token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        
        c.execute('UPDATE queue SET status = "waiting", queue_number = ?, validation_token = ? WHERE id = ?', 
                  (queue_number, validation_token, request[0]))
    
    conn.commit()
    conn.close()
    
    flash(f'Approved {len(pending_requests)} requests for {service_name}', 'success')
    return redirect(url_for('dashboard'))

@app.route('/approve_current_request/<service_name>')
@admin_required
def approve_current_request(service_name):
    import random, string
    
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    
    # Get service ID
    c.execute('SELECT id FROM services WHERE name = ?', (service_name,))
    result = c.fetchone()
    if not result:
        flash(f'Service {service_name} not found', 'error')
        return redirect(url_for('dashboard'))
    
    service_id = result[0]
    
    # Get oldest pending request for this service
    c.execute('''SELECT id FROM queue WHERE service_id = ? AND status = "pending" 
                 ORDER BY created_at ASC LIMIT 1''', (service_id,))
    result = c.fetchone()
    
    if not result:
        flash(f'No pending requests for {service_name}', 'info')
        return redirect(url_for('dashboard'))
    
    queue_id = result[0]
    
    # Get next queue number for this service
    c.execute('SELECT COALESCE(MAX(queue_number), 0) + 1 FROM queue WHERE service_id = ? AND DATE(created_at) = DATE("now") AND status != "pending"', (service_id,))
    queue_number = c.fetchone()[0]
    
    # Generate validation token
    validation_token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    
    # Approve the request
    c.execute('UPDATE queue SET status = "waiting", queue_number = ?, validation_token = ? WHERE id = ?', 
              (queue_number, validation_token, queue_id))
    
    conn.commit()
    conn.close()
    
    flash(f'Approved 1 request for {service_name}. Token: {queue_number}, Validation ID: {validation_token}', 'success')
    return redirect(url_for('dashboard'))

@app.route('/alternative_solution/<service_name>', methods=['POST'])
@admin_required
def alternative_solution(service_name):
    message = request.form.get('message', 'Alternative solution provided')
    
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    
    # Get service ID
    c.execute('SELECT id FROM services WHERE name = ?', (service_name,))
    service_id = c.fetchone()[0]
    
    # Update all pending requests for this service with alternative message
    c.execute('UPDATE queue SET status = "alternative", admin_message = ? WHERE service_id = ? AND status = "pending"', 
              (message, service_id))
    
    conn.commit()
    conn.close()
    
    flash(f'Alternative solution sent for all pending {service_name} requests', 'info')
    return redirect(url_for('dashboard'))

@app.route('/validate_token', methods=['POST'])
@login_required
def validate_token():
    if session['role'] not in ['admin', 'officer']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    validation_id = request.form['validation_id']
    current_time = datetime.now().strftime('%H:%M')
    current_date = datetime.now().strftime('%Y-%m-%d')
    
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    
    # Find queue item with validation token
    c.execute('''SELECT q.id, q.queue_number, s.name, u.username, q.preferred_date, q.preferred_time, q.status
                 FROM queue q 
                 JOIN services s ON q.service_id = s.id 
                 JOIN users u ON q.user_id = u.id 
                 WHERE q.validation_token = ?''', (validation_id,))
    
    result = c.fetchone()
    
    if not result:
        flash('Invalid validation ID', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    queue_id, queue_number, service_name, username, preferred_date, preferred_time, status = result
    
    # Check if appointment date matches
    if preferred_date != current_date:
        flash(f'Appointment date mismatch. Expected: {preferred_date}, Current: {current_date}', 'warning')
        conn.close()
        return redirect(url_for('dashboard'))
    
    # Check if time slot matches (within 1 hour window)
    time_start = preferred_time.split('-')[0]
    time_end = preferred_time.split('-')[1]
    
    if not (time_start <= current_time <= time_end):
        flash(f'Time slot mismatch. Expected: {preferred_time}, Current: {current_time}', 'warning')
        conn.close()
        return redirect(url_for('dashboard'))
    
    # Update status to serving
    c.execute('UPDATE queue SET status = "serving", officer_id = ? WHERE id = ?', 
              (session['user_id'], queue_id))
    conn.commit()
    conn.close()
    
    flash(f'Token validated! Now serving {username} for {service_name}', 'success')
    return redirect(url_for('dashboard'))

@app.route('/clear_queue')
@login_required
def clear_queue():
    if session['role'] not in ['admin', 'officer']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    c.execute('DELETE FROM queue')
    conn.commit()
    conn.close()
    
    flash('All queue items cleared successfully', 'success')
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
    # Check if any admin exists
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
    app.run(host='0.0.0.0', port=port, debug=False)
else:
    init_db()