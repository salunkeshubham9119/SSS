from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secure random key
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['DATABASE'] = 'database.db'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}

# Database helper functions
def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        # Create tables if they don't exist
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('student', 'admin', 'pending_admin')),
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS complaints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                admin_id INTEGER,
                category TEXT NOT NULL,
                subcategory TEXT NOT NULL,
                description TEXT NOT NULL,
                file_path TEXT,
                status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'resolved')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES users (id),
                FOREIGN KEY (admin_id) REFERENCES users (id)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                complaint_id INTEGER NOT NULL,
                admin_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (complaint_id) REFERENCES complaints (id),
                FOREIGN KEY (admin_id) REFERENCES users (id)
            )
        """)
        
        # Create initial admin if none exists
        admin_exists = db.execute('SELECT 1 FROM users WHERE role = "admin" LIMIT 1').fetchone()
        if not admin_exists:
            try:
                db.execute(
                    'INSERT INTO users (username, password, role, full_name, email) '
                    'VALUES (?, ?, ?, ?, ?)',
                    ('admin', generate_password_hash('admin123'), 'admin', 'System Admin', 'admin@example.com')
                )
                db.commit()
                print("Initial admin account created:")
                print("Username: admin")
                print("Password: admin123")
            except sqlite3.Error as e:
                print(f"Error creating initial admin: {str(e)}")
                db.rollback()
        db.commit()
        db.close()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'student':
            flash('Student access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        if session['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return redirect(url_for('login'))
        
        db = get_db()
        try:
            user = db.execute(
                'SELECT * FROM users WHERE username = ?', 
                (username,)
            ).fetchone()
            
            if user and check_password_hash(user['password'], password):
                if user['role'] == 'pending_admin':
                    flash('Your admin account is pending approval', 'info')
                    return redirect(url_for('login'))
                
                session.clear()
                session.update({
                    'user_id': user['id'],
                    'username': user['username'],
                    'role': user['role'],
                    'full_name': user['full_name']
                })
                
                flash(f'Welcome back, {user["full_name"]}!', 'success')
                return redirect(url_for('home'))
            
            flash('Invalid username or password', 'danger')
        except sqlite3.Error as e:
            flash('Database error occurred during login', 'danger')
        finally:
            db.close()
    
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        
        if not all([username, password, full_name, email]):
            flash('All fields are required', 'danger')
            return redirect(url_for('register'))
        
        db = get_db()
        try:
            db.execute(
                'INSERT INTO users (username, password, role, full_name, email) '
                'VALUES (?, ?, ?, ?, ?)',
                (username, generate_password_hash(password), 'student', full_name, email)
            )
            db.commit()
            flash('Registration successful. Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'danger')
        except sqlite3.Error as e:
            flash(f'Database error occurred: {str(e)}', 'danger')
        finally:
            db.close()
    
    return render_template('auth/register.html')

@app.route('/register/admin', methods=['GET', 'POST'])
def register_admin():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        
        if not all([username, password, full_name, email]):
            flash('All fields are required', 'danger')
            return redirect(url_for('register_admin'))
        
        db = get_db()
        try:
            db.execute(
                'INSERT INTO users (username, password, role, full_name, email) '
                'VALUES (?, ?, ?, ?, ?)',
                (username, generate_password_hash(password), 'pending_admin', full_name, email)
            )
            db.commit()
            flash('Admin registration request submitted. Please wait for approval.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'danger')
        except sqlite3.Error as e:
            flash(f'Database error occurred: {str(e)}', 'danger')
        finally:
            db.close()
    
    return render_template('auth/register_admin.html')

@app.route('/admin/approvals')
@admin_required
def admin_approvals():
    if session['username'] != 'admin':  # Only system admin can access
        flash('Only system admin can access this page', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    db = get_db()
    try:
        pending_admins = db.execute(
            'SELECT * FROM users WHERE role = "pending_admin"'
        ).fetchall()
        return render_template('admin/approvals.html', pending_admins=pending_admins)
    except sqlite3.Error as e:
        flash('Error retrieving pending admins', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        db.close()

@app.route('/admin/approve/<int:user_id>')
@admin_required
def approve_admin(user_id):
    if session['username'] != 'admin':  # Only system admin can approve
        flash('Only system admin can approve admins', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    db = get_db()
    try:
        db.execute(
            'UPDATE users SET role = "admin" WHERE id = ?',
            (user_id,)
        )
        db.commit()
        flash('User approved as admin', 'success')
    except sqlite3.Error as e:
        flash(f'Error approving admin: {str(e)}', 'danger')
    finally:
        db.close()
    return redirect(url_for('admin_approvals'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('login'))

# Student routes
@app.route('/student/dashboard')
@student_required
def student_dashboard():
    db = get_db()
    try:
        complaints = db.execute(
            'SELECT c.*, u.full_name as admin_name FROM complaints c '
            'LEFT JOIN users u ON c.admin_id = u.id '
            'WHERE c.student_id = ? '
            'ORDER BY CASE c.status '
            "WHEN 'pending' THEN 1 "
            "WHEN 'in_progress' THEN 2 "
            "WHEN 'resolved' THEN 3 "
            'END, c.created_at DESC',
            (session['user_id'],)
        ).fetchall()
        return render_template('student/dashboard.html', complaints=complaints)
    except sqlite3.Error as e:
        flash(f'Error retrieving complaints: {str(e)}', 'danger')
        return redirect(url_for('home'))
    finally:
        db.close()

@app.route('/student/complaint/new', methods=['GET', 'POST'])
@student_required
def new_complaint():
    if request.method == 'POST':
        category = request.form.get('category', '').strip()
        subcategory = request.form.get('subcategory', '').strip()
        description = request.form.get('description', '').strip()
        admin_id = request.form.get('admin_id', '').strip() or None
        
        if not all([category, subcategory, description]):
            flash('All required fields must be filled', 'danger')
            return redirect(url_for('new_complaint'))
        
        file_path = None
        if 'file' in request.files:
            file = request.files['file']
            if file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(f"{datetime.now().timestamp()}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                file_path = filename
        
        db = get_db()
        try:
            db.execute(
                'INSERT INTO complaints (student_id, admin_id, category, subcategory, description, file_path) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (session['user_id'], admin_id, category, subcategory, description, file_path))
            db.commit()
            flash('Complaint submitted successfully', 'success')
            return redirect(url_for('student_dashboard'))
        except sqlite3.Error as e:
            flash(f'Error submitting complaint: {str(e)}', 'danger')
        finally:
            db.close()
        
    db = get_db()
    try:
        admins = db.execute(
            'SELECT id, full_name FROM users WHERE role = "admin"'
        ).fetchall()
        return render_template('student/complaint.html', admins=admins, mode='new')
    except sqlite3.Error as e:
        flash(f'Error retrieving admin list: {str(e)}', 'danger')
        return redirect(url_for('student_dashboard'))
    finally:
        db.close()

@app.route('/student/complaint/<int:complaint_id>')
@student_required
def view_complaint(complaint_id):
    db = get_db()
    try:
        complaint = db.execute(
            'SELECT c.*, u.full_name as admin_name FROM complaints c '
            'LEFT JOIN users u ON c.admin_id = u.id '
            'WHERE c.id = ? AND c.student_id = ?',
            (complaint_id, session['user_id'])
        ).fetchone()
        
        if not complaint:
            flash('Complaint not found', 'danger')
            return redirect(url_for('student_dashboard'))
        
        feedback = db.execute(
            'SELECT f.*, u.full_name as admin_name FROM feedback f '
            'JOIN users u ON f.admin_id = u.id '
            'WHERE f.complaint_id = ? '
            'ORDER BY f.created_at DESC',
            (complaint_id,)
        ).fetchall()
        
        return render_template('student/complaint.html', 
                            complaint=complaint, 
                            feedback=feedback,
                            mode='view')
    except sqlite3.Error as e:
        flash(f'Error retrieving complaint: {str(e)}', 'danger')
        return redirect(url_for('student_dashboard'))
    finally:
        db.close()

# Admin dashboard route (only one definition)
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    db = get_db()
    try:
        complaints = db.execute(
            'SELECT c.*, u.full_name as student_name FROM complaints c '
            'JOIN users u ON c.student_id = u.id '
            'WHERE c.admin_id = ? '
            'ORDER BY CASE c.status '
            "WHEN 'pending' THEN 1 "
            "WHEN 'in_progress' THEN 2 "
            "WHEN 'resolved' THEN 3 "
            'END, c.created_at DESC',
            (session['user_id'],)
        ).fetchall()
        
        # Always get pending admins count
        pending_admins_count = db.execute(
            'SELECT COUNT(*) as count FROM users WHERE role = "pending_admin"'
        ).fetchone()['count']
        
        # Also get the actual pending admins list
        pending_admins = db.execute(
            'SELECT * FROM users WHERE role = "pending_admin"'
        ).fetchall()
        
        return render_template('admin/dashboard.html', 
                            complaints=complaints,
                            pending_admins_count=pending_admins_count,
                            pending_admins=pending_admins)
    except sqlite3.Error as e:
        flash(f'Error retrieving complaints: {str(e)}', 'danger')
        return redirect(url_for('home'))
    finally:
        db.close()

@app.route('/admin/complaint/<int:complaint_id>', methods=['GET', 'POST'])
@admin_required
def admin_view_complaint(complaint_id):
    db = get_db()
    try:
        complaint = db.execute(
            'SELECT c.*, u.full_name as student_name FROM complaints c '
            'JOIN users u ON c.student_id = u.id '
            'WHERE c.id = ? AND c.admin_id = ?',
            (complaint_id, session['user_id'])
        ).fetchone()
        
        if not complaint:
            flash('Complaint not found or not assigned to you', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        if request.method == 'POST':
            status = request.form.get('status')
            feedback_msg = request.form.get('feedback', '').strip()
            
            if status not in ['pending', 'in_progress', 'resolved']:
                flash('Invalid status', 'danger')
                return redirect(url_for('admin_view_complaint', complaint_id=complaint_id))
            
            try:
                db.execute(
                    'UPDATE complaints SET status = ?, updated_at = CURRENT_TIMESTAMP '
                    'WHERE id = ?',
                    (status, complaint_id)
                )
                
                if feedback_msg:
                    db.execute(
                        'INSERT INTO feedback (complaint_id, admin_id, message) '
                        'VALUES (?, ?, ?)',
                        (complaint_id, session['user_id'], feedback_msg)
                    )
                
                db.commit()
                flash('Complaint updated successfully', 'success')
            except sqlite3.Error as e:
                flash(f'Error updating complaint: {str(e)}', 'danger')
            
            return redirect(url_for('admin_view_complaint', complaint_id=complaint_id))
        
        feedback = db.execute(
            'SELECT f.*, u.full_name as admin_name FROM feedback f '
            'JOIN users u ON f.admin_id = u.id '
            'WHERE f.complaint_id = ? '
            'ORDER BY f.created_at DESC',
            (complaint_id,)
        ).fetchall()
        
        return render_template('admin/complaint.html', 
                            complaint=complaint, 
                            feedback=feedback)
    except sqlite3.Error as e:
        flash(f'Error retrieving complaint: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        db.close()

# File download route
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    # Create upload folder if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Initialize database
    with app.app_context():
        init_db()
    
    app.run(debug=True)