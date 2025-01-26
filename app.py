from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import timedelta

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace_with_a_secure_generated_key'

# Define the absolute path to the database
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "database", "sentri.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DATABASE_PATH}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(minutes=30)

# Ensure the database directory exists
os.makedirs(os.path.join(BASE_DIR, "database"), exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
        else:
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    stats = {
        'total_logs': 1000,  # Placeholder
        'active_devices': 50,  # Placeholder
        'alerts_today': 10  # Placeholder
    }
    return render_template('dashboard.html', user=current_user, stats=stats)

@app.route('/logs')
@login_required
def logs():
    sample_logs = [
        {"id": 1, "timestamp": "2025-01-26 14:00:00", "message": "System booted."},
        {"id": 2, "timestamp": "2025-01-26 14:01:00", "message": "User admin logged in."}
    ]
    return render_template('logs.html', logs=sample_logs)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        current_user.username = request.form['username']
        if request.form['password']:
            current_user.password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        db.session.commit()
        flash('Settings updated successfully!', 'success')
    return render_template('settings.html', user=current_user)

@app.route('/reports')
@login_required
def reports():
    report_data = [
        {"date": "2025-01-25", "total_logs": 500, "alerts": 25},
        {"date": "2025-01-26", "total_logs": 600, "alerts": 30}
    ]
    return render_template('reports.html', reports=report_data)

if __name__ == '__main__':
    # Ensure the certificates directory exists
    CERTS_DIR = os.path.join(BASE_DIR, "certs")
    os.makedirs(CERTS_DIR, exist_ok=True)

    # SSL certificate and key paths
    SSL_CERT_PATH = os.path.join(CERTS_DIR, "cert.pem")
    SSL_KEY_PATH = os.path.join(CERTS_DIR, "key.pem")

    # Initialize the database and create a default user
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            hashed_password = generate_password_hash("password123", method='pbkdf2:sha256')
            default_user = User(username="admin", password=hashed_password)
            db.session.add(default_user)
            db.session.commit()
            print("Default user 'admin' with password 'password123' created.")

    # Run Flask app with SSL
    app.run(ssl_context=(SSL_CERT_PATH, SSL_KEY_PATH), debug=True)
