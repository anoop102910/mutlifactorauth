from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import secrets
import os
from datetime import datetime, timedelta, timezone
import bcrypt
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# Email configuration
email_user = os.environ.get('EMAIL_USER')
email_password = os.environ.get('EMAIL_PASSWORD')

if not email_user or not email_password:
    print("Warning: Email credentials not found in environment variables")
    print("Please set EMAIL_USER and EMAIL_PASSWORD environment variables")
    print("For Gmail, you need to use an App Password, not your regular password")
    print("To create an App Password:")
    print("1. Go to your Google Account settings")
    print("2. Enable 2-Step Verification if not already enabled")
    print("3. Go to Security > App passwords")
    print("4. Generate a new app password for your application")
    print("5. Use that password as EMAIL_PASSWORD")

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = email_user
app.config['MAIL_PASSWORD'] = email_password
app.config['MAIL_DEFAULT_SENDER'] = email_user
app.config['MAIL_DEBUG'] = True
app.config['MAIL_SUPPRESS_SEND'] = False  # Ensure emails are actually sent
app.config['MAIL_ASCII_ATTACHMENTS'] = False  # Handle non-ASCII characters properly

db = SQLAlchemy(app)
mail = Mail(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True)
    verification_token_expires = db.Column(db.DateTime(timezone=True))
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32), nullable=True)

with app.app_context():
    db.drop_all()  # Drop existing tables
    db.create_all()  # Create fresh tables

print(email_user, email_password)


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']

            # Check if user already exists
            if User.query.filter_by(email=email).first():
                flash('Email already registered!', 'error')
                return redirect(url_for('register'))
            
            # Hash password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            # Generate verification token
            verification_token = secrets.token_urlsafe(32)
            verification_token_expires = datetime.now(timezone.utc) + timedelta(hours=24)
            
            # Create new user
            new_user = User(
                username=username,
                email=email,
                password=hashed_password.decode('utf-8'),
                verification_token=verification_token,
                verification_token_expires=verification_token_expires
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            # Send verification email
            try:
                with app.app_context():
                    verification_url = url_for('verify_email', token=verification_token, _external=True)
                    msg = Message(
                        'Verify your email',
                        sender=app.config['MAIL_DEFAULT_SENDER'],
                        recipients=[email]
                    )
                    msg.body = f'Click the following link to verify your email: {verification_url}'
                    mail.send(msg)
                print("Email sent successfully")
            except Exception as e:
                print(f"Detailed email error: {str(e)}")
                print(f"Email config - Server: {app.config['MAIL_SERVER']}, Port: {app.config['MAIL_PORT']}")
                print(f"Email config - TLS: {app.config['MAIL_USE_TLS']}, SSL: {app.config['MAIL_USE_SSL']}")
                print(f"Email config - Username: {app.config['MAIL_USERNAME']}")
                raise  # Re-raise the exception to maintain the original error handling
            
            flash('Registration successful! Please check your email to verify your account.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            if not user.email_verified:
                flash('Please verify your email before logging in.', 'danger')
                return redirect(url_for('login'))
            
            # Generate 6-digit OTP
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
            session['otp'] = otp
            session['otp_email'] = email
            session['otp_expiry'] = datetime.now(timezone.utc) + timedelta(minutes=5)
            
            # Send OTP email
            try:
                msg = Message(
                    'Your Login OTP',
                    sender=app.config['MAIL_DEFAULT_SENDER'],
                    recipients=[email]
                )
                msg.body = f'Your OTP for login is: {otp}\nThis OTP will expire in 5 minutes.'
                mail.send(msg)
                flash('OTP has been sent to your email.', 'success')
                return redirect(url_for('verify_otp'))
            except Exception as e:
                flash('Failed to send OTP. Please try again.', 'error')
                return redirect(url_for('login'))
        
        flash('Invalid email or password!', 'danger')
    
    return render_template('login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp' not in session or 'otp_email' not in session:
        flash('Please login first.', 'error')
        return redirect(url_for('login'))
    
    if datetime.now(timezone.utc) > session['otp_expiry']:
        flash('OTP has expired. Please login again.', 'error')
        session.pop('otp', None)
        session.pop('otp_email', None)
        session.pop('otp_expiry', None)
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        user_otp = request.form['otp']
        if user_otp == session['otp']:
            user = User.query.filter_by(email=session['otp_email']).first()
            session['user_id'] = user.id
            session.pop('otp', None)
            session.pop('otp_email', None)
            session.pop('otp_expiry', None)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP. Please try again.', 'error')
    
    return render_template('verify_otp.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    
    current_time = datetime.now(timezone.utc)
    if not user or user.verification_token_expires.replace(tzinfo=timezone.utc) < current_time:
        flash('Invalid or expired verification token!', 'error')
        return redirect(url_for('register'))
    
    user.email_verified = True
    user.verification_token = None
    user.verification_token_expires = None
    db.session.commit()
    
    flash('Email verified successfully! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True) 