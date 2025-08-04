from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string, send_from_directory
from flask_cors import CORS
import os
import hashlib
import secrets
import time
import requests
import json
from datetime import datetime, timedelta
import uuid
import io
import base64
from urllib.parse import urlparse
import socket
import dns.resolver
import geoip2.database
import geoip2.errors
from user_agents import parse
import bcrypt
from functools import wraps

# Database imports - using PostgreSQL for Vercel
try:
    import psycopg2
    from psycopg2 import Error, sql
    DATABASE_TYPE = "postgresql"
except ImportError:
    # Fallback to SQLite for local development
    import sqlite3
    DATABASE_TYPE = "sqlite"

app = Flask(__name__, static_folder='static')
CORS(app, origins="*")

# Configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "your-default-secret-key-if-not-set")
app.config["SECRET_KEY"] = SECRET_KEY

# Database configuration
if DATABASE_TYPE == "postgresql":
    DATABASE_URL = os.environ.get("DATABASE_URL")
else:
    DATABASE_PATH = os.path.join(os.path.dirname(__file__), "database", "app.db")

def get_db_connection():
    """Get a database connection"""
    if DATABASE_TYPE == "postgresql":
        return psycopg2.connect(DATABASE_URL)
    else:
        return sqlite3.connect(DATABASE_PATH)

# Initialize database
def init_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            # PostgreSQL table creation
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(50) NOT NULL DEFAULT 'member',
                    status VARCHAR(50) NOT NULL DEFAULT 'active',
                    parent_id INTEGER,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP WITH TIME ZONE,
                    subscription_status VARCHAR(50) DEFAULT 'inactive',
                    subscription_expires TIMESTAMP WITH TIME ZONE,
                    FOREIGN KEY (parent_id) REFERENCES users (id)
                );
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_permissions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    permission VARCHAR(255) NOT NULL,
                    granted_by INTEGER,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (granted_by) REFERENCES users (id)
                );
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    session_token VARCHAR(255) UNIQUE NOT NULL,
                    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    user_id INTEGER NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(50) DEFAULT 'active',
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tracking_links (
                    id SERIAL PRIMARY KEY,
                    campaign_id INTEGER,
                    user_id INTEGER NOT NULL,
                    original_url TEXT NOT NULL,
                    tracking_token VARCHAR(255) UNIQUE NOT NULL,
                    recipient_email VARCHAR(255),
                    recipient_name VARCHAR(255),
                    link_status VARCHAR(50) DEFAULT 'active',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP WITH TIME ZONE,
                    click_limit INTEGER DEFAULT 0,
                    click_count INTEGER DEFAULT 0,
                    last_clicked TIMESTAMP WITH TIME ZONE,
                    custom_message TEXT,
                    redirect_delay INTEGER DEFAULT 0,
                    password_protected BOOLEAN DEFAULT FALSE,
                    access_password VARCHAR(255),
                    geo_restrictions TEXT,
                    device_restrictions TEXT,
                    time_restrictions TEXT,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tracking_events (
                    id SERIAL PRIMARY KEY,
                    tracking_token VARCHAR(255) NOT NULL,
                    event_type VARCHAR(100) NOT NULL,
                    ip_address INET,
                    user_agent TEXT,
                    referrer TEXT,
                    country VARCHAR(100),
                    city VARCHAR(100),
                    device_type VARCHAR(100),
                    browser VARCHAR(100),
                    os VARCHAR(100),
                    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    additional_data JSONB,
                    campaign_id INTEGER,
                    user_id INTEGER,
                    is_bot BOOLEAN DEFAULT FALSE,
                    bot_confidence DECIMAL(3,2),
                    bot_reason TEXT,
                    status VARCHAR(50) DEFAULT 'processed',
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );
            """)
            
        else:
            # SQLite table creation (for local development)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'member',
                    status TEXT NOT NULL DEFAULT 'active',
                    parent_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    subscription_status TEXT DEFAULT 'inactive',
                    subscription_expires TIMESTAMP,
                    FOREIGN KEY (parent_id) REFERENCES users (id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_permissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    permission TEXT NOT NULL,
                    granted_by INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (granted_by) REFERENCES users (id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_token TEXT UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS campaigns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    user_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'active',
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tracking_links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id INTEGER,
                    user_id INTEGER NOT NULL,
                    original_url TEXT NOT NULL,
                    tracking_token TEXT UNIQUE NOT NULL,
                    recipient_email TEXT,
                    recipient_name TEXT,
                    link_status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    click_limit INTEGER DEFAULT 0,
                    click_count INTEGER DEFAULT 0,
                    last_clicked TIMESTAMP,
                    custom_message TEXT,
                    redirect_delay INTEGER DEFAULT 0,
                    password_protected INTEGER DEFAULT 0,
                    access_password TEXT,
                    geo_restrictions TEXT,
                    device_restrictions TEXT,
                    time_restrictions TEXT,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tracking_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tracking_token TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    referrer TEXT,
                    country TEXT,
                    city TEXT,
                    device_type TEXT,
                    browser TEXT,
                    os TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    additional_data TEXT,
                    campaign_id INTEGER,
                    user_id INTEGER,
                    is_bot INTEGER DEFAULT 0,
                    bot_confidence REAL,
                    bot_reason TEXT,
                    status TEXT DEFAULT 'processed',
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
        
        # Check if admin user exists
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        else:
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        
        admin_count = cursor.fetchone()[0]
        
        if admin_count == 0:
            # Create default admin user
            admin_password = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            if DATABASE_TYPE == "postgresql":
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role, status)
                    VALUES (%s, %s, %s, %s, %s)
                """, ("admin", "admin@brainlinktracker.com", admin_password, "admin", "active"))
            else:
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role, status)
                    VALUES (?, ?, ?, ?, ?)
                """, ("admin", "admin@brainlinktracker.com", admin_password, "admin", "active"))
            
            print("✅ Default admin user created: admin / admin123")
        
        conn.commit()
        cursor.close()
        conn.close()
        print("✅ Database initialized successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        return False

# Authentication decorator
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.headers.get('Authorization')
        if not session_token:
            return jsonify({'error': 'No authorization token provided'}), 401
        
        if session_token.startswith('Bearer '):
            session_token = session_token[7:]
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            if DATABASE_TYPE == "postgresql":
                cursor.execute("""
                    SELECT u.id, u.username, u.role, u.status 
                    FROM users u 
                    JOIN user_sessions s ON u.id = s.user_id 
                    WHERE s.session_token = %s AND s.expires_at > CURRENT_TIMESTAMP
                """, (session_token,))
            else:
                cursor.execute("""
                    SELECT u.id, u.username, u.role, u.status 
                    FROM users u 
                    JOIN user_sessions s ON u.id = s.user_id 
                    WHERE s.session_token = ? AND s.expires_at > datetime('now')
                """, (session_token,))
            
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if not user:
                return jsonify({'error': 'Invalid or expired session'}), 401
            
            if user[3] != 'active':  # status
                return jsonify({'error': 'Account not active'}), 401
            
            # Add user info to request context
            request.current_user = {
                'id': user[0],
                'username': user[1],
                'role': user[2],
                'status': user[3]
            }
            
            return f(*args, **kwargs)
            
        except Exception as e:
            print(f"Auth error: {e}")
            return jsonify({'error': 'Authentication failed'}), 401
    
    return decorated_function

# Frontend serving routes
@app.route('/')
def serve_frontend():
    """Serve the main frontend page"""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static_files(path):
    """Serve static files"""
    try:
        return send_from_directory(app.static_folder, path)
    except:
        # If file not found, serve index.html for SPA routing
        return send_from_directory(app.static_folder, 'index.html')

# Health check endpoint
@app.route('/api/health')
def health_check():
    """Health check endpoint with database initialization"""
    try:
        # Check if admin user exists and create if needed
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", ("admin",))
        else:
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", ("admin",))
        
        admin_count = cursor.fetchone()[0]
        
        if admin_count == 0:
            # Create admin user
            admin_password = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            if DATABASE_TYPE == "postgresql":
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role, status)
                    VALUES (%s, %s, %s, %s, %s)
                """, ("admin", "admin@brainlinktracker.com", admin_password, "admin", "active"))
            else:
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role, status)
                    VALUES (?, ?, ?, ?, ?)
                """, ("admin", "admin@brainlinktracker.com", admin_password, "admin", "active"))
            
            conn.commit()
            admin_status = "created"
        else:
            admin_status = "exists"
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'status': 'healthy',
            'message': 'Brain Link Tracker API is running',
            'version': '1.0.0',
            'database': DATABASE_TYPE,
            'admin_user': admin_status
        })
        
    except Exception as e:
        return jsonify({
            'status': 'healthy',
            'message': 'Brain Link Tracker API is running',
            'version': '1.0.0',
            'database': DATABASE_TYPE,
            'admin_user_error': str(e)
        })

# Simple admin creation endpoint
@app.route('/api/create-admin')
def create_admin():
    """Force admin user creation"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Delete existing admin if any
        if DATABASE_TYPE == "postgresql":
            cursor.execute("DELETE FROM users WHERE username = %s", ("admin",))
        else:
            cursor.execute("DELETE FROM users WHERE username = ?", ("admin",))
        
        # Create new admin user
        admin_password = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, status)
                VALUES (%s, %s, %s, %s, %s)
            """, ("admin", "admin@brainlinktracker.com", admin_password, "admin", "active"))
        else:
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, status)
                VALUES (?, ?, ?, ?, ?)
            """, ("admin", "admin@brainlinktracker.com", admin_password, "admin", "active"))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'message': 'Admin user created successfully',
            'username': 'admin',
            'password': 'admin123'
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        })

# Authentication endpoints
@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        print(f"Login attempt for username: {username}")
        
        if not username or not password:
            print("Missing username or password")
            return jsonify({'error': 'Username and password required'}), 400
            
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT id, username, password_hash, role, status FROM users WHERE username = %s", (username,))
        else:
            cursor.execute("SELECT id, username, password_hash, role, status FROM users WHERE username = ?", (username,))
        
        user = cursor.fetchone()
        
        if not user:
            print(f"User not found: {username}")
            cursor.close()
            conn.close()
            return jsonify({"error": "Invalid credentials"}), 401
        
        user_id, username, password_hash, role, status = user
        print(f"User found: {username}, role: {role}, status: {status}")
        
        # Check password using bcrypt
        try:
            password_check = bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
            print(f"Password check result: {password_check}")
        except Exception as e:
            print(f"Password check error: {e}")
            cursor.close()
            conn.close()
            return jsonify({"error": "Invalid credentials"}), 401
        
        if not password_check:
            print("Password check failed")
            cursor.close()
            conn.close()
            return jsonify({"error": "Invalid credentials"}), 401
        
        if status != 'active':
            print(f"Account not active: {status}")
            cursor.close()
            conn.close()
            return jsonify({"error": "Account is not active"}), 401
        
        # Create session token
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(days=30)
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                INSERT INTO user_sessions (user_id, session_token, expires_at)
                VALUES (%s, %s, %s)
            """, (user_id, session_token, expires_at))
            
            # Update last login
            cursor.execute("""
                UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s
            """, (user_id,))
        else:
            cursor.execute("""
                INSERT INTO user_sessions (user_id, session_token, expires_at)
                VALUES (?, ?, ?)
            """, (user_id, session_token, expires_at))
            
            # Update last login
            cursor.execute("""
                UPDATE users SET last_login = datetime('now') WHERE id = ?
            """, (user_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print(f"Login successful for user: {username}")
        return jsonify({
            "message": "Login successful",
            "user": {
                "id": user_id,
                "username": username,
                "role": role,
                "status": status
            },
            "session_token": session_token
        }), 200
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": "Login failed"}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """User logout endpoint"""
    try:
        session_token = request.headers.get('Authorization')
        if session_token and session_token.startswith('Bearer '):
            session_token = session_token[7:]
        
        if session_token:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            if DATABASE_TYPE == "postgresql":
                cursor.execute("""
                    UPDATE user_sessions 
                    SET expires_at = CURRENT_TIMESTAMP 
                    WHERE session_token = %s
                """, (session_token,))
            else:
                cursor.execute("""
                    UPDATE user_sessions 
                    SET expires_at = datetime('now') 
                    WHERE session_token = ?
                """, (session_token,))
            
            conn.commit()
            cursor.close()
            conn.close()
        
        return jsonify({"message": "Logout successful"}), 200
        
    except Exception as e:
        print(f"Logout error: {e}")
        return jsonify({"error": "Logout failed"}), 500

@app.route('/api/auth/register', methods=['POST'])
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not username or not email or not password:
            return jsonify({'error': 'Username, email and password required'}), 400
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            if DATABASE_TYPE == "postgresql":
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role, status)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                """, (username.lower(), email.lower(), password_hash, 'member', 'active'))
                user_id = cursor.fetchone()[0]
            else:
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role, status)
                    VALUES (?, ?, ?, ?, ?)
                """, (username.lower(), email.lower(), password_hash, 'member', 'active'))
                user_id = cursor.lastrowid
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return jsonify({
                "message": "Registration successful",
                "user_id": user_id
            }), 201
            
        except Exception as e:
            if "unique" in str(e).lower():
                return jsonify({"error": "Username or email already exists"}), 400
            raise e
            
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({"error": "Registration failed"}), 500

# Campaign management endpoints
@app.route('/api/campaigns', methods=['GET'])
@require_auth
def get_campaigns():
    """Get user campaigns"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        user_id = request.current_user['id']
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                SELECT id, name, description, status, created_at
                FROM campaigns 
                WHERE user_id = %s
                ORDER BY created_at DESC
            """, (user_id,))
        else:
            cursor.execute("""
                SELECT id, name, description, status, created_at
                FROM campaigns 
                WHERE user_id = ?
                ORDER BY created_at DESC
            """, (user_id,))
        
        campaigns = []
        for row in cursor.fetchall():
            campaigns.append({
                'id': row[0],
                'name': row[1],
                'description': row[2],
                'status': row[3],
                'created_at': row[4].isoformat() if row[4] else None
            })
        
        cursor.close()
        conn.close()
        
        return jsonify({"campaigns": campaigns}), 200
        
    except Exception as e:
        print(f"Get campaigns error: {e}")
        return jsonify({"error": "Failed to get campaigns"}), 500

@app.route('/api/campaigns', methods=['POST'])
@require_auth
def create_campaign():
    """Create new campaign"""
    try:
        data = request.get_json()
        name = data.get('name')
        description = data.get('description', '')
        
        if not name:
            return jsonify({'error': 'Campaign name is required'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        user_id = request.current_user['id']
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                INSERT INTO campaigns (name, description, user_id)
                VALUES (%s, %s, %s)
                RETURNING id
            """, (name, description, user_id))
            campaign_id = cursor.fetchone()[0]
        else:
            cursor.execute("""
                INSERT INTO campaigns (name, description, user_id)
                VALUES (?, ?, ?)
            """, (name, description, user_id))
            campaign_id = cursor.lastrowid
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            "message": "Campaign created successfully",
            "campaign_id": campaign_id
        }), 201
        
    except Exception as e:
        print(f"Create campaign error: {e}")
        return jsonify({"error": "Failed to create campaign"}), 500

# Tracking link management endpoints
@app.route('/api/tracking-links', methods=['POST'])
@require_auth
def create_tracking_link():
    """Create new tracking link"""
    try:
        data = request.get_json()
        original_url = data.get('original_url')
        campaign_id = data.get('campaign_id')
        recipient_email = data.get('recipient_email', '')
        recipient_name = data.get('recipient_name', '')
        
        if not original_url:
            return jsonify({'error': 'Original URL is required'}), 400
        
        # Generate tracking token
        tracking_token = secrets.token_urlsafe(16)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        user_id = request.current_user['id']
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                INSERT INTO tracking_links (campaign_id, user_id, original_url, tracking_token, recipient_email, recipient_name)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (campaign_id, user_id, original_url, tracking_token, recipient_email, recipient_name))
            link_id = cursor.fetchone()[0]
        else:
            cursor.execute("""
                INSERT INTO tracking_links (campaign_id, user_id, original_url, tracking_token, recipient_email, recipient_name)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (campaign_id, user_id, original_url, tracking_token, recipient_email, recipient_name))
            link_id = cursor.lastrowid
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # Generate tracking URL
        tracking_url = f"{request.host_url}t/{tracking_token}"
        
        return jsonify({
            "message": "Tracking link created successfully",
            "link_id": link_id,
            "tracking_token": tracking_token,
            "tracking_url": tracking_url
        }), 201
        
    except Exception as e:
        print(f"Create tracking link error: {e}")
        return jsonify({"error": "Failed to create tracking link"}), 500

@app.route('/api/tracking-links', methods=['GET'])
@require_auth
def get_tracking_links():
    """Get user tracking links"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        user_id = request.current_user['id']
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                SELECT tl.id, tl.original_url, tl.tracking_token, tl.recipient_email, 
                       tl.recipient_name, tl.link_status, tl.created_at, tl.click_count,
                       c.name as campaign_name
                FROM tracking_links tl
                LEFT JOIN campaigns c ON tl.campaign_id = c.id
                WHERE tl.user_id = %s
                ORDER BY tl.created_at DESC
            """, (user_id,))
        else:
            cursor.execute("""
                SELECT tl.id, tl.original_url, tl.tracking_token, tl.recipient_email, 
                       tl.recipient_name, tl.link_status, tl.created_at, tl.click_count,
                       c.name as campaign_name
                FROM tracking_links tl
                LEFT JOIN campaigns c ON tl.campaign_id = c.id
                WHERE tl.user_id = ?
                ORDER BY tl.created_at DESC
            """, (user_id,))
        
        links = []
        for row in cursor.fetchall():
            tracking_url = f"{request.host_url}t/{row[2]}"
            links.append({
                'id': row[0],
                'original_url': row[1],
                'tracking_token': row[2],
                'tracking_url': tracking_url,
                'recipient_email': row[3],
                'recipient_name': row[4],
                'link_status': row[5],
                'created_at': row[6].isoformat() if row[6] else None,
                'click_count': row[7] or 0,
                'campaign_name': row[8]
            })
        
        cursor.close()
        conn.close()
        
        return jsonify({"tracking_links": links}), 200
        
    except Exception as e:
        print(f"Get tracking links error: {e}")
        return jsonify({"error": "Failed to get tracking links"}), 500

# Tracking redirect endpoint
@app.route('/t/<tracking_token>')
def track_and_redirect(tracking_token):
    """Track click and redirect to original URL"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get tracking link
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                SELECT id, original_url, click_count, campaign_id, user_id, link_status
                FROM tracking_links 
                WHERE tracking_token = %s
            """, (tracking_token,))
        else:
            cursor.execute("""
                SELECT id, original_url, click_count, campaign_id, user_id, link_status
                FROM tracking_links 
                WHERE tracking_token = ?
            """, (tracking_token,))
        
        link = cursor.fetchone()
        
        if not link:
            cursor.close()
            conn.close()
            return "Link not found", 404
        
        link_id, original_url, click_count, campaign_id, user_id, link_status = link
        
        if link_status != 'active':
            cursor.close()
            conn.close()
            return "Link is no longer active", 410
        
        # Get client info
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', ''))
        user_agent = request.headers.get('User-Agent', '')
        referrer = request.headers.get('Referer', '')
        
        # Parse user agent
        try:
            ua = parse(user_agent)
            device_type = 'mobile' if ua.is_mobile else 'tablet' if ua.is_tablet else 'desktop'
            browser = ua.browser.family
            os = ua.os.family
        except:
            device_type = 'unknown'
            browser = 'unknown'
            os = 'unknown'
        
        # Record tracking event
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                INSERT INTO tracking_events (tracking_token, event_type, ip_address, user_agent, 
                                           referrer, device_type, browser, os, campaign_id, user_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (tracking_token, 'click', ip_address, user_agent, referrer, 
                  device_type, browser, os, campaign_id, user_id))
            
            # Update click count and last clicked
            cursor.execute("""
                UPDATE tracking_links 
                SET click_count = click_count + 1, last_clicked = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (link_id,))
        else:
            cursor.execute("""
                INSERT INTO tracking_events (tracking_token, event_type, ip_address, user_agent, 
                                           referrer, device_type, browser, os, campaign_id, user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (tracking_token, 'click', ip_address, user_agent, referrer, 
                  device_type, browser, os, campaign_id, user_id))
            
            # Update click count and last clicked
            cursor.execute("""
                UPDATE tracking_links 
                SET click_count = click_count + 1, last_clicked = datetime('now')
                WHERE id = ?
            """, (link_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # Redirect to original URL
        return redirect(original_url)
        
    except Exception as e:
        print(f"Tracking error: {e}")
        return "Tracking error", 500

# Analytics endpoints
@app.route('/api/analytics/dashboard', methods=['GET'])
@require_auth
def get_dashboard_analytics():
    """Get dashboard analytics"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        user_id = request.current_user['id']
        
        # Get total campaigns
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT COUNT(*) FROM campaigns WHERE user_id = %s", (user_id,))
        else:
            cursor.execute("SELECT COUNT(*) FROM campaigns WHERE user_id = ?", (user_id,))
        total_campaigns = cursor.fetchone()[0]
        
        # Get total tracking links
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT COUNT(*) FROM tracking_links WHERE user_id = %s", (user_id,))
        else:
            cursor.execute("SELECT COUNT(*) FROM tracking_links WHERE user_id = ?", (user_id,))
        total_links = cursor.fetchone()[0]
        
        # Get total clicks
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT COALESCE(SUM(click_count), 0) FROM tracking_links WHERE user_id = %s", (user_id,))
        else:
            cursor.execute("SELECT COALESCE(SUM(click_count), 0) FROM tracking_links WHERE user_id = ?", (user_id,))
        total_clicks = cursor.fetchone()[0]
        
        # Get recent events
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                SELECT COUNT(*) FROM tracking_events 
                WHERE user_id = %s AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '7 days'
            """, (user_id,))
        else:
            cursor.execute("""
                SELECT COUNT(*) FROM tracking_events 
                WHERE user_id = ? AND timestamp >= datetime('now', '-7 days')
            """, (user_id,))
        recent_events = cursor.fetchone()[0]
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "total_campaigns": total_campaigns,
            "total_links": total_links,
            "total_clicks": total_clicks,
            "recent_events": recent_events
        }), 200
        
    except Exception as e:
        print(f"Analytics error: {e}")
        return jsonify({"error": "Failed to get analytics"}), 500

# Admin endpoints
@app.route('/api/admin/users', methods=['GET'])
@require_auth
def get_all_users():
    """Get all users (admin only)"""
    try:
        if request.current_user['role'] != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                SELECT id, username, email, role, status, created_at, last_login
                FROM users 
                ORDER BY created_at DESC
            """)
        else:
            cursor.execute("""
                SELECT id, username, email, role, status, created_at, last_login
                FROM users 
                ORDER BY created_at DESC
            """)
        
        users = []
        for row in cursor.fetchall():
            users.append({
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'role': row[3],
                'status': row[4],
                'created_at': row[5].isoformat() if row[5] else None,
                'last_login': row[6].isoformat() if row[6] else None
            })
        
        cursor.close()
        conn.close()
        
        return jsonify({"users": users}), 200
        
    except Exception as e:
        print(f"Get users error: {e}")
        return jsonify({"error": "Failed to get users"}), 500

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@require_auth
def update_user(user_id):
    """Update user (admin only)"""
    try:
        if request.current_user['role'] != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        
        data = request.get_json()
        role = data.get('role')
        status = data.get('status')
        
        if not role or not status:
            return jsonify({'error': 'Role and status are required'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                UPDATE users SET role = %s, status = %s WHERE id = %s
            """, (role, status, user_id))
        else:
            cursor.execute("""
                UPDATE users SET role = ?, status = ? WHERE id = ?
            """, (role, status, user_id))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({"message": "User updated successfully"}), 200
        
    except Exception as e:
        print(f"Update user error: {e}")
        return jsonify({"error": "Failed to update user"}), 500

# Simple debug endpoint to test database connection
@app.route('/api/test-db')
def test_db():
    """Simple test endpoint to check database connection"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Try to create admin user if it doesn't exist
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", ("admin",))
        else:
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", ("admin",))
        
        admin_count = cursor.fetchone()[0]
        
        if admin_count == 0:
            # Create admin user
            admin_password = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            if DATABASE_TYPE == "postgresql":
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role, status)
                    VALUES (%s, %s, %s, %s, %s)
                """, ("admin", "admin@brainlinktracker.com", admin_password, "admin", "active"))
            else:
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role, status)
                    VALUES (?, ?, ?, ?, ?)
                """, ("admin", "admin@brainlinktracker.com", admin_password, "admin", "active"))
            
            conn.commit()
            message = "Admin user created"
        else:
            message = "Admin user already exists"
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "status": "success",
            "message": message,
            "admin_count": admin_count,
            "database_type": DATABASE_TYPE
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e),
            "database_type": DATABASE_TYPE
        }), 500

# Debug endpoint to check database status
@app.route('/api/debug/users')
def debug_users():
    """Debug endpoint to check users in database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT id, username, role, status FROM users")
        else:
            cursor.execute("SELECT id, username, role, status FROM users")
        
        users = []
        for row in cursor.fetchall():
            users.append({
                'id': row[0],
                'username': row[1],
                'role': row[2],
                'status': row[3]
            })
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "users": users,
            "database_type": DATABASE_TYPE,
            "database_url_set": bool(os.environ.get("DATABASE_URL")),
            "secret_key_set": bool(os.environ.get("SECRET_KEY"))
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "database_type": DATABASE_TYPE,
            "database_url_set": bool(os.environ.get("DATABASE_URL")),
            "secret_key_set": bool(os.environ.get("SECRET_KEY"))
        }), 500

# Force database initialization endpoint
@app.route('/api/debug/init-db')
def debug_init_db():
    """Debug endpoint to force database initialization"""
    try:
        result = init_db()
        return jsonify({
            "message": "Database initialization completed",
            "success": result
        }), 200
    except Exception as e:
        return jsonify({
            "error": str(e),
            "message": "Database initialization failed"
        }), 500

# Initialize database on startup
with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

