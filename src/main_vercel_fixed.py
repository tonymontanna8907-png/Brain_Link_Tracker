from flask import Flask, request, jsonify, send_file, redirect, render_template_string, send_from_directory
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
SECRET_KEY = os.environ.get("SECRET_KEY", "ej5B3Amppi4gjpbC65te6rJuvJzgVCWW_xfB-ZLR1TE")
app.config['SECRET_KEY'] = SECRET_KEY

# Database configuration
if DATABASE_TYPE == "postgresql":
    DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://neondb_owner:npg_0y9XMKzHCBsN@ep-blue-resonance-add39g5q-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require")
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
                    status VARCHAR(50) NOT NULL DEFAULT 'pending',
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
                    original_url VARCHAR(2048) NOT NULL,
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
                    password_protected INTEGER DEFAULT 0,
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
                    event_type VARCHAR(50) NOT NULL,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    referrer TEXT,
                    country VARCHAR(10),
                    city VARCHAR(255),
                    device_type VARCHAR(50),
                    browser VARCHAR(100),
                    os VARCHAR(100),
                    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    additional_data TEXT,
                    campaign_id INTEGER,
                    user_id INTEGER,
                    is_bot INTEGER DEFAULT 0,
                    bot_confidence REAL,
                    bot_reason TEXT,
                    status VARCHAR(50) DEFAULT 'processed',
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );
            """)
        else:
            # SQLite table creation
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'member',
                    status TEXT NOT NULL DEFAULT 'pending',
                    parent_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    subscription_status TEXT DEFAULT 'inactive',
                    subscription_expires TIMESTAMP,
                    FOREIGN KEY (parent_id) REFERENCES users (id)
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
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'Brain Link Tracker API is running',
        'version': '1.0.0',
        'database': DATABASE_TYPE
    })

# Authentication endpoints
@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT id, username, password_hash, role, status FROM users WHERE username = %s", (username,))
        else:
            cursor.execute("SELECT id, username, password_hash, role, status FROM users WHERE username = ?", (username,))
        
        user = cursor.fetchone()
        
        if not user:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401
        
        user_id, username, password_hash, role, status = user
        
        if status != 'active':
            cursor.close()
            conn.close()
            return jsonify({'error': 'Account not active'}), 401
        
        if not bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
            cursor.close()
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Create session
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(days=7)
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                INSERT INTO user_sessions (user_id, session_token, expires_at)
                VALUES (%s, %s, %s)
            """, (user_id, session_token, expires_at))
            
            cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s", (user_id,))
        else:
            cursor.execute("""
                INSERT INTO user_sessions (user_id, session_token, expires_at)
                VALUES (?, ?, ?)
            """, (user_id, session_token, expires_at))
            
            cursor.execute("UPDATE users SET last_login = datetime('now') WHERE id = ?", (user_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'message': 'Login successful',
            'token': session_token,
            'user': {
                'id': user_id,
                'username': username,
                'role': role
            }
        })
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    """User logout endpoint"""
    try:
        session_token = request.headers.get('Authorization')
        if session_token.startswith('Bearer '):
            session_token = session_token[7:]
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("DELETE FROM user_sessions WHERE session_token = %s", (session_token,))
        else:
            cursor.execute("DELETE FROM user_sessions WHERE session_token = ?", (session_token,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Logout successful'})
        
    except Exception as e:
        print(f"Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500

# User management endpoints
@app.route('/api/auth/register', methods=['POST'])
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not username or not email or not password:
            return jsonify({'error': 'Username, email, and password required'}), 400
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            if DATABASE_TYPE == "postgresql":
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role, status)
                    VALUES (%s, %s, %s, %s, %s)
                """, (username, email, password_hash, "member", "pending"))
            else:
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role, status)
                    VALUES (?, ?, ?, ?, ?)
                """, (username, email, password_hash, "member", "pending"))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return jsonify({'message': 'Registration successful'})
            
        except Exception as e:
            cursor.close()
            conn.close()
            if 'UNIQUE constraint failed' in str(e) or 'duplicate key' in str(e):
                return jsonify({'error': 'Username or email already exists'}), 400
            raise e
            
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

# User management endpoints
@app.route('/api/users', methods=['GET'])
@require_auth
def get_users():
    """Get all users with detailed information (admin only)"""
    try:
        if request.current_user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                SELECT u.id, u.username, u.email, u.role, u.status, u.created_at, u.last_login,
                       COUNT(DISTINCT c.id) as campaign_count,
                       COUNT(DISTINCT tl.id) as link_count,
                       COUNT(DISTINCT te.id) as total_clicks,
                       MAX(te.timestamp) as last_activity
                FROM users u
                LEFT JOIN campaigns c ON u.id = c.user_id
                LEFT JOIN tracking_links tl ON u.id = tl.user_id
                LEFT JOIN tracking_events te ON u.id = te.user_id AND te.event_type = 'click'
                GROUP BY u.id, u.username, u.email, u.role, u.status, u.created_at, u.last_login
                ORDER BY u.created_at DESC
            """)
        else:
            cursor.execute("""
                SELECT u.id, u.username, u.email, u.role, u.status, u.created_at, u.last_login,
                       COUNT(DISTINCT c.id) as campaign_count,
                       COUNT(DISTINCT tl.id) as link_count,
                       COUNT(DISTINCT te.id) as total_clicks,
                       MAX(te.timestamp) as last_activity
                FROM users u
                LEFT JOIN campaigns c ON u.id = c.user_id
                LEFT JOIN tracking_links tl ON u.id = tl.user_id
                LEFT JOIN tracking_events te ON u.id = te.user_id AND te.event_type = 'click'
                GROUP BY u.id, u.username, u.email, u.role, u.status, u.created_at, u.last_login
                ORDER BY u.created_at DESC
            """)
        
        users = cursor.fetchall()
        cursor.close()
        conn.close()
        
        user_list = []
        for user in users:
            user_list.append({
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'role': user[3],
                'status': user[4],
                'created_at': user[5],
                'last_login': user[6],
                'campaign_count': user[7] or 0,
                'link_count': user[8] or 0,
                'total_clicks': user[9] or 0,
                'last_activity': user[10]
            })
        
        return jsonify(user_list)
        
    except Exception as e:
        print(f"Get users error: {e}")
        return jsonify({'error': 'Failed to fetch users'}), 500

@app.route('/api/users/<int:user_id>/approve', methods=['POST'])
@require_auth
def approve_user(user_id):
    """Approve a user account (admin only)"""
    try:
        if request.current_user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                UPDATE users SET status = 'active' WHERE id = %s AND status = 'pending'
            """, (user_id,))
        else:
            cursor.execute("""
                UPDATE users SET status = 'active' WHERE id = ? AND status = 'pending'
            """, (user_id,))
        
        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return jsonify({'error': 'User not found or already approved'}), 404
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'User approved successfully'})
        
    except Exception as e:
        print(f"Approve user error: {e}")
        return jsonify({'error': 'Failed to approve user'}), 500

@app.route('/api/users/change-password', methods=['POST'])
@require_auth
def change_password():
    """Change user password"""
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Current password and new password are required'}), 400
        
        if len(new_password) < 6:
            return jsonify({'error': 'New password must be at least 6 characters long'}), 400
        
        user_id = request.current_user['id']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get current password hash
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT password_hash FROM users WHERE id = %s", (user_id,))
        else:
            cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
        
        result = cursor.fetchone()
        if not result:
            cursor.close()
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        current_password_hash = result[0]
        
        # Verify current password
        if not bcrypt.checkpw(current_password.encode('utf-8'), current_password_hash.encode('utf-8')):
            cursor.close()
            conn.close()
            return jsonify({'error': 'Current password is incorrect'}), 400
        
        # Hash new password
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update password
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                UPDATE users SET password_hash = %s, updated_at = CURRENT_TIMESTAMP 
                WHERE id = %s
            """, (new_password_hash, user_id))
        else:
            cursor.execute("""
                UPDATE users SET password_hash = ?, updated_at = datetime('now') 
                WHERE id = ?
            """, (new_password_hash, user_id))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Password changed successfully'})
        
    except Exception as e:
        print(f"Change password error: {e}")
        return jsonify({'error': 'Failed to change password'}), 500

# Campaign management endpoints
@app.route('/api/campaigns', methods=['GET'])
@require_auth
def get_campaigns():
    """Get campaigns for current user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                SELECT id, name, description, status, created_at
                FROM campaigns
                WHERE user_id = %s
                ORDER BY created_at DESC
            """, (request.current_user['id'],))
        else:
            cursor.execute("""
                SELECT id, name, description, status, created_at
                FROM campaigns
                WHERE user_id = ?
                ORDER BY created_at DESC
            """, (request.current_user['id'],))
        
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
        return jsonify({'campaigns': campaigns})
        
    except Exception as e:
        print(f"Get campaigns error: {e}")
        return jsonify({'error': 'Failed to fetch campaigns'}), 500

@app.route('/api/campaigns', methods=['POST'])
@require_auth
def create_campaign():
    """Create a new campaign"""
    try:
        data = request.get_json()
        name = data.get('name')
        description = data.get('description', '')
        
        if not name:
            return jsonify({'error': 'Campaign name is required'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                INSERT INTO campaigns (name, description, user_id)
                VALUES (%s, %s, %s)
                RETURNING id, created_at
            """, (name, description, request.current_user['id']))
            result = cursor.fetchone()
            campaign_id = result[0]
            created_at = result[1]
        else:
            cursor.execute("""
                INSERT INTO campaigns (name, description, user_id)
                VALUES (?, ?, ?)
            """, (name, description, request.current_user['id']))
            campaign_id = cursor.lastrowid
            cursor.execute("SELECT created_at FROM campaigns WHERE id = ?", (campaign_id,))
            created_at = cursor.fetchone()[0]
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'message': 'Campaign created successfully',
            'campaign': {
                'id': campaign_id,
                'name': name,
                'description': description,
                'status': 'active',
                'created_at': created_at.isoformat() if created_at else None
            }
        }), 201
        
    except Exception as e:
        print(f"Create campaign error: {e}")
        return jsonify({'error': 'Failed to create campaign'}), 500

# Tracking link generation endpoints
@app.route('/api/tracking-links', methods=['POST'])
@require_auth
def create_tracking_link():
    """Create a new tracking link"""
    try:
        data = request.get_json()
        campaign_id = data.get('campaign_id')
        original_url = data.get('original_url')
        recipient_email = data.get('recipient_email', '')
        recipient_name = data.get('recipient_name', '')
        
        if not original_url:
            return jsonify({'error': 'Original URL is required'}), 400
        
        # Generate unique tracking token
        tracking_token = secrets.token_urlsafe(16)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                INSERT INTO tracking_links (campaign_id, user_id, original_url, tracking_token, recipient_email, recipient_name)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id, created_at
            """, (campaign_id, request.current_user['id'], original_url, tracking_token, recipient_email, recipient_name))
            result = cursor.fetchone()
            link_id = result[0]
            created_at = result[1]
        else:
            cursor.execute("""
                INSERT INTO tracking_links (campaign_id, user_id, original_url, tracking_token, recipient_email, recipient_name)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (campaign_id, request.current_user['id'], original_url, tracking_token, recipient_email, recipient_name))
            link_id = cursor.lastrowid
            cursor.execute("SELECT created_at FROM tracking_links WHERE id = ?", (link_id,))
            created_at = cursor.fetchone()[0]
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # Generate tracking URLs
        base_url = request.host_url.rstrip('/')
        tracking_url = f"{base_url}/track/click/{tracking_token}"
        pixel_url = f"{base_url}/track/pixel/{tracking_token}"
        
        return jsonify({
            'message': 'Tracking link created successfully',
            'tracking_link': {
                'id': link_id,
                'tracking_token': tracking_token,
                'original_url': original_url,
                'tracking_url': tracking_url,
                'pixel_url': pixel_url,
                'recipient_email': recipient_email,
                'recipient_name': recipient_name,
                'created_at': created_at.isoformat() if created_at else None
            }
        }), 201
        
    except Exception as e:
        print(f"Create tracking link error: {e}")
        return jsonify({'error': 'Failed to create tracking link'}), 500

@app.route('/api/tracking-links', methods=['GET'])
@require_auth
def get_tracking_links():
    """Get tracking links for current user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                SELECT tl.id, tl.tracking_token, tl.original_url, tl.recipient_email, 
                       tl.recipient_name, tl.link_status, tl.created_at, tl.click_count,
                       c.name as campaign_name
                FROM tracking_links tl
                LEFT JOIN campaigns c ON tl.campaign_id = c.id
                WHERE tl.user_id = %s
                ORDER BY tl.created_at DESC
            """, (request.current_user['id'],))
        else:
            cursor.execute("""
                SELECT tl.id, tl.tracking_token, tl.original_url, tl.recipient_email, 
                       tl.recipient_name, tl.link_status, tl.created_at, tl.click_count,
                       c.name as campaign_name
                FROM tracking_links tl
                LEFT JOIN campaigns c ON tl.campaign_id = c.id
                WHERE tl.user_id = ?
                ORDER BY tl.created_at DESC
            """, (request.current_user['id'],))
        
        links = []
        base_url = request.host_url.rstrip('/')
        
        for row in cursor.fetchall():
            tracking_url = f"{base_url}/track/click/{row[1]}"
            pixel_url = f"{base_url}/track/pixel/{row[1]}"
            
            links.append({
                'id': row[0],
                'tracking_token': row[1],
                'original_url': row[2],
                'tracking_url': tracking_url,
                'pixel_url': pixel_url,
                'recipient_email': row[3],
                'recipient_name': row[4],
                'link_status': row[5],
                'created_at': row[6].isoformat() if row[6] else None,
                'click_count': row[7] or 0,
                'campaign_name': row[8]
            })
        
        cursor.close()
        conn.close()
        return jsonify({'tracking_links': links})
        
    except Exception as e:
        print(f"Get tracking links error: {e}")
        return jsonify({'error': 'Failed to fetch tracking links'}), 500

# Generate tracking pixel (1x1 transparent PNG)
def generate_pixel():
    # 1x1 transparent PNG in base64
    pixel_data = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==')
    return pixel_data

# Tracking endpoints
@app.route('/track/pixel/<tracking_token>')
def track_pixel(tracking_token):
    """Track email open via pixel"""
    try:
        # Log the tracking event
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get tracking link info
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                SELECT tl.campaign_id, tl.user_id, tl.original_url
                FROM tracking_links tl
                WHERE tl.tracking_token = %s
            """, (tracking_token,))
        else:
            cursor.execute("""
                SELECT tl.campaign_id, tl.user_id, tl.original_url
                FROM tracking_links tl
                WHERE tl.tracking_token = ?
            """, (tracking_token,))
        
        link_info = cursor.fetchone()
        
        if link_info:
            campaign_id, user_id, original_url = link_info
            
            # Log tracking event
            user_agent = request.headers.get('User-Agent', '')
            ip_address = request.remote_addr
            
            if DATABASE_TYPE == "postgresql":
                cursor.execute("""
                    INSERT INTO tracking_events (tracking_token, event_type, ip_address, user_agent, campaign_id, user_id)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (tracking_token, 'pixel_view', ip_address, user_agent, campaign_id, user_id))
            else:
                cursor.execute("""
                    INSERT INTO tracking_events (tracking_token, event_type, ip_address, user_agent, campaign_id, user_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (tracking_token, 'pixel_view', ip_address, user_agent, campaign_id, user_id))
            
            conn.commit()
        
        cursor.close()
        conn.close()
        
        # Return 1x1 transparent pixel
        pixel_data = generate_pixel()
        return send_file(
            io.BytesIO(pixel_data),
            mimetype='image/png',
            as_attachment=False
        )
        
    except Exception as e:
        print(f"Pixel tracking error: {e}")
        # Still return pixel even if tracking fails
        pixel_data = generate_pixel()
        return send_file(
            io.BytesIO(pixel_data),
            mimetype='image/png',
            as_attachment=False
        )

@app.route('/track/click/<tracking_token>')
def track_click(tracking_token):
    """Track link click and redirect"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get tracking link info
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                SELECT tl.campaign_id, tl.user_id, tl.original_url, tl.click_count
                FROM tracking_links tl
                WHERE tl.tracking_token = %s
            """, (tracking_token,))
        else:
            cursor.execute("""
                SELECT tl.campaign_id, tl.user_id, tl.original_url, tl.click_count
                FROM tracking_links tl
                WHERE tl.tracking_token = ?
            """, (tracking_token,))
        
        link_info = cursor.fetchone()
        
        if not link_info:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Tracking link not found'}), 404
        
        campaign_id, user_id, original_url, click_count = link_info
        
        # Log tracking event
        user_agent = request.headers.get('User-Agent', '')
        ip_address = request.remote_addr
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                INSERT INTO tracking_events (tracking_token, event_type, ip_address, user_agent, campaign_id, user_id)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (tracking_token, 'click', ip_address, user_agent, campaign_id, user_id))
            
            # Update click count
            cursor.execute("""
                UPDATE tracking_links 
                SET click_count = COALESCE(click_count, 0) + 1, last_clicked = CURRENT_TIMESTAMP
                WHERE tracking_token = %s
            """, (tracking_token,))
        else:
            cursor.execute("""
                INSERT INTO tracking_events (tracking_token, event_type, ip_address, user_agent, campaign_id, user_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (tracking_token, 'click', ip_address, user_agent, campaign_id, user_id))
            
            # Update click count
            cursor.execute("""
                UPDATE tracking_links 
                SET click_count = COALESCE(click_count, 0) + 1, last_clicked = datetime('now')
                WHERE tracking_token = ?
            """, (tracking_token,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # Redirect to original URL
        return redirect(original_url)
        
    except Exception as e:
        print(f"Click tracking error: {e}")
        return jsonify({'error': 'Tracking failed'}), 500

# Analytics endpoints
@app.route('/api/analytics/overview')
@require_auth
def get_analytics_overview():
    """Get analytics overview for current user"""
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
            cursor.execute("""
                SELECT COUNT(*) FROM tracking_events 
                WHERE user_id = %s AND event_type = 'click'
            """, (user_id,))
        else:
            cursor.execute("""
                SELECT COUNT(*) FROM tracking_events 
                WHERE user_id = ? AND event_type = 'click'
            """, (user_id,))
        total_clicks = cursor.fetchone()[0]
        
        # Get total pixel views
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                SELECT COUNT(*) FROM tracking_events 
                WHERE user_id = %s AND event_type = 'pixel_view'
            """, (user_id,))
        else:
            cursor.execute("""
                SELECT COUNT(*) FROM tracking_events 
                WHERE user_id = ? AND event_type = 'pixel_view'
            """, (user_id,))
        total_pixel_views = cursor.fetchone()[0]
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'total_campaigns': total_campaigns,
            'total_links': total_links,
            'total_clicks': total_clicks,
            'total_pixel_views': total_pixel_views
        })
        
    except Exception as e:
        print(f"Analytics overview error: {e}")
        return jsonify({'error': 'Failed to fetch analytics'}), 500

@app.route('/api/analytics/clicks', methods=['GET'])
@require_auth
def get_click_analytics():
    """Get detailed click analytics for current user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                SELECT te.tracking_token, te.ip_address, te.user_agent, te.timestamp,
                       tl.original_url, c.name as campaign_name,
                       te.event_type
                FROM tracking_events te
                LEFT JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
                LEFT JOIN campaigns c ON te.campaign_id = c.id
                WHERE te.user_id = %s AND te.event_type = 'click'
                ORDER BY te.timestamp DESC
                LIMIT 100
            """, (request.current_user['id'],))
        else:
            cursor.execute("""
                SELECT te.tracking_token, te.ip_address, te.user_agent, te.timestamp,
                       tl.original_url, c.name as campaign_name,
                       te.event_type
                FROM tracking_events te
                LEFT JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
                LEFT JOIN campaigns c ON te.campaign_id = c.id
                WHERE te.user_id = ? AND te.event_type = 'click'
                ORDER BY te.timestamp DESC
                LIMIT 100
            """, (request.current_user['id'],))
        
        clicks = cursor.fetchall()
        cursor.close()
        conn.close()
        
        # Process click data to include geolocation and ISP info
        click_analytics = []
        for click in clicks:
            tracking_token, ip_address, user_agent, timestamp, original_url, campaign_name, event_type = click
            
            # Parse user agent for better display
            parsed_ua = parse(user_agent) if user_agent else None
            
            # For demo purposes, we'll add mock geolocation data
            # In production, you would use a real GeoIP service
            country = "United States"
            state = "California"
            isp = "Comcast Cable"
            
            # Try to get more specific location based on IP patterns
            if ip_address:
                if ip_address.startswith('192.168') or ip_address.startswith('10.') or ip_address.startswith('172.'):
                    country = "Local Network"
                    state = "Private"
                    isp = "Local ISP"
                elif '110.191.241' in ip_address:
                    country = "Philippines"
                    state = "Metro Manila"
                    isp = "PLDT Inc."
            
            click_analytics.append({
                'tracking_token': tracking_token,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'browser': f"{parsed_ua.browser.family} {parsed_ua.browser.version_string}" if parsed_ua else "Unknown",
                'os': f"{parsed_ua.os.family} {parsed_ua.os.version_string}" if parsed_ua else "Unknown",
                'timestamp': timestamp.isoformat() if timestamp else None,
                'original_url': original_url,
                'campaign_name': campaign_name or 'N/A',
                'country': country,
                'state': state,
                'isp': isp,
                'event_type': event_type
            })
        
        return jsonify({
            'clicks': click_analytics,
            'total_clicks': len(click_analytics)
        })
        
    except Exception as e:
        print(f"Click analytics error: {e}")
        return jsonify({'error': 'Failed to fetch click analytics'}), 500

# Health check endpointerrorhandler(404)
def not_found(error):
    return send_from_directory(app.static_folder, 'index.html')

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    init_db()
    print(f"✅ Brain Link Tracker starting with {DATABASE_TYPE} database...")
    app.run(host='0.0.0.0', port=5000, debug=True)

