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

app = Flask(__name__, static_folder=\'static\')
CORS(app, origins="*")

# Configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "ej5B3Amppi4gjpbC65te6rJuvJzgVCWW_xfB-ZLR1TE")
app.config[\'SECRET_KEY\'] = SECRET_KEY

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
                    role VARCHAR(50) NOT NULL DEFAULT \'member\',
                    status VARCHAR(50) NOT NULL DEFAULT \'pending\',
                    parent_id INTEGER,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP WITH TIME ZONE,
                    subscription_status VARCHAR(50) DEFAULT \'inactive\',
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
                    status VARCHAR(50) DEFAULT \'active\',
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
                    link_status VARCHAR(50) DEFAULT \'active\',
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
                    status VARCHAR(50) DEFAULT \'processed\',
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );
            """)
        else:
            # SQLite table creation
            cursor.execute(\'\'\'
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT \'member\',
                    status TEXT NOT NULL DEFAULT \'pending\',
                    parent_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    subscription_status TEXT DEFAULT \'inactive\',
                    subscription_expires TIMESTAMP,
                    FOREIGN KEY (parent_id) REFERENCES users (id)
                )
            \'\'\')
            
            cursor.execute(\'\'\'
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_token TEXT UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            \'\'\')
            
            cursor.execute(\'\'\'
                CREATE TABLE IF NOT EXISTS campaigns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    user_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT \'active\',
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            \'\'\')
            
            cursor.execute(\'\'\'
                CREATE TABLE IF NOT EXISTS tracking_links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id INTEGER,
                    user_id INTEGER NOT NULL,
                    original_url TEXT NOT NULL,
                    tracking_token TEXT UNIQUE NOT NULL,
                    recipient_email TEXT,
                    recipient_name TEXT,
                    link_status TEXT DEFAULT \'active\',
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
            \'\'\')
            
            cursor.execute(\'\'\'
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
                    status TEXT DEFAULT \'processed\',
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            \'\'\')
        
        # Check if admin user exists
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = \'admin\'")
        else:
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = \'admin\'")
        
        admin_count = cursor.fetchone()[0]
        
        if admin_count == 0:
            # Create default admin user
            admin_password = bcrypt.hashpw("admin123".encode(\'utf-8\'), bcrypt.gensalt()).decode(\'utf-8\')
            
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
        session_token = request.headers.get(\'Authorization\')
        if not session_token:
            return jsonify({\'error\': \'No authorization token provided\'}), 401
        
        if session_token.startswith(\'Bearer \'):
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
                    WHERE s.session_token = ? AND s.expires_at > datetime(\'now\')
                """, (session_token,))
            
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if not user:
                return jsonify({\'error\': \'Invalid or expired session\'}), 401
            
            if user[3] != \'active\':  # status
                return jsonify({\'error\': \'Account not active\'}), 401
            
            # Add user info to request context
            request.current_user = {
                \'id\': user[0],
                \'username\': user[1],
                \'role\': user[2],
                \'status\': user[3]
            }
            
            return f(*args, **kwargs)
            
        except Exception as e:
            print(f"Auth error: {e}")
            return jsonify({\'error\': \'Authentication failed\'}), 401
    
    return decorated_function

# Frontend serving routes
@app.route(\'/\')
def serve_frontend():
    """Serve the main frontend page"""
    return send_from_directory(app.static_folder, \'index.html\')

@app.route(\'/<path:path>\')
def serve_static_files(path):
    """Serve static files"""
    try:
        return send_from_directory(app.static_folder, path)
    except:
        # If file not found, serve index.html for SPA routing
        return send_from_directory(app.static_folder, \'index.html\')

# Health check endpoint
@app.route(\'/api/health\')
def health_check():
    """Health check endpoint"""
    return jsonify({
        \'status\': \'healthy\',
        \'message\': \'Brain Link Tracker API is running\',
        \'version\': \'1.0.0\',
        \'database\': DATABASE_TYPE
    })

# Authentication endpoints
@app.route(\'/api/auth/login\', methods=[\'POST\'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        username = data.get(\'username\')
        password = data.get(\'password\')
        
        if not username or not password:
            return jsonify({\'error\': \'Username and password required\'}), 400
        
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
            return jsonify({\'error\': \'Invalid credentials\'}), 401
        
        user_id, username, password_hash, role, status = user
        
        if status != \'active\':
            cursor.close()
            conn.close()
            return jsonify({\'error\': \'Account not active\'}), 401
        
        if not bcrypt.checkpw(password.encode(\'utf-8\'), password_hash.encode(\'utf-8\')):
            cursor.close()
            conn.close()
            return jsonify({\'error\': \'Invalid credentials\'}), 401
        
        # Create session
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=1)  # Session expires in 1 hour
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                INSERT INTO user_sessions (user_id, session_token, expires_at)
                VALUES (%s, %s, %s)
            """, (user_id, session_token, expires_at))
        else:
            cursor.execute("""
                INSERT INTO user_sessions (user_id, session_token, expires_at)
                VALUES (?, ?, ?)
            """, (user_id, session_token, expires_at))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            \'message\': \'Login successful\',
            \'token\': session_token,
            \'user\': {
                \'id\': user_id,
                \'username\': username,
                \'role\': role,
                \'status\': status
            }
        }), 200
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({\'error\': \'An error occurred during login\'}), 500

@app.route(\'/api/auth/logout\', methods=[\'POST\'])
@require_auth
def logout():
    """User logout endpoint"""
    session_token = request.headers.get(\'Authorization\')
    if session_token and session_token.startswith(\'Bearer \'):
        session_token = session_token[7:]
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("DELETE FROM user_sessions WHERE session_token = %s", (session_token,))
        else:
            cursor.execute("DELETE FROM user_sessions WHERE session_token = ?", (session_token,))
        
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({\'message\': \'Logout successful\'}), 200
    except Exception as e:
        print(f"Logout error: {e}")
        return jsonify({\'error\': \'An error occurred during logout\'}), 500

@app.route(\'/api/auth/register\', methods=[\'POST\'])
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        username = data.get(\'username\')
        email = data.get(\'email\')
        password = data.get(\'password\')
        
        if not username or not email or not password:
            return jsonify({\'error\': \'Username, email, and password required\'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if username or email already exists
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
        else:
            cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        
        existing_user = cursor.fetchone()
        if existing_user:
            cursor.close()
            conn.close()
            return jsonify({\'error\': \'Username or email already exists\'}), 409
        
        hashed_password = bcrypt.hashpw(password.encode(\'utf-8\'), bcrypt.gensalt()).decode(\'utf-8\')
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, status)
                VALUES (%s, %s, %s, %s, %s)
            """, (username, email, hashed_password, \'member\', \'active\'))
        else:
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, status)
                VALUES (?, ?, ?, ?, ?)
            """, (username, email, hashed_password, \'member\', \'active\'))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({\'message\': \'User registered successfully\', \'username\': username}), 201
        
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({\'error\': \'An error occurred during registration\'}), 500

@app.route(\'/api/auth/status\', methods=[\'GET\'])
@require_auth
def auth_status():
    """Check authentication status"""
    return jsonify({
        \'message\': \'Authenticated\',
        \'user\': request.current_user
    }), 200

# Admin routes
@app.route(\'/api/admin/users\', methods=[\'GET\'])
@require_auth
def get_users():
    """Get all users (admin only)"""
    if request.current_user[\'role\'] != \'admin\':
        return jsonify({\'error\': \'Unauthorized\'}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE_TYPE == "postgresql":
        cursor.execute("SELECT id, username, email, role, status, created_at FROM users")
    else:
        cursor.execute("SELECT id, username, email, role, status, created_at FROM users")
    
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    
    user_list = []
    for user in users:
        user_list.append({
            \'id\': user[0],
            \'username\': user[1],
            \'email\': user[2],
            \'role\': user[3],
            \'status\': user[4],
            \'created_at\': user[5].isoformat() if user[5] else None
        })
    
    return jsonify(user_list), 200

@app.route(\'/api/admin/users/<int:user_id>/status\', methods=[\'PUT\'])
@require_auth
def update_user_status(user_id):
    """Update user status (admin only)"""
    if request.current_user[\'role\'] != \'admin\':
        return jsonify({\'error\': \'Unauthorized\'}), 403
    
    data = request.get_json()
    new_status = data.get(\'status\')
    
    if not new_status or new_status not in [\'active\', \'inactive\', \'pending\']:
        return jsonify({\'error\': \'Invalid status\'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE_TYPE == "postgresql":
        cursor.execute("UPDATE users SET status = %s WHERE id = %s", (new_status, user_id))
    else:
        cursor.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, user_id))
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({\'message\': \'User status updated successfully\'}), 200

@app.route(\'/api/admin/users/<int:user_id>/role\', methods=[\'PUT\'])
@require_auth
def update_user_role(user_id):
    """Update user role (admin only)"""
    if request.current_user[\'role\'] != \'admin\':
        return jsonify({\'error\': \'Unauthorized\'}), 403
    
    data = request.get_json()
    new_role = data.get(\'role\')
    
    if not new_role or new_role not in [\'admin\', \'member\']:
        return jsonify({\'error\': \'Invalid role\'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE_TYPE == "postgresql":
        cursor.execute("UPDATE users SET role = %s WHERE id = %s", (new_role, user_id))
    else:
        cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({\'message\': \'User role updated successfully\'}), 200

@app.route(\'/api/admin/users/<int:user_id>\', methods=[\'DELETE\'])
@require_auth
def delete_user(user_id):
    """Delete a user (admin only)"""
    if request.current_user[\'role\'] != \'admin\':
        return jsonify({\'error\': \'Unauthorized\'}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE_TYPE == "postgresql":
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    else:
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({\'message\': \'User deleted successfully\'}), 200

# Campaign routes
@app.route(\'/api/campaigns\', methods=[\'POST\'])
@require_auth
def create_campaign():
    """Create a new campaign"""
    data = request.get_json()
    name = data.get(\'name\')
    description = data.get(\'description\')
    user_id = request.current_user[\'id\']
    
    if not name:
        return jsonify({\'error\': \'Campaign name required\'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE_TYPE == "postgresql":
        cursor.execute("""
            INSERT INTO campaigns (name, description, user_id)
            VALUES (%s, %s, %s) RETURNING id
        """, (name, description, user_id))
    else:
        cursor.execute("""
            INSERT INTO campaigns (name, description, user_id)
            VALUES (?, ?, ?)
        """, (name, description, user_id))
    
    campaign_id = cursor.fetchone()[0] if DATABASE_TYPE == "postgresql" else cursor.lastrowid
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({\'message\': \'Campaign created successfully\', \'campaign_id\': campaign_id}), 201

@app.route(\'/api/campaigns\', methods=[\'GET\'])
@require_auth
def get_campaigns():
    """Get all campaigns for the current user"""
    user_id = request.current_user[\'id\']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE_TYPE == "postgresql":
        cursor.execute("SELECT id, name, description, status, created_at FROM campaigns WHERE user_id = %s", (user_id,))
    else:
        cursor.execute("SELECT id, name, description, status, created_at FROM campaigns WHERE user_id = ?", (user_id,))
    
    campaigns = cursor.fetchall()
    cursor.close()
    conn.close()
    
    campaign_list = []
    for campaign in campaigns:
        campaign_list.append({
            \'id\': campaign[0],
            \'name\': campaign[1],
            \'description\': campaign[2],
            \'status\': campaign[3],
            \'created_at\': campaign[4].isoformat() if campaign[4] else None
        })
    
    return jsonify(campaign_list), 200

@app.route(\'/api/campaigns/<int:campaign_id>\', methods=[\'GET\'])
@require_auth
def get_campaign(campaign_id):
    """Get a specific campaign by ID"""
    user_id = request.current_user[\'id\']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE_TYPE == "postgresql":
        cursor.execute("SELECT id, name, description, status, created_at FROM campaigns WHERE id = %s AND user_id = %s", (campaign_id, user_id))
    else:
        cursor.execute("SELECT id, name, description, status, created_at FROM campaigns WHERE id = ? AND user_id = ?", (campaign_id, user_id))
    
    campaign = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not campaign:
        return jsonify({\'error\': \'Campaign not found or unauthorized\'}), 404
    
    return jsonify({
        \'id\': campaign[0],
        \'name\': campaign[1],
        \'description\': campaign[2],
        \'status\': campaign[3],
        \'created_at\': campaign[4].isoformat() if campaign[4] else None
    }), 200

@app.route(\'/api/campaigns/<int:campaign_id>\', methods=[\'PUT\'])
@require_auth
def update_campaign(campaign_id):
    """Update a campaign"""
    user_id = request.current_user[\'id\']
    data = request.get_json()
    name = data.get(\'name\')
    description = data.get(\'description\')
    status = data.get(\'status\')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check ownership
    if DATABASE_TYPE == "postgresql":
        cursor.execute("SELECT id FROM campaigns WHERE id = %s AND user_id = %s", (campaign_id, user_id))
    else:
        cursor.execute("SELECT id FROM campaigns WHERE id = ? AND user_id = ?", (campaign_id, user_id))
    
    if not cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({\'error\': \'Campaign not found or unauthorized\'}), 404
    
    updates = []
    params = []
    if name:
        updates.append("name = %s" if DATABASE_TYPE == "postgresql" else "name = ?")
        params.append(name)
    if description:
        updates.append("description = %s" if DATABASE_TYPE == "postgresql" else "description = ?")
        params.append(description)
    if status:
        updates.append("status = %s" if DATABASE_TYPE == "postgresql" else "status = ?")
        params.append(status)
        
    if not updates:
        cursor.close()
        conn.close()
        return jsonify({\'message\': \'No updates provided\'}), 200
        
    params.append(campaign_id)
    params.append(user_id)
    
    query = f"UPDATE campaigns SET {\', \'.join(updates)} WHERE id = %s AND user_id = %s" if DATABASE_TYPE == "postgresql" else f"UPDATE campaigns SET {\', \'.join(updates)} WHERE id = ? AND user_id = ?"
    cursor.execute(query, tuple(params))
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({\'message\': \'Campaign updated successfully\'}), 200

@app.route(\'/api/campaigns/<int:campaign_id>\', methods=[\'DELETE\'])
@require_auth
def delete_campaign(campaign_id):
    """Delete a campaign"""
    user_id = request.current_user[\'id\']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check ownership
    if DATABASE_TYPE == "postgresql":
        cursor.execute("SELECT id FROM campaigns WHERE id = %s AND user_id = %s", (campaign_id, user_id))
    else:
        cursor.execute("SELECT id FROM campaigns WHERE id = ? AND user_id = ?", (campaign_id, user_id))
    
    if not cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({\'error\': \'Campaign not found or unauthorized\'}), 404
    
    if DATABASE_TYPE == "postgresql":
        cursor.execute("DELETE FROM campaigns WHERE id = %s", (campaign_id,))
    else:
        cursor.execute("DELETE FROM campaigns WHERE id = ?", (campaign_id,))
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({\'message\': \'Campaign deleted successfully\'}), 200

# Tracking link routes
@app.route(\'/api/tracking_links\', methods=[\'POST\'])
@require_auth
def create_tracking_link():
    """Create a new tracking link"""
    data = request.get_json()
    campaign_id = data.get(\'campaign_id\')
    original_url = data.get(\'original_url\')
    recipient_email = data.get(\'recipient_email\')
    recipient_name = data.get(\'recipient_name\')
    expires_at_str = data.get(\'expires_at\')
    click_limit = data.get(\'click_limit\', 0)
    custom_message = data.get(\'custom_message\')
    redirect_delay = data.get(\'redirect_delay\', 0)
    password_protected = data.get(\'password_protected\', 0)
    access_password = data.get(\'access_password\')
    geo_restrictions = json.dumps(data.get(\'geo_restrictions\')) if data.get(\'geo_restrictions\') else None
    device_restrictions = json.dumps(data.get(\'device_restrictions\')) if data.get(\'device_restrictions\') else None
    time_restrictions = json.dumps(data.get(\'time_restrictions\')) if data.get(\'time_restrictions\') else None
    
    user_id = request.current_user[\'id\']
    
    if not original_url:
        return jsonify({\'error\': \'Original URL required\'}), 400
    
    expires_at = None
    if expires_at_str:
        try:
            expires_at = datetime.fromisoformat(expires_at_str.replace(\'Z\', \'+00:00\'))
        except ValueError:
            return jsonify({\'error\': \'Invalid expires_at format. Use ISO 8601.\'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Validate campaign ownership
    if campaign_id:
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT id FROM campaigns WHERE id = %s AND user_id = %s", (campaign_id, user_id))
        else:
            cursor.execute("SELECT id FROM campaigns WHERE id = ? AND user_id = ?", (campaign_id, user_id))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({\'error\': \'Campaign not found or unauthorized\'}), 404

    tracking_token = secrets.token_urlsafe(8)
    
    if DATABASE_TYPE == "postgresql":
        cursor.execute("""
            INSERT INTO tracking_links (
                campaign_id, user_id, original_url, tracking_token, recipient_email, 
                recipient_name, expires_at, click_limit, custom_message, redirect_delay,
                password_protected, access_password, geo_restrictions, device_restrictions, time_restrictions
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
        """, (
            campaign_id, user_id, original_url, tracking_token, recipient_email,
            recipient_name, expires_at, click_limit, custom_message, redirect_delay,
            password_protected, access_password, geo_restrictions, device_restrictions, time_restrictions
        ))
    else:
        cursor.execute("""
            INSERT INTO tracking_links (
                campaign_id, user_id, original_url, tracking_token, recipient_email, 
                recipient_name, expires_at, click_limit, custom_message, redirect_delay,
                password_protected, access_password, geo_restrictions, device_restrictions, time_restrictions
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            campaign_id, user_id, original_url, tracking_token, recipient_email,
            recipient_name, expires_at, click_limit, custom_message, redirect_delay,
            password_protected, access_password, geo_restrictions, device_restrictions, time_restrictions
        ))
    
    link_id = cursor.fetchone()[0] if DATABASE_TYPE == "postgresql" else cursor.lastrowid
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({
        \'message\': \'Tracking link created successfully\',
        \'link_id\': link_id,
        \'tracking_url\': f"/track/{tracking_token}"
    }), 201

@app.route(\'/api/tracking_links\', methods=[\'GET\'])
@require_auth
def get_tracking_links():
    """Get all tracking links for the current user"""
    user_id = request.current_user[\'id\']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE_TYPE == "postgresql":
        cursor.execute("SELECT id, campaign_id, original_url, tracking_token, link_status, created_at, click_count FROM tracking_links WHERE user_id = %s", (user_id,))
    else:
        cursor.execute("SELECT id, campaign_id, original_url, tracking_token, link_status, created_at, click_count FROM tracking_links WHERE user_id = ?", (user_id,))
    
    links = cursor.fetchall()
    cursor.close()
    conn.close()
    
    link_list = []
    for link in links:
        link_list.append({
            \'id\': link[0],
            \'campaign_id\': link[1],
            \'original_url\': link[2],
            \'tracking_token\': link[3],
            \'link_status\': link[4],
            \'created_at\': link[5].isoformat() if link[5] else None,
            \'click_count\': link[6]
        })
    
    return jsonify(link_list), 200

@app.route(\'/api/tracking_links/<int:link_id>\', methods=[\'GET\'])
@require_auth
def get_tracking_link(link_id):
    """Get a specific tracking link by ID"""
    user_id = request.current_user[\'id\']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE_TYPE == "postgresql":
        cursor.execute("SELECT * FROM tracking_links WHERE id = %s AND user_id = %s", (link_id, user_id))
    else:
        cursor.execute("SELECT * FROM tracking_links WHERE id = ? AND user_id = ?", (link_id, user_id))
    
    link = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not link:
        return jsonify({\'error\': \'Tracking link not found or unauthorized\'}), 404
    
    # Convert row to dictionary for easier access
    link_dict = {
        \'id\': link[0],
        \'campaign_id\': link[1],
        \'user_id\': link[2],
        \'original_url\': link[3],
        \'tracking_token\': link[4],
        \'recipient_email\': link[5],
        \'recipient_name\': link[6],
        \'link_status\': link[7],
        \'created_at\': link[8].isoformat() if link[8] else None,
        \'expires_at\': link[9].isoformat() if link[9] else None,
        \'click_limit\': link[10],
        \'click_count\': link[11],
        \'last_clicked\': link[12].isoformat() if link[12] else None,
        \'custom_message\': link[13],
        \'redirect_delay\': link[14],
        \'password_protected\': bool(link[15]),
        \'access_password\': link[16],
        \'geo_restrictions\': json.loads(link[17]) if link[17] else None,
        \'device_restrictions\': json.loads(link[18]) if link[18] else None,
        \'time_restrictions\': json.loads(link[19]) if link[19] else None,
    }
    
    return jsonify(link_dict), 200

@app.route(\'/api/tracking_links/<int:link_id>\', methods=[\'PUT\'])
@require_auth
def update_tracking_link(link_id):
    """Update a tracking link"""
    user_id = request.current_user[\'id\']
    data = request.get_json()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check ownership
    if DATABASE_TYPE == "postgresql":
        cursor.execute("SELECT id FROM tracking_links WHERE id = %s AND user_id = %s", (link_id, user_id))
    else:
        cursor.execute("SELECT id FROM tracking_links WHERE id = ? AND user_id = ?", (link_id, user_id))
    
    if not cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({\'error\': \'Tracking link not found or unauthorized\'}), 404
    
    updates = []
    params = []
    
    if \'campaign_id\' in data:
        campaign_id = data.get(\'campaign_id\')
        if campaign_id:
            if DATABASE_TYPE == "postgresql":
                cursor.execute("SELECT id FROM campaigns WHERE id = %s AND user_id = %s", (campaign_id, user_id))
            else:
                cursor.execute("SELECT id FROM campaigns WHERE id = ? AND user_id = ?", (campaign_id, user_id))
            if not cursor.fetchone():
                cursor.close()
                conn.close()
                return jsonify({\'error\': \'Campaign not found or unauthorized\'}), 404
        updates.append("campaign_id = %s" if DATABASE_TYPE == "postgresql" else "campaign_id = ?")
        params.append(campaign_id)
    
    if \'original_url\' in data:
        updates.append("original_url = %s" if DATABASE_TYPE == "postgresql" else "original_url = ?")
        params.append(data[\'original_url\'])
    if \'recipient_email\' in data:
        updates.append("recipient_email = %s" if DATABASE_TYPE == "postgresql" else "recipient_email = ?")
        params.append(data[\'recipient_email\'])
    if \'recipient_name\' in data:
        updates.append("recipient_name = %s" if DATABASE_TYPE == "postgresql" else "recipient_name = ?")
        params.append(data[\'recipient_name\'])
    if \'link_status\' in data:
        updates.append("link_status = %s" if DATABASE_TYPE == "postgresql" else "link_status = ?")
        params.append(data[\'link_status\'])
    if \'expires_at\' in data:
        expires_at_str = data.get(\'expires_at\')
        expires_at = None
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(expires_at_str.replace(\'Z\', \'+00:00\'))
            except ValueError:
                cursor.close()
                conn.close()
                return jsonify({\'error\': \'Invalid expires_at format. Use ISO 8601.\'}), 400
        updates.append("expires_at = %s" if DATABASE_TYPE == "postgresql" else "expires_at = ?")
        params.append(expires_at)
    if \'click_limit\' in data:
        updates.append("click_limit = %s" if DATABASE_TYPE == "postgresql" else "click_limit = ?")
        params.append(data[\'click_limit\'])
    if \'custom_message\' in data:
        updates.append("custom_message = %s" if DATABASE_TYPE == "postgresql" else "custom_message = ?")
        params.append(data[\'custom_message\'])
    if \'redirect_delay\' in data:
        updates.append("redirect_delay = %s" if DATABASE_TYPE == "postgresql" else "redirect_delay = ?")
        params.append(data[\'redirect_delay\'])
    if \'password_protected\' in data:
        updates.append("password_protected = %s" if DATABASE_TYPE == "postgresql" else "password_protected = ?")
        params.append(data[\'password_protected\'])
    if \'access_password\' in data:
        updates.append("access_password = %s" if DATABASE_TYPE == "postgresql" else "access_password = ?")
        params.append(data[\'access_password\'])
    if \'geo_restrictions\' in data:
        updates.append("geo_restrictions = %s" if DATABASE_TYPE == "postgresql" else "geo_restrictions = ?")
        params.append(json.dumps(data[\'geo_restrictions\']) if data[\'geo_restrictions\'] else None)
    if \'device_restrictions\' in data:
        updates.append("device_restrictions = %s" if DATABASE_TYPE == "postgresql" else "device_restrictions = ?")
        params.append(json.dumps(data[\'device_restrictions\']) if data[\'device_restrictions\'] else None)
    if \'time_restrictions\' in data:
        updates.append("time_restrictions = %s" if DATABASE_TYPE == "postgresql" else "time_restrictions = ?")
        params.append(json.dumps(data[\'time_restrictions\']) if data[\'time_restrictions\'] else None)
        
    if not updates:
        cursor.close()
        conn.close()
        return jsonify({\'message\': \'No updates provided\'}), 200
        
    params.append(link_id)
    params.append(user_id)
    
    query = f"UPDATE tracking_links SET {\', \'.join(updates)} WHERE id = %s AND user_id = %s" if DATABASE_TYPE == "postgresql" else f"UPDATE tracking_links SET {\', \'.join(updates)} WHERE id = ? AND user_id = ?"
    cursor.execute(query, tuple(params))
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({\'message\': \'Tracking link updated successfully\'}), 200

@app.route(\'/api/tracking_links/<int:link_id>\', methods=[\'DELETE\'])
@require_auth
def delete_tracking_link(link_id):
    """Delete a tracking link"""
    user_id = request.current_user[\'id\']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check ownership
    if DATABASE_TYPE == "postgresql":
        cursor.execute("SELECT id FROM tracking_links WHERE id = %s AND user_id = %s", (link_id, user_id))
    else:
        cursor.execute("SELECT id FROM tracking_links WHERE id = ? AND user_id = ?", (link_id, user_id))
    
    if not cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({\'error\': \'Tracking link not found or unauthorized\'}), 404
    
    if DATABASE_TYPE == "postgresql":
        cursor.execute("DELETE FROM tracking_links WHERE id = %s", (link_id,))
    else:
        cursor.execute("DELETE FROM tracking_links WHERE id = ?", (link_id,))
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({\'message\': \'Tracking link deleted successfully\'}), 200

# Tracking events routes
@app.route(\'/api/tracking_events\', methods=[\'GET\'])
@require_auth
def get_tracking_events():
    """Get all tracking events for the current user's links"""
    user_id = request.current_user[\'id\']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE_TYPE == "postgresql":
        cursor.execute("""
            SELECT te.id, te.tracking_token, te.event_type, te.ip_address, te.user_agent, 
                   te.referrer, te.country, te.city, te.device_type, te.browser, te.os, 
                   te.timestamp, te.additional_data, te.campaign_id, te.user_id, 
                   te.is_bot, te.bot_confidence, te.bot_reason, te.status
            FROM tracking_events te
            JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
            WHERE tl.user_id = %s
            ORDER BY te.timestamp DESC
        """, (user_id,))
    else:
        cursor.execute("""
            SELECT te.id, te.tracking_token, te.event_type, te.ip_address, te.user_agent, 
                   te.referrer, te.country, te.city, te.device_type, te.browser, te.os, 
                   te.timestamp, te.additional_data, te.campaign_id, te.user_id, 
                   te.is_bot, te.bot_confidence, te.bot_reason, te.status
            FROM tracking_events te
            JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
            WHERE tl.user_id = ?
            ORDER BY te.timestamp DESC
        """, (user_id,))
    
    events = cursor.fetchall()
    cursor.close()
    conn.close()
    
    event_list = []
    for event in events:
        event_list.append({
            \'id\': event[0],
            \'tracking_token\': event[1],
            \'event_type\': event[2],
            \'ip_address\': event[3],
            \'user_agent\': event[4],
            \'referrer\': event[5],
            \'country\': event[6],
            \'city\': event[7],
            \'device_type\': event[8],
            \'browser\': event[9],
            \'os\': event[10],
            \'timestamp\': event[11].isoformat() if event[11] else None,
            \'additional_data\': json.loads(event[12]) if event[12] else None,
            \'campaign_id\': event[13],
            \'user_id\': event[14],
            \'is_bot\': bool(event[15]),
            \'bot_confidence\': event[16],
            \'bot_reason\': event[17],
            \'status\': event[18]
        })
    
    return jsonify(event_list), 200

@app.route(\'/api/tracking_events/summary\', methods=[\'GET\'])
@require_auth
def get_tracking_summary():
    """Get a summary of tracking events for the current user's links"""
    user_id = request.current_user[\'id\']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    summary = {}
    
    # Total clicks
    if DATABASE_TYPE == "postgresql":
        cursor.execute("SELECT SUM(click_count) FROM tracking_links WHERE user_id = %s", (user_id,))
    else:
        cursor.execute("SELECT SUM(click_count) FROM tracking_links WHERE user_id = ?", (user_id,))
    total_clicks = cursor.fetchone()[0] or 0
    summary[\'total_clicks\'] = total_clicks
    
    # Unique clicks (example, needs more sophisticated logic for true uniqueness)
    if DATABASE_TYPE == "postgresql":
        cursor.execute("""
            SELECT COUNT(DISTINCT ip_address) FROM tracking_events te
            JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
            WHERE tl.user_id = %s AND te.event_type = \'click\'
        """, (user_id,))
    else:
        cursor.execute("""
            SELECT COUNT(DISTINCT ip_address) FROM tracking_events te
            JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
            WHERE tl.user_id = ? AND te.event_type = \'click\'
        """, (user_id,))
    unique_clicks = cursor.fetchone()[0] or 0
    summary[\'unique_clicks\'] = unique_clicks
    
    # Clicks by country
    if DATABASE_TYPE == "postgresql":
        cursor.execute("""
            SELECT country, COUNT(*) FROM tracking_events te
            JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
            WHERE tl.user_id = %s AND te.event_type = \'click\' AND country IS NOT NULL
            GROUP BY country ORDER BY COUNT(*) DESC LIMIT 5
        """, (user_id,))
    else:
        cursor.execute("""
            SELECT country, COUNT(*) FROM tracking_events te
            JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
            WHERE tl.user_id = ? AND te.event_type = \'click\' AND country IS NOT NULL
            GROUP BY country ORDER BY COUNT(*) DESC LIMIT 5
        """, (user_id,))
    clicks_by_country = [{\'country\': row[0], \'count\': row[1]} for row in cursor.fetchall()]
    summary[\'clicks_by_country\'] = clicks_by_country
    
    # Clicks by device type
    if DATABASE_TYPE == "postgresql":
        cursor.execute("""
            SELECT device_type, COUNT(*) FROM tracking_events te
            JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
            WHERE tl.user_id = %s AND te.event_type = \'click\' AND device_type IS NOT NULL
            GROUP BY device_type ORDER BY COUNT(*) DESC LIMIT 3
        """, (user_id,))
    else:
        cursor.execute("""
            SELECT device_type, COUNT(*) FROM tracking_events te
            JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
            WHERE tl.user_id = ? AND te.event_type = \'click\' AND device_type IS NOT NULL
            GROUP BY device_type ORDER BY COUNT(*) DESC LIMIT 3
        """, (user_id,))
    clicks_by_device = [{\'device_type\': row[0], \'count\': row[1]} for row in cursor.fetchall()]
    summary[\'clicks_by_device\'] = clicks_by_device
    
    cursor.close()
    conn.close()
    
    return jsonify(summary), 200

# Tracking endpoint for links
@app.route(\'/track/<tracking_token>\')
def track_link(tracking_token):
    """Tracking endpoint for clicks"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT * FROM tracking_links WHERE tracking_token = %s", (tracking_token,))
        else:
            cursor.execute("SELECT * FROM tracking_links WHERE tracking_token = ?", (tracking_token,))
        
        link = cursor.fetchone()
        
        if not link:
            return "Link not found", 404
        
        link_dict = {
            \'id\': link[0],
            \'campaign_id\': link[1],
            \'user_id\': link[2],
            \'original_url\': link[3],
            \'tracking_token\': link[4],
            \'recipient_email\': link[5],
            \'recipient_name\': link[6],
            \'link_status\': link[7],
            \'created_at\': link[8],
            \'expires_at\': link[9],
            \'click_limit\': link[10],
            \'click_count\': link[11],
            \'last_clicked\': link[12],
            \'custom_message\': link[13],
            \'redirect_delay\': link[14],
            \'password_protected\': bool(link[15]),
            \'access_password\': link[16],
            \'geo_restrictions\': json.loads(link[17]) if link[17] else None,
            \'device_restrictions\': json.loads(link[18]) if link[18] else None,
            \'time_restrictions\': json.loads(link[19]) if link[19] else None,
        }
        
        # Check link status and expiry
        if link_dict[\'link_status\'] != \'active\':
            return "Link is not active", 403
        
        if link_dict[\'expires_at\'] and datetime.now() > link_dict[\'expires_at\']:
            return "Link has expired", 403
            
        if link_dict[\'click_limit\'] > 0 and link_dict[\'click_count\'] >= link_dict[\'click_limit\']:
            return "Link click limit reached", 403
            
        # Geo-restrictions
        ip_address = request.headers.get(\'X-Forwarded-For\', request.remote_addr)
        country = None
        city = None
        try:
            reader = geoip2.database.Reader(\'GeoLite2-City.mmdb\')
            response = reader.city(ip_address)
            country = response.country.iso_code
            city = response.city.name
        except geoip2.errors.AddressNotFoundError:
            print(f"GeoLite2: IP address {ip_address} not found in database.")
        except Exception as e:
            print(f"GeoLite2 error: {e}")
        finally:
            if \'reader\' in locals():
                reader.close()

        if link_dict[\'geo_restrictions\'] and country not in link_dict[\'geo_restrictions\']:
            return "Access denied: Geo-restricted", 403

        # Device restrictions
        user_agent_string = request.headers.get(\'User-Agent\')
        user_agent = parse(user_agent_string)
        device_type = \'Other\'
        if user_agent.is_mobile:
            device_type = \'Mobile\'
        elif user_agent.is_tablet:
            device_type = \'Tablet\'
        elif user_agent.is_pc:
            device_type = \'Desktop\'

        if link_dict[\'device_restrictions\'] and device_type not in link_dict[\'device_restrictions\']:
            return "Access denied: Device-restricted", 403

        # Time restrictions (e.g., specific hours of the day)
        if link_dict[\'time_restrictions\']:
            current_hour = datetime.now().hour
            allowed_hours = link_dict[\'time_restrictions\'].get(\'hours\', [])
            if allowed_hours and current_hour not in allowed_hours:
                return "Access denied: Time-restricted", 403

        # Password protection
        if link_dict[\'password_protected\']:
            provided_password = request.args.get(\'password\')
            if not provided_password or provided_password != link_dict[\'access_password\']:
                return "Password required or incorrect", 401

        # Update click count and last clicked timestamp
        if DATABASE_TYPE == "postgresql":
            cursor.execute("UPDATE tracking_links SET click_count = click_count + 1, last_clicked = CURRENT_TIMESTAMP WHERE id = %s", (link_dict[\'id\'],))
        else:
            cursor.execute("UPDATE tracking_links SET click_count = click_count + 1, last_clicked = CURRENT_TIMESTAMP WHERE id = ?", (link_dict[\'id\'],))
        
        # Record tracking event
        browser = user_agent.browser.family
        os_name = user_agent.os.family
        referrer = request.referrer
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                INSERT INTO tracking_events (
                    tracking_token, event_type, ip_address, user_agent, referrer, 
                    country, city, device_type, browser, os, campaign_id, user_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                tracking_token, \'click\', ip_address, user_agent_string, referrer,
                country, city, device_type, browser, os_name, link_dict[\'campaign_id\'], link_dict[\'user_id\']
            ))
        else:
            cursor.execute("""
                INSERT INTO tracking_events (
                    tracking_token, event_type, ip_address, user_agent, referrer, 
                    country, city, device_type, browser, os, campaign_id, user_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tracking_token, \'click\', ip_address, user_agent_string, referrer,
                country, city, device_type, browser, os_name, link_dict[\'campaign_id\'], link_dict[\'user_id\']
            ))
        
        conn.commit()
        
        # Redirect after delay
        if link_dict[\'redirect_delay\'] > 0:
            time.sleep(link_dict[\'redirect_delay\'])
            
        return redirect(link_dict[\'original_url\'])
        
    except Exception as e:
        print(f"Tracking error: {e}")
        return "An error occurred during tracking", 500
    finally:
        if conn:
            conn.close()

# Initialize database and create admin user on startup
init_db()

# This is the entry point for Vercel
# It should not contain app.run() if deployed as a serverless function
# app.run(host=\'0.0.0.0\', port=5000, debug=True)


