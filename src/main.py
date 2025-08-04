from flask import Flask, request, jsonify, send_file, redirect, render_template_string
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
import time
import requests
import json
from datetime import datetime, timedelta
import os
import uuid
from PIL import Image
import io
import base64
from urllib.parse import urlparse
import socket
import dns.resolver
import geoip2.database
import geoip2.errors
from user_agents import parse
import os
import bcrypt
from functools import wraps

app = Flask(__name__)
CORS(app)

# Configuration
SECRET_KEY = "7th-brain-advanced-link-tracker-secret-2024"
DATABASE_PATH = "/home/ubuntu/enhanced_link_tracker/7th-brain-link-tracker-backend/src/database/app.db"

# Initialize database
def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Create users table for authentication and hierarchy
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
    
    # Create user_permissions table for granular permissions
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
    
    # Create user_sessions table for session management
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
    
    # Update tracking_links table to include user ownership
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tracking_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER,
            user_id INTEGER NOT NULL,
            original_url TEXT NOT NULL,
            tracking_token TEXT UNIQUE NOT NULL,
            recipient_email TEXT,
            status TEXT DEFAULT 'active',
            link_status TEXT DEFAULT 'created',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
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
            country_code TEXT,
            city TEXT,
            device_type TEXT,
            browser TEXT,
            is_bot BOOLEAN DEFAULT 0,
            bot_confidence REAL DEFAULT 0.0,
            blocked BOOLEAN DEFAULT 0,
            block_reason TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'ok',
            redirect_success BOOLEAN DEFAULT 1,
            email_opened BOOLEAN DEFAULT 0,
            link_clicked BOOLEAN DEFAULT 0,
            campaign_id INTEGER,
            user_id INTEGER,
            FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_reputation (
            ip_address TEXT PRIMARY KEY,
            reputation_score REAL DEFAULT 0.5,
            country_code TEXT,
            is_vpn BOOLEAN DEFAULT 0,
            is_proxy BOOLEAN DEFAULT 0,
            threat_types TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create default admin user if not exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
    admin_count = cursor.fetchone()[0]
    
    if admin_count == 0:
        import bcrypt
        password_hash = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, role, status, subscription_status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('admin', 'admin@brainlinktracker.com', password_hash, 'admin', 'active', 'lifetime'))
    
    # Insert sample data with user ownership
    cursor.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
    admin_user = cursor.fetchone()
    if admin_user:
        admin_id = admin_user[0]
        cursor.execute("INSERT OR IGNORE INTO campaigns (id, name, description, user_id) VALUES (1, 'Test Campaign', 'Sample campaign for testing', ?)", (admin_id,))
        cursor.execute("INSERT OR IGNORE INTO tracking_links (campaign_id, user_id, original_url, tracking_token, recipient_email) VALUES (1, ?, 'https://example.com', 'test123token456', 'test@example.com')", (admin_id,))
    
    conn.commit()
    conn.close()

# Security Services
class SecurityService:
    BLOCKED_REFERRERS = [
        'facebook.com', 'twitter.com', 'linkedin.com', 'slack.com',
        'virustotal.com', 'urlvoid.com', 'hybrid-analysis.com'
    ]
    
    BOT_PATTERNS = [
        'curl', 'wget', 'python-requests', 'axios', 'postman',
        'bot', 'crawler', 'spider', 'scanner'
    ]
    
    @staticmethod
    def is_blocked_referrer(referrer):
        if not referrer:
            return False
        return any(blocked in referrer.lower() for blocked in SecurityService.BLOCKED_REFERRERS)
    
    @staticmethod
    def detect_bot(user_agent, headers):
        if not user_agent:
            return True, 0.9, "Missing user agent"
        
        ua_lower = user_agent.lower()
        confidence = 0.0
        reasons = []
        
        # Check bot patterns
        for pattern in SecurityService.BOT_PATTERNS:
            if pattern in ua_lower:
                confidence += 0.4
                reasons.append(f"Bot pattern: {pattern}")
        
        # Check missing headers
        if not headers.get('Accept'):
            confidence += 0.2
            reasons.append("Missing Accept header")
        
        if not headers.get('Accept-Language'):
            confidence += 0.1
            reasons.append("Missing Accept-Language")
        
        # Very short user agent
        if len(user_agent) < 20:
            confidence += 0.2
            reasons.append("Suspicious user agent length")
        
        is_bot = confidence > 0.6
        return is_bot, min(confidence, 1.0), "; ".join(reasons)
    
    @staticmethod
    def update_link_status(tracking_token, new_status, event_type='status_update'):
        """Update the status of a tracking link and log the event"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            # Update the tracking link status
            cursor.execute('''
                UPDATE tracking_links 
                SET link_status = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE tracking_token = ?
            ''', (new_status, tracking_token))
            
            # Get link details for event logging
            cursor.execute('''
                SELECT campaign_id, user_id FROM tracking_links 
                WHERE tracking_token = ?
            ''', (tracking_token,))
            link_data = cursor.fetchone()
            
            if link_data:
                campaign_id, user_id = link_data
                
                # Log the status change event
                cursor.execute('''
                    INSERT INTO tracking_events 
                    (tracking_token, event_type, status, campaign_id, user_id, timestamp)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (tracking_token, event_type, new_status, campaign_id, user_id))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error updating link status: {e}")
            return False
    
    @staticmethod
    def get_link_status_history(tracking_token):
        """Get the status history for a tracking link"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT event_type, status, timestamp, ip_address, user_agent
                FROM tracking_events 
                WHERE tracking_token = ? 
                ORDER BY timestamp DESC
            ''', (tracking_token,))
            
            events = cursor.fetchall()
            conn.close()
            
            return [{
                'event_type': event[0],
                'status': event[1],
                'timestamp': event[2],
                'ip_address': event[3],
                'user_agent': event[4]
            } for event in events]
        except Exception as e:
            print(f"Error getting status history: {e}")
            return []
    
    @staticmethod
    def get_geolocation(ip_address):
        # Simple geolocation using ipapi.co
        try:
            if ip_address in ['127.0.0.1', '::1', 'localhost']:
                return {'country_code': 'US', 'city': 'Local', 'is_vpn': False}
            
            response = requests.get(f'http://ipapi.co/{ip_address}/json/', timeout=2)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country_code': data.get('country_code', 'XX'),
                    'city': data.get('city', 'Unknown'),
                    'is_vpn': data.get('threat', {}).get('is_anonymous', False)
                }
        except:
            pass
        
        return {'country_code': 'XX', 'city': 'Unknown', 'is_vpn': False}

# Authentication and Authorization Services
class AuthService:
    @staticmethod
    def hash_password(password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    @staticmethod
    def verify_password(password, password_hash):
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    
    @staticmethod
    def generate_session_token():
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def create_session(user_id):
        token = AuthService.generate_session_token()
        expires_at = datetime.now() + timedelta(days=7)  # 7 days session
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO user_sessions (user_id, session_token, expires_at)
            VALUES (?, ?, ?)
        ''', (user_id, token, expires_at))
        conn.commit()
        conn.close()
        
        return token
    
    @staticmethod
    def validate_session(token):
        if not token:
            return None
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.id, u.username, u.email, u.role, u.status, u.parent_id
            FROM user_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = ? AND s.expires_at > datetime('now') AND u.status = 'active'
        ''', (token,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'id': result[0],
                'username': result[1],
                'email': result[2],
                'role': result[3],
                'status': result[4],
                'parent_id': result[5]
            }
        return None
    
    @staticmethod
    def get_user_hierarchy(user_id):
        """Get all users under this user's hierarchy"""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get direct children
        cursor.execute('SELECT id FROM users WHERE parent_id = ?', (user_id,))
        children = [row[0] for row in cursor.fetchall()]
        
        # Recursively get all descendants
        all_descendants = children.copy()
        for child_id in children:
            all_descendants.extend(AuthService.get_user_hierarchy(child_id))
        
        conn.close()
        return all_descendants
    
    @staticmethod
    def has_permission(user, permission):
        """Check if user has specific permission"""
        role_permissions = {
            'admin': ['*'],  # Admin has all permissions
            'admin2': [
                'view_users', 'manage_members', 'manage_workers', 'view_analytics',
                'create_campaigns', 'manage_campaigns', 'view_tracking_links'
            ],
            'member': [
                'create_campaigns', 'manage_own_campaigns', 'view_own_analytics',
                'create_tracking_links', 'view_own_tracking_links', 'manage_workers'
            ],
            'worker': [
                'view_assigned_campaigns', 'view_assigned_tracking_links'
            ]
        }
        
        user_permissions = role_permissions.get(user['role'], [])
        return '*' in user_permissions or permission in user_permissions

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if token and token.startswith('Bearer '):
            token = token[7:]  # Remove 'Bearer ' prefix
        
        user = AuthService.validate_session(token)
        if not user:
            return jsonify({'error': 'Authentication required'}), 401
        
        request.current_user = user
        return f(*args, **kwargs)
    return decorated_function

def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(request, 'current_user'):
                return jsonify({'error': 'Authentication required'}), 401
            
            if not AuthService.has_permission(request.current_user, permission):
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Generate tracking pixel (1x1 transparent PNG)
def generate_pixel():
    # 1x1 transparent PNG in base64
    pixel_data = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==')
    return pixel_data

# Authentication Routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'member')
        
        if not username or not email or not password:
            return jsonify({'error': 'Username, email, and password are required'}), 400
        
        # Check if user already exists
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'User already exists'}), 400
        
        # Hash password
        password_hash = AuthService.hash_password(password)
        
        # Create user with pending status (admin approval required)
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, role, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, email, password_hash, role, 'pending'))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Registration successful. Awaiting admin approval.'}), 201
        
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, email, password_hash, role, status
            FROM users WHERE username = ? OR email = ?
        ''', (username, username))
        user = cursor.fetchone()
        conn.close()
        
        if not user or not AuthService.verify_password(password, user[3]):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if user[5] != 'active':
            return jsonify({'error': 'Account not activated. Please contact admin.'}), 403
        
        # Create session
        token = AuthService.create_session(user[0])
        
        # Update last login
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET last_login = datetime("now") WHERE id = ?', (user[0],))
        conn.commit()
        conn.close()
        
        return jsonify({
            'token': token,
            'user': {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'role': user[4],
                'status': user[5]
            }
        }), 200
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    try:
        token = request.headers.get('Authorization')
        if token and token.startswith('Bearer '):
            token = token[7:]
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM user_sessions WHERE session_token = ?', (token,))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Logged out successfully'}), 200
        
    except Exception as e:
        print(f"Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500

@app.route('/api/auth/me', methods=['GET'])
@require_auth
def get_current_user():
    return jsonify({'user': request.current_user}), 200

# User Management Routes (Admin only)
@app.route('/api/admin/users', methods=['GET'])
@require_auth
@require_permission('view_users')
def get_users():
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Admin can see all users, Admin2 can see their hierarchy
        if request.current_user['role'] == 'admin':
            cursor.execute('''
                SELECT id, username, email, role, status, parent_id, created_at, last_login,
                       subscription_status, subscription_expires
                FROM users ORDER BY created_at DESC
            ''')
        else:
            # Admin2 can only see users in their hierarchy
            hierarchy = AuthService.get_user_hierarchy(request.current_user['id'])
            hierarchy.append(request.current_user['id'])  # Include self
            placeholders = ','.join('?' * len(hierarchy))
            cursor.execute(f'''
                SELECT id, username, email, role, status, parent_id, created_at, last_login,
                       subscription_status, subscription_expires
                FROM users WHERE id IN ({placeholders}) ORDER BY created_at DESC
            ''', hierarchy)
        
        users = cursor.fetchall()
        conn.close()
        
        users_list = []
        for user in users:
            users_list.append({
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'role': user[3],
                'status': user[4],
                'parent_id': user[5],
                'created_at': user[6],
                'last_login': user[7],
                'subscription_status': user[8],
                'subscription_expires': user[9]
            })
        
        return jsonify({'users': users_list}), 200
        
    except Exception as e:
        print(f"Get users error: {e}")
        return jsonify({'error': 'Failed to get users'}), 500

@app.route('/api/admin/users/<int:user_id>/approve', methods=['POST'])
@require_auth
@require_permission('manage_members')
def approve_user(user_id):
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET status = ? WHERE id = ?', ('active', user_id))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'User approved successfully'}), 200
        
    except Exception as e:
        print(f"Approve user error: {e}")
        return jsonify({'error': 'Failed to approve user'}), 500

@app.route('/api/admin/users/<int:user_id>/role', methods=['PUT'])
@require_auth
@require_permission('manage_members')
def update_user_role(user_id):
    try:
        data = request.get_json()
        new_role = data.get('role')
        parent_id = data.get('parent_id')
        
        if new_role not in ['admin2', 'member', 'worker']:
            return jsonify({'error': 'Invalid role'}), 400
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Set parent_id based on role and current user
        if new_role == 'admin2' and request.current_user['role'] == 'admin':
            parent_id = request.current_user['id']
        elif new_role in ['member', 'worker'] and request.current_user['role'] in ['admin', 'admin2']:
            parent_id = request.current_user['id']
        
        cursor.execute('UPDATE users SET role = ?, parent_id = ? WHERE id = ?', (new_role, parent_id, user_id))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'User role updated successfully'}), 200
        
    except Exception as e:
        print(f"Update user role error: {e}")
        return jsonify({'error': 'Failed to update user role'}), 500

# Routes
@app.route('/track/pixel/<token>')
def track_pixel(token):
    try:
        # Update link status to 'opened' (email opened)
        SecurityService.update_link_status(token, 'opened', 'email_open')
        
        # Get request info
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        user_agent = request.headers.get('User-Agent', '')
        referrer = request.headers.get('Referer', '')
        
        # Security checks
        if SecurityService.is_blocked_referrer(referrer):
            SecurityService.update_link_status(token, 'blocked', 'security_block')
            record_event(token, 'pixel_blocked', ip_address, user_agent, block_reason='Social referrer blocked')
        else:
            # Bot detection
            is_bot, confidence, reason = SecurityService.detect_bot(user_agent, dict(request.headers))
            
            if is_bot:
                SecurityService.update_link_status(token, 'blocked', 'bot_detected')
                record_event(token, 'pixel_blocked', ip_address, user_agent, 
                           is_bot=True, bot_confidence=confidence, block_reason=f'Bot detected: {reason}')
            else:
                # Get geolocation
                geo = SecurityService.get_geolocation(ip_address)
                
                # Record successful pixel view and update opens count
                record_event(token, 'pixel_view', ip_address, user_agent,
                           country_code=geo['country_code'], city=geo['city'])
                
                # Update opens count in tracking_links
                conn = sqlite3.connect(DATABASE_PATH)
                cursor = conn.cursor()
                cursor.execute('UPDATE tracking_links SET opens = COALESCE(opens, 0) + 1 WHERE tracking_token = ?', (token,))
                conn.commit()
                conn.close()
        
        # Always return pixel
        pixel_data = generate_pixel()
        response = app.response_class(
            pixel_data,
            mimetype='image/png',
            headers={
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
        )
        return response
        
    except Exception as e:
        print(f"Error in pixel tracking: {e}")
        SecurityService.update_link_status(token, 'error', 'system_error')
        return send_file(io.BytesIO(generate_pixel()), mimetype='image/png')

@app.route('/track/click/<token>')
def track_click(token):
    try:
        # Update link status to 'clicked'
        SecurityService.update_link_status(token, 'clicked', 'click')
        
        # Get request info
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        user_agent = request.headers.get('User-Agent', '')
        referrer = request.headers.get('Referer', '')
        
        # Security checks
        if SecurityService.is_blocked_referrer(referrer):
            SecurityService.update_link_status(token, 'blocked', 'security_block')
            record_event(token, 'click_blocked', ip_address, user_agent, block_reason='Social referrer blocked')
            return "Access Denied", 403
        
        # Bot detection
        is_bot, confidence, reason = SecurityService.detect_bot(user_agent, dict(request.headers))
        
        if is_bot:
            SecurityService.update_link_status(token, 'blocked', 'bot_detected')
            record_event(token, 'click_blocked', ip_address, user_agent,
                       is_bot=True, bot_confidence=confidence, block_reason=f'Bot detected: {reason}')
            return "Access Denied", 403
        
        # Get original URL
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT original_url FROM tracking_links WHERE tracking_token = ? AND is_active = 1", (token,))
        result = cursor.fetchone()
        
        if not result:
            SecurityService.update_link_status(token, 'not_found', 'error')
            conn.close()
            return "Link not found", 404
        
        original_url = result[0]
        
        # Update click count
        cursor.execute('UPDATE tracking_links SET clicks = COALESCE(clicks, 0) + 1 WHERE tracking_token = ?', (token,))
        conn.commit()
        conn.close()
        
        # Get geolocation
        geo = SecurityService.get_geolocation(ip_address)
        
        # Record successful click
        record_event(token, 'click', ip_address, user_agent,
                   country_code=geo['country_code'], city=geo['city'])
        
        # Update status to 'redirected' before redirect
        SecurityService.update_link_status(token, 'redirected', 'redirect')
        
        # Redirect to original URL
        response = redirect(original_url, code=302)
        
        # Update final status to 'ok' after successful redirect setup
        SecurityService.update_link_status(token, 'ok', 'redirect_success')
        
        return response
        
    except Exception as e:
        print(f"Error in click tracking: {e}")
        SecurityService.update_link_status(token, 'error', 'system_error')
        return "Internal Server Error", 500

def record_event(token, event_type, ip_address, user_agent, country_code='XX', city='Unknown',
                is_bot=False, bot_confidence=0.0, blocked=False, block_reason=None):
    try:
        # Parse user agent
        device_type = 'Unknown'
        browser = 'Unknown'
        
        if user_agent:
            ua = parse(user_agent)
            device_type = 'Mobile' if ua.is_mobile else 'Tablet' if ua.is_tablet else 'Desktop'
            browser = f"{ua.browser.family} {ua.browser.version_string}" if ua.browser.family else 'Unknown'
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO tracking_events 
            (tracking_token, event_type, ip_address, user_agent, country_code, city, 
             device_type, browser, is_bot, bot_confidence, blocked, block_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (token, event_type, ip_address, user_agent, country_code, city,
              device_type, browser, is_bot, bot_confidence, blocked, block_reason))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"Error recording event: {e}")

# Analytics API
@app.route('/api/analytics')
def get_analytics():
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get overview stats
        cursor.execute("SELECT COUNT(*) FROM tracking_events WHERE event_type = 'click' AND blocked = 0")
        total_clicks = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM tracking_events WHERE event_type = 'pixel_view' AND blocked = 0")
        total_opens = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT ip_address) FROM tracking_events WHERE blocked = 0")
        unique_visitors = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM tracking_events WHERE blocked = 1")
        blocked_requests = cursor.fetchone()[0]
        
        # Get hourly activity (last 24 hours)
        cursor.execute('''
            SELECT 
                strftime('%H:00', timestamp) as hour,
                COUNT(CASE WHEN event_type = 'click' AND blocked = 0 THEN 1 END) as clicks,
                COUNT(CASE WHEN event_type = 'pixel_view' AND blocked = 0 THEN 1 END) as opens,
                COUNT(CASE WHEN blocked = 1 THEN 1 END) as blocked
            FROM tracking_events 
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY strftime('%H', timestamp)
            ORDER BY hour
        ''')
        hourly_data = cursor.fetchall()
        
        # Get top countries
        cursor.execute('''
            SELECT 
                country_code,
                COUNT(CASE WHEN event_type = 'click' AND blocked = 0 THEN 1 END) as clicks,
                COUNT(CASE WHEN event_type = 'pixel_view' AND blocked = 0 THEN 1 END) as opens
            FROM tracking_events 
            WHERE blocked = 0 AND country_code != 'XX'
            GROUP BY country_code
            ORDER BY (clicks + opens) DESC
            LIMIT 10
        ''')
        country_data = cursor.fetchall()
        
        # Get device types
        cursor.execute('''
            SELECT 
                device_type,
                COUNT(*) as count
            FROM tracking_events 
            WHERE blocked = 0 AND device_type != 'Unknown'
            GROUP BY device_type
        ''')
        device_data = cursor.fetchall()
        
        # Get security events
        cursor.execute('''
            SELECT 
                CASE 
                    WHEN is_bot = 1 THEN 'Bot Detected'
                    WHEN block_reason LIKE '%referrer%' THEN 'Social Referrer'
                    WHEN block_reason LIKE '%rate%' THEN 'Rate Limited'
                    ELSE 'Other'
                END as event_type,
                COUNT(*) as count
            FROM tracking_events 
            WHERE blocked = 1
            GROUP BY event_type
        ''')
        security_data = cursor.fetchall()
        
        # Get recent activity
        cursor.execute('''
            SELECT 
                event_type,
                country_code,
                city,
                device_type,
                browser,
                blocked,
                timestamp
            FROM tracking_events 
            ORDER BY timestamp DESC
            LIMIT 20
        ''')
        recent_activity = cursor.fetchall()
        
        conn.close()
        
        # Format response
        analytics = {
            'overview': {
                'totalClicks': total_clicks,
                'totalOpens': total_opens,
                'uniqueVisitors': unique_visitors,
                'conversionRate': round((total_clicks / max(total_opens, 1)) * 100, 1),
                'blockedRequests': blocked_requests,
                'riskScore': min(blocked_requests / max(total_clicks + total_opens, 1), 1.0)
            },
            'hourlyActivity': [
                {'hour': row[0], 'clicks': row[1], 'opens': row[2], 'blocked': row[3]}
                for row in hourly_data
            ],
            'topCountries': [
                {
                    'country': get_country_name(row[0]),
                    'code': row[0],
                    'clicks': row[1],
                    'opens': row[2],
                    'percentage': round(((row[1] + row[2]) / max(total_clicks + total_opens, 1)) * 100, 1)
                }
                for row in country_data
            ],
            'deviceTypes': [
                {
                    'name': row[0],
                    'count': row[1],
                    'value': round((row[1] / max(sum(d[1] for d in device_data), 1)) * 100, 1)
                }
                for row in device_data
            ],
            'securityEvents': [
                {'type': row[0], 'count': row[1], 'severity': 'high' if 'Bot' in row[0] else 'medium'}
                for row in security_data
            ],
            'recentActivity': [
                {
                    'time': get_time_ago(row[6]),
                    'event': format_event_name(row[0]),
                    'location': f"{row[2]}, {row[1]}" if row[2] != 'Unknown' else row[1],
                    'device': row[4] if row[4] != 'Unknown' else row[3],
                    'status': 'blocked' if row[5] else 'success'
                }
                for row in recent_activity
            ]
        }
        
        return jsonify(analytics)
        
    except Exception as e:
        print(f"Error getting analytics: {e}")
        return jsonify({'error': 'Failed to get analytics'}), 500

def get_country_name(code):
    country_names = {
        'US': 'United States', 'GB': 'United Kingdom', 'CA': 'Canada',
        'AU': 'Australia', 'DE': 'Germany', 'FR': 'France', 'JP': 'Japan',
        'CN': 'China', 'IN': 'India', 'BR': 'Brazil'
    }
    return country_names.get(code, code)

def get_time_ago(timestamp):
    try:
        event_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        now = datetime.now()
        diff = now - event_time
        
        if diff.seconds < 60:
            return f"{diff.seconds} sec ago"
        elif diff.seconds < 3600:
            return f"{diff.seconds // 60} min ago"
        elif diff.days == 0:
            return f"{diff.seconds // 3600} hr ago"
        else:
            return f"{diff.days} day ago"
    except:
        return "Unknown"

def format_event_name(event_type):
    names = {
        'pixel_view': 'Email opened',
        'click': 'Link clicked',
        'pixel_blocked': 'Email blocked',
        'click_blocked': 'Click blocked'
    }
    return names.get(event_type, event_type)

# Health check
@app.route('/health')
def health():
    return jsonify({'status': 'OK', 'timestamp': datetime.now().isoformat()})

# Serve frontend
@app.route('/')
def serve_frontend():
    return send_file('static/index.html')

@app.route('/<path:path>')
def serve_static(path):
    # Don't serve static files for API routes
    if path.startswith('api/'):
        return jsonify({'error': 'API endpoint not found'}), 404
    return send_file(f'static/{path}')

# API endpoint to get link status history
@app.route('/api/tracking-links/<tracking_token>/status-history')
@require_auth
def get_link_status_history(tracking_token):
    try:
        history = SecurityService.get_link_status_history(tracking_token)
        return jsonify({'history': history})
    except Exception as e:
        print(f"Get status history error: {e}")
        return jsonify({'error': 'Failed to get status history'}), 500

# API endpoint to manually update link status (admin only)
@app.route('/api/tracking-links/<tracking_token>/status', methods=['PUT'])
@require_auth
def update_link_status_api(tracking_token):
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if not new_status:
            return jsonify({'error': 'Status is required'}), 400
        
        # Check if user has permission (admin or link owner)
        user = get_current_user()
        if user['role'] not in ['admin', 'admin2']:
            # Check if user owns this link
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT user_id FROM tracking_links WHERE tracking_token = ?', (tracking_token,))
            result = cursor.fetchone()
            conn.close()
            
            if not result or result[0] != user['id']:
                return jsonify({'error': 'Permission denied'}), 403
        
        success = SecurityService.update_link_status(tracking_token, new_status, 'manual_update')
        
        if success:
            return jsonify({'message': 'Status updated successfully'})
        else:
            return jsonify({'error': 'Failed to update status'}), 500
            
    except Exception as e:
        print(f"Update status error: {e}")
        return jsonify({'error': 'Failed to update status'}), 500

# Role-based analytics endpoints
@app.route('/api/analytics/hierarchy')
@require_auth
def get_hierarchy_analytics():
    try:
        user = get_current_user()
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        if user['role'] == 'admin':
            # Admin sees everything
            cursor.execute('''
                SELECT 
                    u.role,
                    COUNT(DISTINCT u.id) as user_count,
                    COUNT(DISTINCT c.id) as campaign_count,
                    COUNT(DISTINCT tl.id) as link_count,
                    COALESCE(SUM(tl.clicks), 0) as total_clicks,
                    COALESCE(SUM(tl.opens), 0) as total_opens
                FROM users u
                LEFT JOIN campaigns c ON u.id = c.user_id
                LEFT JOIN tracking_links tl ON c.id = tl.campaign_id
                GROUP BY u.role
            ''')
            
        elif user['role'] == 'admin2':
            # Admin2 sees their team only
            cursor.execute('''
                SELECT 
                    u.role,
                    COUNT(DISTINCT u.id) as user_count,
                    COUNT(DISTINCT c.id) as campaign_count,
                    COUNT(DISTINCT tl.id) as link_count,
                    COALESCE(SUM(tl.clicks), 0) as total_clicks,
                    COALESCE(SUM(tl.opens), 0) as total_opens
                FROM users u
                LEFT JOIN campaigns c ON u.id = c.user_id
                LEFT JOIN tracking_links tl ON c.id = tl.campaign_id
                WHERE u.created_by = ? OR u.id = ?
                GROUP BY u.role
            ''', (user['id'], user['id']))
            
        else:
            # Members and Workers see only their own data
            cursor.execute('''
                SELECT 
                    ? as role,
                    1 as user_count,
                    COUNT(DISTINCT c.id) as campaign_count,
                    COUNT(DISTINCT tl.id) as link_count,
                    COALESCE(SUM(tl.clicks), 0) as total_clicks,
                    COALESCE(SUM(tl.opens), 0) as total_opens
                FROM campaigns c
                LEFT JOIN tracking_links tl ON c.id = tl.campaign_id
                WHERE c.user_id = ?
            ''', (user['role'], user['id']))
        
        results = cursor.fetchall()
        conn.close()
        
        hierarchy_data = []
        for row in results:
            hierarchy_data.append({
                'role': row[0],
                'user_count': row[1],
                'campaign_count': row[2],
                'link_count': row[3],
                'total_clicks': row[4],
                'total_opens': row[5],
                'conversion_rate': (row[4] / row[5] * 100) if row[5] > 0 else 0
            })
        
        return jsonify({'hierarchy_analytics': hierarchy_data})
        
    except Exception as e:
        print(f"Hierarchy analytics error: {e}")
        return jsonify({'error': 'Failed to fetch hierarchy analytics'}), 500

@app.route('/api/analytics/campaigns')
@require_auth
def get_campaign_analytics():
    try:
        user = get_current_user()
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        if user['role'] == 'admin':
            # Admin sees all campaigns
            cursor.execute('''
                SELECT 
                    c.id, c.name, c.status, c.created_at,
                    u.username as owner,
                    COUNT(DISTINCT tl.id) as link_count,
                    COALESCE(SUM(tl.clicks), 0) as total_clicks,
                    COALESCE(SUM(tl.opens), 0) as total_opens
                FROM campaigns c
                JOIN users u ON c.user_id = u.id
                LEFT JOIN tracking_links tl ON c.id = tl.campaign_id
                GROUP BY c.id, c.name, c.status, c.created_at, u.username
                ORDER BY c.created_at DESC
            ''')
            
        elif user['role'] == 'admin2':
            # Admin2 sees campaigns from their team
            cursor.execute('''
                SELECT 
                    c.id, c.name, c.status, c.created_at,
                    u.username as owner,
                    COUNT(DISTINCT tl.id) as link_count,
                    COALESCE(SUM(tl.clicks), 0) as total_clicks,
                    COALESCE(SUM(tl.opens), 0) as total_opens
                FROM campaigns c
                JOIN users u ON c.user_id = u.id
                LEFT JOIN tracking_links tl ON c.id = tl.campaign_id
                WHERE u.created_by = ? OR u.id = ?
                GROUP BY c.id, c.name, c.status, c.created_at, u.username
                ORDER BY c.created_at DESC
            ''', (user['id'], user['id']))
            
        else:
            # Members and Workers see only their own campaigns
            cursor.execute('''
                SELECT 
                    c.id, c.name, c.status, c.created_at,
                    ? as owner,
                    COUNT(DISTINCT tl.id) as link_count,
                    COALESCE(SUM(tl.clicks), 0) as total_clicks,
                    COALESCE(SUM(tl.opens), 0) as total_opens
                FROM campaigns c
                LEFT JOIN tracking_links tl ON c.id = tl.campaign_id
                WHERE c.user_id = ?
                GROUP BY c.id, c.name, c.status, c.created_at
                ORDER BY c.created_at DESC
            ''', (user['username'], user['id']))
        
        results = cursor.fetchall()
        conn.close()
        
        campaigns_data = []
        for row in results:
            campaigns_data.append({
                'id': row[0],
                'name': row[1],
                'status': row[2],
                'created_at': row[3],
                'owner': row[4],
                'link_count': row[5],
                'total_clicks': row[6],
                'total_opens': row[7],
                'conversion_rate': (row[6] / row[7] * 100) if row[7] > 0 else 0
            })
        
        return jsonify({'campaigns': campaigns_data})
        
    except Exception as e:
        print(f"Campaign analytics error: {e}")
        return jsonify({'error': 'Failed to fetch campaign analytics'}), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)


# New API endpoints for tracking links management

@app.route('/api/tracking-links', methods=['GET'])
def get_tracking_links():
    """Get all tracking links with their details"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                tl.id,
                tl.tracking_token,
                tl.original_url,
                tl.recipient_email,
                tl.created_at,
                tl.is_active,
                c.name as campaign_name,
                COUNT(te.id) as total_events,
                COUNT(CASE WHEN te.event_type = 'click' AND te.blocked = 0 THEN 1 END) as clicks,
                COUNT(CASE WHEN te.event_type = 'pixel_view' AND te.blocked = 0 THEN 1 END) as opens
            FROM tracking_links tl
            LEFT JOIN campaigns c ON tl.campaign_id = c.id
            LEFT JOIN tracking_events te ON tl.tracking_token = te.tracking_token
            GROUP BY tl.id, tl.tracking_token, tl.original_url, tl.recipient_email, tl.created_at, tl.is_active, c.name
            ORDER BY tl.created_at DESC
        ''')
        
        links = cursor.fetchall()
        conn.close()
        
        tracking_links = []
        for link in links:
            tracking_links.append({
                'id': link[0],
                'tracking_token': link[1],
                'original_url': link[2],
                'recipient_email': link[3] or 'N/A',
                'created_at': link[4],
                'is_active': bool(link[5]),
                'campaign_name': link[6] or 'Default Campaign',
                'total_events': link[7],
                'clicks': link[8],
                'opens': link[9],
                'tracking_url': f"{request.host_url}track/click/{link[1]}",
                'pixel_url': f"{request.host_url}track/pixel/{link[1]}"
            })
        
        return jsonify({
            'success': True,
            'tracking_links': tracking_links,
            'total_count': len(tracking_links)
        })
        
    except Exception as e:
        print(f"Error getting tracking links: {e}")
        return jsonify({'success': False, 'error': 'Failed to get tracking links'}), 500

@app.route('/api/tracking-links', methods=['POST'])
def create_tracking_link():
    """Create a new tracking link"""
    try:
        data = request.get_json()
        original_url = data.get('original_url')
        recipient_email = data.get('recipient_email', '')
        campaign_name = data.get('campaign_name', 'Default Campaign')
        
        if not original_url:
            return jsonify({'success': False, 'error': 'Original URL is required'}), 400
        
        # Validate URL format
        if not original_url.startswith(('http://', 'https://')):
            original_url = 'https://' + original_url
        
        # Generate unique tracking token
        import uuid
        tracking_token = str(uuid.uuid4()).replace('-', '')[:16]
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get or create campaign
        cursor.execute("SELECT id FROM campaigns WHERE name = ?", (campaign_name,))
        campaign = cursor.fetchone()
        
        if not campaign:
            cursor.execute("INSERT INTO campaigns (name, description) VALUES (?, ?)", 
                         (campaign_name, f"Campaign for {original_url}"))
            campaign_id = cursor.lastrowid
        else:
            campaign_id = campaign[0]
        
        # Create tracking link
        cursor.execute('''
            INSERT INTO tracking_links (campaign_id, original_url, tracking_token, recipient_email)
            VALUES (?, ?, ?, ?)
        ''', (campaign_id, original_url, tracking_token, recipient_email))
        
        link_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        tracking_url = f"{request.host_url}track/click/{tracking_token}"
        pixel_url = f"{request.host_url}track/pixel/{tracking_token}"
        
        return jsonify({
            'success': True,
            'tracking_link': {
                'id': link_id,
                'tracking_token': tracking_token,
                'original_url': original_url,
                'recipient_email': recipient_email,
                'campaign_name': campaign_name,
                'tracking_url': tracking_url,
                'pixel_url': pixel_url,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        })
        
    except Exception as e:
        print(f"Error creating tracking link: {e}")
        return jsonify({'success': False, 'error': 'Failed to create tracking link'}), 500

@app.route('/api/tracking-events/<token>', methods=['GET'])
def get_tracking_events(token):
    """Get all events for a specific tracking token"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                id,
                event_type,
                ip_address,
                user_agent,
                country_code,
                city,
                device_type,
                browser,
                is_bot,
                blocked,
                block_reason,
                timestamp
            FROM tracking_events 
            WHERE tracking_token = ?
            ORDER BY timestamp DESC
        ''', (token,))
        
        events = cursor.fetchall()
        conn.close()
        
        tracking_events = []
        for event in events:
            tracking_events.append({
                'id': event[0],
                'event_type': event[1],
                'ip_address': event[2],
                'user_agent': event[3],
                'country_code': event[4],
                'city': event[5],
                'device_type': event[6],
                'browser': event[7],
                'is_bot': bool(event[8]),
                'blocked': bool(event[9]),
                'block_reason': event[10],
                'timestamp': event[11]
            })
        
        return jsonify({
            'success': True,
            'events': tracking_events,
            'total_count': len(tracking_events)
        })
        
    except Exception as e:
        print(f"Error getting tracking events: {e}")
        return jsonify({'success': False, 'error': 'Failed to get tracking events'}), 500


