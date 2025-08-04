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
# from PIL import Image  # Commented out for Vercel compatibility
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
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__, static_folder='static')
CORS(app, origins="*")

# Configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "your-default-secret-key-if-not-set")
app.config["SECRET_KEY"] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
=7)
        
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
        
        conn = current_app.get_db_connection()
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
        
        conn = current_app.get_db_connection()
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

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return send_from_directory(app.static_folder, 'index.html')

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/users', methods=['GET'])
@require_auth
def get_users():
    """Get all users (admin only)"""
    try:
        if request.current_user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        conn = current_app.get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                SELECT id, username, email, role, status, created_at, last_login
                FROM users ORDER BY created_at DESC
            """)
        else:
            cursor.execute("""
                SELECT id, username, email, role, status, created_at, last_login
                FROM users ORDER BY created_at DESC
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
                'last_login': user[6]
            })
        
        return jsonify(user_list)
        
    except Exception as e:
        print(f"Get users error: {e}")
        return jsonify({'error': 'Failed to fetch users'}), 500

@app.route('/api/users/<int:user_id>/approve', methods=['POST'])
@require_auth
def approve_user(user_id):
    """Approve a pending user (admin only)"""
    try:
        if request.current_user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        conn = current_app.get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("UPDATE users SET status = 'active' WHERE id = %s", (user_id,))
        else:
            cursor.execute("UPDATE users SET status = 'active' WHERE id = ?", (user_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'User approved successfully'})
        
    except Exception as e:
        print(f"Approve user error: {e}")
        return jsonify({'error': 'Failed to approve user'}), 500

@app.route('/api/users/<int:user_id>/reject', methods=['POST'])
@require_auth
def reject_user(user_id):
    """Reject a pending user (admin only)"""
    try:
        if request.current_user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        conn = current_app.get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("UPDATE users SET status = 'rejected' WHERE id = %s", (user_id,))
        else:
            cursor.execute("UPDATE users SET status = 'rejected' WHERE id = ?", (user_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'User rejected successfully'})
        
    except Exception as e:
        print(f"Reject user error: {e}")
        return jsonify({'error': 'Failed to reject user'}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@require_auth
def delete_user(user_id):
    """Delete a user (admin only)"""
    try:
        if request.current_user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        conn = current_app.get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        else:
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'User deleted successfully'})
        
    except Exception as e:
        print(f"Delete user error: {e}")
        return jsonify({'error': 'Failed to delete user'}), 500

@app.route('/api/analytics', methods=['GET'])
@require_auth
def get_analytics():
    """Get analytics data"""
    try:
        conn = current_app.get_db_connection()
        cursor = conn.cursor()
        
        # Get user counts
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'active'")
            active_users = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'pending'")
            pending_users = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            admin_users = cursor.fetchone()[0]
        else:
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'active'")
            active_users = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'pending'")
            pending_users = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            admin_users = cursor.fetchone()[0]
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'total_users': total_users,
            'active_users': active_users,
            'pending_users': pending_users,
            'admin_users': admin_users,
            'last_updated': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Analytics error: {e}")
        return jsonify({'error': 'Failed to fetch analytics'}), 500

