from flask import Blueprint, request, jsonify, session, current_app
from werkzeug.security import check_password_hash
from datetime import datetime, timedelta
import secrets
import re
import json
import pyotp
import qrcode
import io
import base64
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
import smtplib

auth_bp = Blueprint('auth', __name__)

def get_client_ip():
    """Get client IP address"""
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
    return request.environ.get('REMOTE_ADDR', 'unknown')

def get_user_agent():
    """Get user agent"""
    return request.headers.get('User-Agent', 'unknown')

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password_strength(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is strong"

def log_audit_event(action, user_id=None, resource_type=None, resource_id=None, details=None):
    """Log audit event"""
    try:
        audit_log = AuditLog(
            action=action,
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=get_client_ip(),
            user_agent=get_user_agent()
        )
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        print(f"Failed to log audit event: {e}")

def send_email(to_email, subject, body, is_html=False):
    """Send email (placeholder - implement with your email service)"""
    # This is a placeholder. In production, use services like:
    # - SendGrid, Mailgun, AWS SES, etc.
    print(f"EMAIL TO: {to_email}")
    print(f"SUBJECT: {subject}")
    print(f"BODY: {body}")
    return True

@auth_bp.route('/register', methods=['POST'])
def register():
    """Advanced user registration with validation"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'email', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        username = data['username'].strip().lower()
        email = data['email'].strip().lower()
        password = data['password']
        
        # Validate email format
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate password strength
        is_strong, message = validate_password_strength(password)
        if not is_strong:
            return jsonify({'error': message}), 400
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        conn = current_app.get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, first_name, last_name, company, phone, timezone) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id, email",
                (username, email, user.password_hash, data.get("first_name", "").strip(),
                 data.get("last_name", "").strip(), data.get("company", "").strip(),
                 data.get("phone", "").strip(), data.get("timezone", "UTC"))
            )
            new_user_id, new_user_email = cursor.fetchone()
            conn.commit()

            # Generate email verification token
            verification_token = user.generate_email_verification_token()
            # Update the user with the verification token in the database
            cursor.execute(
                "UPDATE users SET email_verification_token = %s, email_verification_sent_at = %s WHERE id = %s",
                (verification_token, datetime.utcnow(), new_user_id)
            )
            conn.commit()

            # Send verification email
            verification_link = f"{request.host_url}auth/verify-email?token={verification_token}"
            email_body = f"""
            Welcome to 7th Brain Link Tracker!

            Please verify your email address by clicking the link below:
            {verification_link}

            This link will expire in 24 hours.

            If you didn't create this account, please ignore this email.
            """

            send_email(new_user_email, "Verify your 7th Brain account", email_body)

            # Log registration
            log_audit_event("user_registered", new_user_id, "user", str(new_user_id), {
                "username": username,
                "email": email
            })

            return jsonify({
                "message": "Registration successful. Please check your email to verify your account.",
                "user_id": new_user_id
            }), 201
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """Advanced login with security features"""
    try:
        data = request.get_json()
        
        if not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Username and password are required'}), 400
        
        username = data['username'].strip().lower()
        password = data['password']
        
    conn = current_app.get_db_connection()
    cursor = conn.cursor()
    try:
        # Find user by username or email
        cursor.execute(
            "SELECT id, username, password_hash, role, status, failed_login_attempts, locked_until, two_factor_enabled, totp_secret, backup_codes FROM users WHERE username = %s OR email = %s",
            (username, username)
        )
        user_data = cursor.fetchone()

        if not user_data:
            log_audit_event("login_failed", None, "auth", None, {"username": username, "reason": "user_not_found"})
            return jsonify({"error": "Invalid credentials"}), 401

        user_id, db_username, password_hash, role, status, failed_login_attempts, locked_until, two_factor_enabled, totp_secret, backup_codes = user_data

        # Check if account is locked
        if locked_until and datetime.utcnow() < locked_until:
            log_audit_event("login_blocked", user_id, "auth", None, {"reason": "account_locked"})
            return jsonify({"error": "Account is temporarily locked due to multiple failed login attempts"}), 423

        # Check if account is active
        if status != "active":
            log_audit_event("login_blocked", user_id, "auth", None, {"reason": "account_inactive"})
            return jsonify({"error": "Account is deactivated"}), 403

        # Verify password
        if not check_password_hash(password_hash, password):
            failed_login_attempts += 1
            if failed_login_attempts >= 5:
                locked_until = datetime.utcnow() + timedelta(minutes=30)
                cursor.execute("UPDATE users SET failed_login_attempts = %s, locked_until = %s WHERE id = %s",
                               (failed_login_attempts, locked_until, user_id))
                conn.commit()
                log_audit_event("account_locked", user_id, "auth", None, {"reason": "too_many_failed_attempts"})
                return jsonify({"error": "Account locked due to too many failed login attempts"}), 423
            cursor.execute("UPDATE users SET failed_login_attempts = %s WHERE id = %s", (failed_login_attempts, user_id))
            conn.commit()
            log_audit_event("login_failed", user_id, "auth", None, {"reason": "invalid_password", "failed_attempts": failed_login_attempts})
            return jsonify({"error": "Invalid credentials"}), 401

        # Check if 2FA is enabled
        if two_factor_enabled:
            totp_token = data.get("totp_token")
            backup_code = data.get("backup_code")

            if not totp_token and not backup_code:
                return jsonify({"requires_2fa": True, "message": "Two-factor authentication required"}), 200

            import pyotp
            totp = pyotp.TOTP(totp_secret)

            if totp_token and not totp.verify(totp_token, valid_window=1):
                log_audit_event("2fa_failed", user_id, "auth", None, {"method": "totp"})
                return jsonify({"error": "Invalid 2FA code"}), 401

            if backup_code:
                codes = json.loads(backup_codes) if backup_codes else []
                if backup_code.upper() not in codes:
                    log_audit_event("2fa_failed", user_id, "auth", None, {"method": "backup_code"})
                    return jsonify({"error": "Invalid backup code"}), 401
                codes.remove(backup_code.upper())
                cursor.execute("UPDATE users SET backup_codes = %s WHERE id = %s", (json.dumps(codes), user_id))
                conn.commit()

        # Successful login
        ip_address = get_client_ip()
        cursor.execute("UPDATE users SET last_login = %s, last_login_ip = %s, failed_login_attempts = 0, locked_until = NULL WHERE id = %s",
                       (datetime.utcnow(), ip_address, user_id))

        # Create login session
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(days=30)
        cursor.execute("INSERT INTO user_sessions (user_id, session_token, expires_at, ip_address, user_agent) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                       (user_id, session_token, expires_at, ip_address, get_user_agent()))
        login_session_id = cursor.fetchone()[0]
        conn.commit()

        log_audit_event("login_successful", user_id, "auth", None, {"ip_address": ip_address, "session_id": login_session_id})

        return jsonify({
            "message": "Login successful",
            "user": {"id": user_id, "username": db_username, "role": role, "status": status},
            "session_token": session_token
        }), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()}), 500
    finally:
        conn.close()
        
    except Exception as e:
        return jsonify({'error': 'Login failed'}), 500

@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Logout and invalidate session"""
    try:
        session_token = request.headers.get("Authorization")
        if session_token and session_token.startswith("Bearer "):
            session_token = session_token[7:]

        if session_token:
            conn = current_app.get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("UPDATE user_sessions SET expires_at = %s WHERE session_token = %s",
                               (datetime.utcnow(), session_token))
                conn.commit()
                log_audit_event("logout", None, "auth", None, {"session_token": session_token})
            except Exception as e:
                conn.rollback()
                print(f"Failed to invalidate session: {e}")
            finally:
                conn.close()

        return jsonify({"message": "Logout successful"}), 200

    except Exception as e:
        return jsonify({"error": "Logout failed"}), 500

@auth_bp.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    """Verify email address"""
    try:
        token = request.args.get('token') or request.json.get('token')
        
        if not token:
            return jsonify({'error': 'Verification token is required'}), 400
        conn = current_app.get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id, email_verification_token, email_verification_sent_at FROM users WHERE email_verification_token = %s", (token,))
            user_data = cursor.fetchone()

            if not user_data:
                return jsonify({"error": "Invalid or expired verification token"}), 400

            user_id, db_token, sent_at = user_data

            if not db_token or (datetime.utcnow() - sent_at) > timedelta(hours=24):
                return jsonify({"error": "Invalid or expired verification token"}), 400

            cursor.execute("UPDATE users SET status = %s, email_verification_token = NULL, email_verification_sent_at = NULL WHERE id = %s",
                           ("active", user_id))
            conn.commit()

            log_audit_event("email_verified", user_id, "user", str(user_id))

            return jsonify({"message": "Email verified successfully"}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

uth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    """Request password reset"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        conn = current_app.get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id, email FROM users WHERE email = %s", (email,))
            user_data = cursor.fetchone()

            if user_data:
                user_id, user_email = user_data
                reset_token = secrets.token_urlsafe(32)
                reset_expires = datetime.utcnow() + timedelta(hours=1)
                cursor.execute("UPDATE users SET password_reset_token = %s, password_reset_expires_at = %s WHERE id = %s",
                               (reset_token, reset_expires, user_id))
                conn.commit()

                # Send reset email
                reset_link = f"{request.host_url}auth/reset-password?token={reset_token}"
                email_body = f"""
                Password Reset Request
                
                Click the link below to reset your password:
                {reset_link}
                
                This link will expire in 1 hour.
                
                If you didn\'t request this reset, please ignore this email.
                """
                
                send_email(user_email, "Password Reset - 7th Brain", email_body)
                
                log_audit_event("password_reset_requested", user_id, "auth", None)
            
            # Always return success to prevent email enumeration
            return jsonify({"message": "If the email exists, a reset link has been sent"}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()  
    except Exception as e:
        return jsonify({'error': 'Password reset request failed'}), 500

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """Reset password with token"""
    try:
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('password')
        
        if not token or not new_password:
            return jsonify({'error': 'Token and new password are required'}), 400
        
        # Validate password strength
        is_strong, message = validate_password_strength(new_password)
        if not is_strong:
            return jsonify({'error': message}), 400
        conn = current_app.get_db_connection()
        cursor = conn.cursor()
        try:
            user_data = cursor.fetchone()

            if not user_data:
                return jsonify({"error": "Invalid or expired reset token"}), 400

            user_id, db_token, expires_at = user_data

            if not db_token or (datetime.utcnow() > expires_at):
                return jsonify({"error": "Invalid or expired reset token"}), 400

            hashed_password = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET password_hash = %s, password_reset_token = NULL, password_reset_expires_at = NULL WHERE id = %s",
                           (hashed_password, user_id))
            conn.commit()

            log_audit_event("password_reset_completed", user_id, "auth", None)

            # Send confirmation email
            # You might need to fetch the user's email here if not already available
            cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
            user_email = cursor.fetchone()[0]
            send_email(user_email, "Password Changed - 7th Brain", 
                      "Your password has been successfully changed.")

            return jsonify({"message": "Password reset successful"}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()      
    except Exception as e:
        return jsonify({'error': 'Password reset failed'}), 500

@auth_bp.route('/setup-2fa', methods=['POST'])
@login_required
def setup_2fa():
    """Setup two-factor authentication"""
    try:
        if current_user.two_factor_enabled:
            return jsonify({'error': '2FA is already enabled'}), 400
        
        secret, backup_codes = current_user.setup_two_factor()
        
        # Generate QR code
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=current_user.email,
            issuer_name="7th Brain Link Tracker"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code_data = base64.b64encode(buffer.getvalue()).decode()
        
        db.session.commit()
        
        log_audit_event('2fa_setup_initiated', current_user.id, 'auth', None)
        
        return jsonify({
            'secret': secret,
            'qr_code': f"data:image/png;base64,{qr_code_data}",
            'backup_codes': backup_codes
        }), 200
        
    except Exception as e:
        return jsonify({'error': '2FA setup failed'}), 500

@auth_bp.route('/enable-2fa', methods=['POST'])
@login_required
def enable_2fa():
    """Enable 2FA after verification"""
    try:
        data = request.get_json()
        totp_token = data.get('totp_token')
        
        if not totp_token:
            return jsonify({'error': 'TOTP token is required'}), 400
        
        if not current_user.totp_secret:
            return jsonify({'error': '2FA setup not initiated'}), 400
        
        if current_user.verify_totp(totp_token):
            current_user.two_factor_enabled = True
            db.session.commit()
            
            log_audit_event('2fa_enabled', current_user.id, 'auth', None)
            
            return jsonify({'message': '2FA enabled successfully'}), 200
        else:
            return jsonify({'error': 'Invalid TOTP token'}), 400
            
    except Exception as e:
        return jsonify({'error': '2FA enable failed'}), 500

@auth_bp.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    """Disable two-factor authentication"""
    try:
        data = request.get_json()
        password = data.get('password')
        totp_token = data.get('totp_token')
        
        if not password:
            return jsonify({'error': 'Password is required'}), 400
        
        if not current_user.check_password(password):
            return jsonify({'error': 'Invalid password'}), 401
        
        if current_user.two_factor_enabled and not current_user.verify_totp(totp_token):
            return jsonify({'error': 'Invalid 2FA token'}), 401
        
        current_user.two_factor_enabled = False
        current_user.totp_secret = None
        current_user.backup_codes = None
        
        db.session.commit()
        
        log_audit_event('2fa_disabled', current_user.id, 'auth', None)
        
        return jsonify({'message': '2FA disabled successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': '2FA disable failed'}), 500

@auth_bp.route('/profile', methods=['GET'])
@login_required
def get_profile():
    """Get user profile"""
    return jsonify(current_user.to_dict()), 200

@auth_bp.route('/profile', methods=['PUT'])
@login_required
def update_profile():
    """Update user profile"""
    try:
        data = request.get_json()
        
        # Update allowed fields
        allowed_fields = ['first_name', 'last_name', 'company', 'phone', 'timezone']
        for field in allowed_fields:
            if field in data:
                setattr(current_user, field, data[field])
        
        db.session.commit()
        
        log_audit_event('profile_updated', current_user.id, 'user', str(current_user.id))
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': current_user.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Profile update failed'}), 500

@auth_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """Change password"""
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Current and new passwords are required'}), 400
        
        if not current_user.check_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Validate new password strength
        is_strong, message = validate_password_strength(new_password)
        if not is_strong:
            return jsonify({'error': message}), 400
        
        current_user.set_password(new_password)
        db.session.commit()
        
        log_audit_event('password_changed', current_user.id, 'auth', None)
        
        # Send confirmation email
        send_email(current_user.email, "Password Changed - 7th Brain", 
                  "Your password has been successfully changed.")
        
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Password change failed'}), 500

@auth_bp.route('/sessions', methods=['GET'])
@login_required
def get_sessions():
    """Get active login sessions"""
    sessions = LoginSession.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).filter(
        LoginSession.expires_at > datetime.utcnow()
    ).order_by(LoginSession.last_activity.desc()).all()
    
    session_data = []
    for s in sessions:
        session_data.append({
            'id': s.id,
            'ip_address': s.ip_address,
            'location': s.location,
            'user_agent': s.user_agent,
            'created_at': s.created_at.isoformat(),
            'last_activity': s.last_activity.isoformat(),
            'is_current': s.session_token == session.get('session_token')
        })
    
    return jsonify({'sessions': session_data}), 200

@auth_bp.route('/sessions/<int:session_id>', methods=['DELETE'])
@login_required
def revoke_session(session_id):
    """Revoke a login session"""
    try:
        login_session = LoginSession.query.filter_by(
            id=session_id,
            user_id=current_user.id
        ).first()
        
        if not login_session:
            return jsonify({'error': 'Session not found'}), 404
        
        login_session.is_active = False
        db.session.commit()
        
        log_audit_event('session_revoked', current_user.id, 'auth', str(session_id))
        
        return jsonify({'message': 'Session revoked successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Session revocation failed'}), 500

@auth_bp.route('/check', methods=['GET'])
def check_auth():
    """Check authentication status"""
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'user': current_user.to_dict()
        }), 200
    else:
        return jsonify({'authenticated': False}), 200

