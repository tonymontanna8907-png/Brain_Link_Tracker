import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from main_vercel import app, init_db, get_db_connection, DATABASE_TYPE
import bcrypt

# Initialize the database when the module is imported
try:
    init_db()
    print("✅ Database initialized for Vercel deployment")
    
    # Force admin user creation
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if admin user exists
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
            print("✅ Admin user created for Vercel deployment")
        else:
            print("✅ Admin user already exists")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"Admin user creation error: {e}")
    
except Exception as e:
    print(f"Database initialization error: {e}")

# Export the Flask app for Vercel
app = app

