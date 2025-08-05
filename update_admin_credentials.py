#!/usr/bin/env python3
"""
Script to update admin credentials for Brain Link Tracker
"""
import os
import psycopg2
from werkzeug.security import generate_password_hash

# Database connection
DATABASE_URL = "postgresql://neondb_owner:npg_0y9XMKzHCBsN@ep-blue-resonance-add39g5q-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"

def update_admin_credentials():
    try:
        # Connect to database
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        # Hash the new passwords
        brain_password_hash = generate_password_hash("Mayflower1!!")
        admin_password_hash = generate_password_hash("Admin123")
        
        # Update main admin (change username from 'admin' to 'Brain')
        cursor.execute("""
            UPDATE users 
            SET username = %s, password_hash = %s 
            WHERE username = 'admin' AND role = 'admin'
        """, ('Brain', brain_password_hash))
        
        # Check if Admin2 user exists, if not create it
        cursor.execute("SELECT id FROM users WHERE username = 'Admin' AND role = 'admin2'")
        admin2_exists = cursor.fetchone()
        
        if not admin2_exists:
            # Create Admin2 user
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, status, created_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
            """, ('Admin', 'admin2@brainlinktracker.com', admin_password_hash, 'admin2', 'active'))
            print("Created new Admin2 user")
        else:
            # Update existing Admin2 user
            cursor.execute("""
                UPDATE users 
                SET password_hash = %s 
                WHERE username = 'Admin' AND role = 'admin2'
            """, (admin_password_hash,))
            print("Updated existing Admin2 user")
        
        # Commit changes
        conn.commit()
        print("✅ Admin credentials updated successfully!")
        print("Main Admin: Brain / Mayflower1!!")
        print("Admin2: Admin / Admin123")
        
        # Verify the changes
        cursor.execute("SELECT username, role FROM users WHERE role IN ('admin', 'admin2')")
        admin_users = cursor.fetchall()
        print("\nCurrent admin users:")
        for user in admin_users:
            print(f"- {user[0]} ({user[1]})")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"❌ Error updating admin credentials: {e}")
        if 'conn' in locals():
            conn.rollback()
            conn.close()

if __name__ == "__main__":
    update_admin_credentials()

