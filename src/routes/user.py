from flask import Blueprint, jsonify, request, current_app
from src.models.user import User, db

user_bp = Blueprint("user", __name__)

@user_bp.route("/users", methods=["GET"])
def get_users():
    conn = current_app.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, status FROM users")
    users_data = cursor.fetchall()
    conn.close()
    users = []
    for user_data in users_data:
        users.append({
            "id": user_data[0],
            "username": user_data[1],
            "email": user_data[2],
            "role": user_data[3],
            "status": user_data[4]
        })
    return jsonify(users)

@user_bp.route('/users', methods=['POST'])
def create_user():
    
    data = request.json
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"error": "Username, email, and password are required"}), 400

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    conn = current_app.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id, username, email, role, status",
            (username, email, hashed_password)
        )
        new_user = cursor.fetchone()
        conn.commit()
        return jsonify({
            "id": new_user[0],
            "username": new_user[1],
            "email": new_user[2],
            "role": new_user[3],
            "status": new_user[4]
        }), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@user_bp.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    conn = current_app.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT id, username, email, role, status FROM users WHERE id = %s",
            (user_id,)
        )
        user_data = cursor.fetchone()
        if not user_data:
            return jsonify({"error": "User not found"}), 404
        return jsonify({
            "id": user_data[0],
            "username": user_data[1],
            "email": user_data[2],
            "role": user_data[3],
            "status": user_data[4]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@user_bp.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    data = request.json
    conn = current_app.get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        if not cursor.fetchone():
            return jsonify({"error": "User not found"}), 404

        updates = []
        params = []
        if "username" in data:
            updates.append("username = %s")
            params.append(data["username"])
        if "email" in data:
            updates.append("email = %s")
            params.append(data["email"])
        if "role" in data:
            updates.append("role = %s")
            params.append(data["role"])
        if "status" in data:
            updates.append("status = %s")
            params.append(data["status"])

        if not updates:
            return jsonify({"message": "No fields to update"}), 200

        params.append(user_id)
        cursor.execute(
            f"UPDATE users SET {', '.join(updates)} WHERE id = %s RETURNING id, username, email, role, status",
            tuple(params)
        )
        updated_user = cursor.fetchone()
        conn.commit()
        return jsonify({
            "id": updated_user[0],
            "username": updated_user[1],
            "email": updated_user[2],
            "role": updated_user[3],
            "status": updated_user[4]
        })
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@user_bp.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    conn = current_app.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        if cursor.rowcount == 0:
            conn.rollback()
            return jsonify({"error": "User not found"}), 404
        conn.commit()
        return '', 204
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()
