# server.py
import psycopg2
import os
import base64
import io
import secrets
import string
import jwt
from functools import wraps
from flask_bcrypt import Bcrypt
import datetime
import datetime
from datetime import timedelta
from datetime import timezone, timedelta
from flask import Flask, jsonify, send_file, request, redirect, url_for, render_template
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)

SECRET_KEY = 'UB96tx'
app.secret_key = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
CORS(app, resources={r"/*": {"origins": "*"}})
CORS(app, resources={r"/*": {"origins": "http://127.0.0.1:5501"}})

# CORS(app)

bcrypt = Bcrypt(app)

DATABASE_HOST = "dpg-cosjgr021fec73cheb50-a"
DATABASE_PORT = 5432
DATABASE_NAME = "db_clientcentral_pmg"
DATABASE_USER = "famage"
DATABASE_PASSWORD = "NSu61doJ3iwfR6FikdxeZpYgqoARqK2v"


# DATABASE_HOST = "localhost"
# DATABASE_PORT = 5432
# DATABASE_NAME = "db_clientcentral_pmg"
# DATABASE_USER = "postgres"
# DATABASE_PASSWORD = ".7447"

def get_db_connection():
    return psycopg2.connect(
        host=DATABASE_HOST,
        port=DATABASE_PORT,
        database=DATABASE_NAME,
        user=DATABASE_USER,
        password=DATABASE_PASSWORD
    )

def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS files (
                        id SERIAL PRIMARY KEY,
                        filename TEXT,
                        is_folder INTEGER DEFAULT 0,
                        content BYTEA,
                        icon_data BYTEA,
                        parent_folder_id INTEGER,
                        FOREIGN KEY (parent_folder_id) REFERENCES files(id)

                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS icons (
                        id SERIAL PRIMARY KEY,
                        icon_name TEXT UNIQUE,
                        file_extension TEXT,
                        icon_data BYTEA NOT NULL
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        user_id TEXT PRIMARY KEY,
                        username TEXT UNIQUE,
                        email TEXT UNIQUE,
                        password TEXT,
                        salt TEXT,
                        files_table TEXT
                    )''')



    cursor.execute('''CREATE TABLE IF NOT EXISTS password_resets (
                        id SERIAL PRIMARY KEY,
                        email TEXT,
                        reset_token TEXT,
                        expiry_time TEXT
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS recently_added_files (
                        id SERIAL PRIMARY KEY,
                        file_id INTEGER,
                        filename TEXT,
                        upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (file_id) REFERENCES files(id)
                    )''')

    cursor.execute('''ALTER TABLE users 
                    ADD COLUMN IF NOT EXISTS files_table TEXT''')

    conn.commit()
    conn.close()
create_tables()

def generate_random_id(length=8):
    characters = string.ascii_letters + string.digits
    random_id = ''.join(secrets.choice(characters) for _ in range(length))
    return random_id

random_id = generate_random_id()

def get_file_icon(extension):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT icon_data FROM icons WHERE file_extension = %s", (extension,))
    icon_data = cursor.fetchone()
    conn.close()
    return icon_data[0] if icon_data else None

def list_folder_contents(folder_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename FROM files WHERE parent_folder_id = %s", (folder_id,))
    files = cursor.fetchall()
    conn.close()
    return files

@app.route('/files/<int:file_id>')
def get_file(file_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT filename, content FROM files WHERE id = %s", (file_id,))
    file_data = cursor.fetchone()
    conn.close()
    if file_data:
        filename, content = file_data
        # Return the file as an attachment
        return send_file(
            io.BytesIO(content),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    return jsonify({"error": "File not found"}), 404

# @app.route('/recently_added_files')
# def get_recently_added_files():
#     # Define the number of minutes to keep files in the recently added list
#     minutes_limit = 30  # Change this to the desired number of minutes

#     # Calculate the time X minutes ago from the current time
#     oldest_allowed_time = datetime.datetime.now() - timedelta(minutes=minutes_limit)


#     conn = get_db_connection()
#     cursor = conn.cursor()

#     # Delete files older than the specified minutes limit
#     cursor.execute("DELETE FROM recently_added_files WHERE upload_time < %s", (oldest_allowed_time,))
#     conn.commit()

#     # Fetch the recently added files within the specified minutes limit
#     cursor.execute("SELECT id, filename FROM recently_added_files ORDER BY upload_time DESC")
#     files = cursor.fetchall()
#     conn.close()

#     recently_added_files = [{"id": file_id, "filename": filename} for file_id, filename in files]
#     return jsonify({"files": recently_added_files})

def generate_salt():
    return base64.b64encode(os.urandom(20)).decode('utf-8')

def hash_password(password, salt):
    return generate_password_hash(password + salt)

def username_exists(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT EXISTS(SELECT 1 FROM users WHERE username = %s)", (username,))
    result = cursor.fetchone()[0]
    conn.close()
    return result

def email_exists(email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT EXISTS(SELECT 1 FROM users WHERE email = %s)", (email,))
    result = cursor.fetchone()[0]
    conn.close()
    return result

def get_user_by_username(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_by_email(email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def generate_salt():
    return base64.b64encode(os.urandom(20)).decode('utf-8')

def hash_password(password, salt):
    return bcrypt.generate_password_hash(password + salt).decode('utf-8')

def verify_password(password, hashed_password):
    return bcrypt.check_password_hash(hashed_password, password)



# Function to generate token with expiration time
def generate_token(user_id, expiration_time_minutes=60):
    # Get the current time in UTC timezone
    current_time_utc = datetime.datetime.now(timezone.utc)
    
    # Calculate the expiration time based on the current time
    expiration_time = current_time_utc + datetime.timedelta(minutes=expiration_time_minutes)
    
    # Construct the payload with expiration time
    payload = {
        'user_id': user_id,
        'exp': expiration_time
    }
    
    # Encode the payload into a JWT token
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')



# Function to decode token
def decode_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Invalid token

# Decorator function for verifying token and retrieving user's table name
def login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        # Extract the token from the authorization header
        token = request.headers.get('Authorization')
        print("Received_token:\n", token)

        # Check if token is present
        if not token:
            print("'error': 'Token key is not set or authenticated'")
            return jsonify({'error': 'Token is missing'}), 401
        
        # Remove the "Bearer " prefix from the token
        token = token.replace("Bearer ", "")
        print(token)

        # Decode the token
        payload = decode_token(token)
        
        # Check if payload is valid
        if not payload:
            print("'error': 'Invalid token'")
            return jsonify({'error': 'Invalid token'}), 401

        # Retrieve the user's table name from the payload
        user_id = payload['user_id']
        files_table_name = get_files_table_name(user_id)

        if not files_table_name:
            return jsonify({'error': 'User not found or table name not available'}), 404

        # Attach the user's table name to the request for further processing
        request.user_files_table = files_table_name

        return func(*args, **kwargs)

    return decorated_function

    

# Function to retrieve the user's files table name
def get_files_table_name(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT files_table FROM users WHERE user_id = %s", (user_id,))
    files_table_name = cursor.fetchone()
    conn.close()
    return files_table_name[0] if files_table_name else None

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not (username and email and password):
        return jsonify({"error": "Missing username, email, or password"}), 400

    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
    if cursor.fetchone()[0] > 0:
        conn.close()
        return jsonify({"error": "Username already exists"}), 400

    cursor.execute("SELECT COUNT(*) FROM users WHERE email = %s", (email,))
    if cursor.fetchone()[0] > 0:
        conn.close()
        return jsonify({"error": "Email already exists"}), 400

    # Generate a unique table name for the user's files
    files_table_name = f"UDB_x2fb_64_{uuid.uuid4().hex}"

    # Generate a random ID for the user
    user_id = generate_random_id()

    cursor.execute("INSERT INTO users (user_id, username, email, password, salt, files_table) VALUES (%s, %s, %s, %s, %s, %s)",
                   (user_id, username, email, hashed_password, salt, files_table_name))
    conn.commit()

    # Create a new table for the user's files
    cursor.execute(f'''CREATE TABLE IF NOT EXISTS {files_table_name} (
                        id SERIAL PRIMARY KEY,
                        filename TEXT,
                        is_folder INTEGER DEFAULT 0,
                        content BYTEA,
                        icon_data BYTEA,
                        parent_folder_id INTEGER,
                        FOREIGN KEY (parent_folder_id) REFERENCES {files_table_name}(id)
                    )''')
    conn.commit()

    conn.close()

    return jsonify({"message": "User registered successfully"}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username_or_email = data.get('username_or_email')
    password = data.get('password')

    if not (username_or_email and password):
        return jsonify({"error": "Missing username/email or password"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT user_id, username, email, password, salt, files_table FROM users WHERE username = %s OR email = %s",
                   (username_or_email, username_or_email))
    user = cursor.fetchone()

    print("Retrieved user data from database:", user)

    if user is None:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    user_id, username, email, hashed_password, salt, files_table_name = user

    if not verify_password(password + salt, hashed_password):
        conn.close()
        return jsonify({"error": "Invalid password"}), 401

    # Generate token upon successful login
    token = generate_token(user_id)
    print("Generated token:", token)

    conn.close()

    # Return the token along with the response
    response = {
        "message": "Login successful",
        "token": token,
        "files_table": files_table_name
    }
    return jsonify(response), 200

# # Modify the login route to return the entire response object
# @app.route('/login', methods=['POST'])
# def login():
#     data = request.json
#     username_or_email = data.get('username_or_email')
#     password = data.get('password')

#     if not (username_or_email and password):
#         return jsonify({"error": "Missing username/email or password"}), 400

#     conn = get_db_connection()
#     cursor = conn.cursor()

#     cursor.execute("SELECT user_id, username, email, password, salt, files_table FROM users WHERE username = %s OR email = %s",
#                    (username_or_email, username_or_email))
#     user = cursor.fetchone()

#     if user is None:
#         conn.close()
#         return jsonify({"error": "User not found"}), 404

#     user_id, username, email, hashed_password, salt, files_table_name = user

#     if not verify_password(password + salt, hashed_password):
#         conn.close()
#         return jsonify({"error": "Invalid password"}), 401

#     # Retrieve the files_table_name
#     files_table_name = get_files_table_name(user_id)

#     conn.close()

#     # Return the files_table_name along with the response
#     response = {
#         "message": "Login successful",
#         "files_table": files_table_name
#     }
#     return jsonify(response), 200

# Modify the login route to return the entire response object

@app.route('/files')
@login_required
def list_files():
    # Retrieve the user's files table name from the request object
    files_table_name = request.user_files_table

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT id, filename, is_folder, parent_folder_id FROM {files_table_name}")
    files = cursor.fetchall()
    
    folders = []
    files_list = []
    for file_id, filename, is_folder, parent_folder_id in files:
        icon_data = get_file_icon(os.path.splitext(filename)[1])
        icon_data_base64 = base64.b64encode(icon_data).decode('utf-8') if icon_data else None
        
        if is_folder:
            folder_contents = list_folder_contents(file_id)
            folders.append({
                "id": file_id,
                "filename": filename,
                "is_folder": True,
                "icon_data": icon_data_base64,
                "contents": [{"id": file[0], "filename": file[1]} for file in folder_contents]
            })
        else:
            files_list.append({
                "id": file_id,
                "filename": filename,
                "is_folder": False,
                "icon_data": icon_data_base64
            })
    
    conn.close()
    return jsonify({"folders": folders, "files": files_list})



@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    files = request.files.getlist('file')  # Retrieve list of files

    if len(files) == 0:
        return jsonify({"error": "No files selected"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Retrieve the user's files table name from the request object
    files_table_name = request.user_files_table

    for file in files:
        if file.filename == '':
            continue  # Skip empty file

        # Insert the file into the user's files table
        cursor.execute(f"INSERT INTO {files_table_name} (filename, content) VALUES (%s, %s) RETURNING id", (file.filename, file.read()))
        file_record = cursor.fetchone()
        if file_record is None:
            return jsonify({"error": f"Failed to insert file '{file.filename}' into '{files_table_name}'"}), 500
        file_id = file_record[0]

        # Insert the file information into the recently_added_files table
        # cursor.execute("INSERT INTO recently_added_files (file_id, filename) VALUES (%s, %s)", (file_id, file.filename))

    conn.commit()
    conn.close()

    return jsonify({"message": "Files uploaded successfully"}), 200



@app.route('/delete/<int:file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Retrieve the user's files table name from the request object
    files_table_name = request.user_files_table

    # Check if the file exists
    cursor.execute(f"SELECT filename FROM {files_table_name} WHERE id = %s", (file_id,))
    file_data = cursor.fetchone()
    if not file_data:
        conn.close()
        return jsonify({"error": "File not found"}), 404

    # Delete the file from the database
    cursor.execute(f"DELETE FROM {files_table_name} WHERE id = %s", (file_id,))
    conn.commit()
    conn.close()

    return jsonify({"message": "File deleted successfully"}), 200



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')