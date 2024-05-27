# server.py
import psycopg2
import os
import base64
import io
import secrets
import string
import jwt
import random
import ssl
import math
import smtplib
from email.message import EmailMessage
from email.mime.text import MIMEText
import mimetypes
from psycopg2.extensions import AsIs
from functools import wraps
from flask_bcrypt import Bcrypt
import datetime
import datetime
from datetime import timedelta
from datetime import timezone, timedelta
from flask import Flask, jsonify, send_file, request, redirect, url_for, render_template, make_response, Response, session, after_this_request
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)

MAX_TABLE_SIZE = 100 * 1024 * 1024

bcrypt = Bcrypt(app)

SECRET_KEY = 'UB96tx'
app.secret_key = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
CORS(app, resources={r"/*": {"origins": "*"}})
CORS(app, resources={r"/*": {"origins": "http://127.0.0.1:5501"}})

app.config['CORS_HEADERS'] = 'Content-Type'
app.config['CORS_HEADERS'] = 'Access-Control-Allow-Origin'
app.config['CORS_HEADERS'] = 'Access-Control-Allow-Methods'
app.config['CORS_HEADERS'] = 'Access-Control-Allow-Headers'
app.config['CORS_HEADERS'] = 'Access-Control-Allow-Credentials'
app.config['CORS_HEADERS'] = 'Access-Control-Max-Age'
app.config['CORS_HEADERS'] = 'Access-Control-Expose-Headers'


DATABASE_HOST = os.environ.get("DATABASE_HOST")
DATABASE_PORT = os.environ.get("DATABASE_PORT")
DATABASE_NAME = os.environ.get("DATABASE_NAME")
DATABASE_USER = os.environ.get("DATABASE_USER")
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")

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
                        user_id TEXT PRIMARY KEY,
                        reset_code TEXT,
                        expires_at TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(user_id)
                    )''')
    
    cursor.execute('''ALTER TABLE users 
                    ADD COLUMN IF NOT EXISTS files_table TEXT''')
    # cursor.execute('''ALTER TABLE password_resets 
    #                 ADD COLUMN IF NOT EXISTS user_id TEXT PRIMARY KEY''')
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
    columns = [column[0] for column in cursor.description]
    user_data = cursor.fetchone()
    conn.close()
    return dict(zip(columns, user_data)) if user_data else None

def get_user_by_email(email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    columns = [column[0] for column in cursor.description]  # Extract column names
    user_data = cursor.fetchone()
    conn.close()
    return dict(zip(columns, user_data)) if user_data else None

def generate_salt():
    return base64.b64encode(os.urandom(20)).decode('utf-8')

def hash_password(password, salt):
    return bcrypt.generate_password_hash(password + salt).decode('utf-8')

def verify_password(password, hashed_password):
    return bcrypt.check_password_hash(hashed_password, password)


def generate_token(user_id, expiration_time_minutes=60):
    current_time_utc = datetime.datetime.now(timezone.utc)
    expiration_time = current_time_utc + datetime.timedelta(minutes=expiration_time_minutes)
    payload = {
        'user_id': user_id,
        'exp': expiration_time
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def decode_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None 

# Function to get the total size of the table
def get_table_size(files_table_name):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT pg_total_relation_size('{files_table_name}')")
    total_size = cursor.fetchone()[0]
    print(f"Total size of {files_table_name}: {total_size} bytes")
    conn.close()
    if total_size is None:
        total_size = 0
    return total_size


# Function to format bytes into a human-readable format
def format_bytes(size):
    if size == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
    i = int(math.floor(math.log(size, 1024)))
    p = math.pow(1024, i)
    s = round(size / p, 2)
    return "%s %s" % (s, units[i])

# Function to calculate and display table sizes
def display_table_sizes(files_table_name):
    # Get total size of the table
    total_table_size = get_table_size(files_table_name)
    
    # Get total size of the files currently in the table
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT SUM(LENGTH(content)) FROM {files_table_name}")
    used_table_size = cursor.fetchone()[0]
    conn.close()

    # Handle the case when used_table_size is None
    if used_table_size is None:
        used_table_size = 0
    
    # Calculate remaining size
    remaining_size = MAX_TABLE_SIZE - used_table_size
    
    # Prepare response
    response = {
        "total_table_size": total_table_size,
        "used_table_size": used_table_size,
        "remaining_size": remaining_size
    }
    
    return jsonify(response)

def login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        token = token.replace("Bearer ", "")
        payload = decode_token(token)
        if not payload:
            return jsonify({'error': 'Invalid token'}), 401
        user_id = payload['user_id']
        files_table_name = get_files_table_name(user_id)
        if not files_table_name:
            return jsonify({'error': 'User not found or table name not available'}), 404
        request.user_files_table = files_table_name
        return func(*args, **kwargs)
    return decorated_function

def get_files_table_name(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT files_table FROM users WHERE user_id = %s", (user_id,))
    files_table_name = cursor.fetchone()
    conn.close()
    return files_table_name[0] if files_table_name else None

def validate_username_and_email(username, email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
    username_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM users WHERE email = %s", (email,))
    email_count = cursor.fetchone()[0]
    conn.close()
    return username_count, email_count

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    if not (username and email and password):
        return jsonify({"error": "Missing username, email, or password"}), 400
    username_count, email_count = validate_username_and_email(username, email)
    if username_count > 0:
        return jsonify({"error": "Username already exists"}), 409
    if email_count > 0:
        return jsonify({"error": "Email already exists"}), 409
    salt = generate_salt()

    hashed_password = hash_password(password, salt)
    
    files_table_name = f"UDB_x2fb_64_{uuid.uuid4().hex}"
    user_id = generate_random_id()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (user_id, username, email, password, salt, files_table) VALUES (%s, %s, %s, %s, %s, %s)",
                   (user_id, username, email, hashed_password, salt, files_table_name))
    conn.commit()
    cursor.execute(f'''CREATE TABLE IF NOT EXISTS {files_table_name} (
                        id SERIAL PRIMARY KEY,
                        filename TEXT,
                        is_folder INTEGER DEFAULT 0,
                        content BYTEA,
                        mimetype TEXT,  -- New column to store the MIME type of the file
                        icon_data BYTEA,
                        parent_folder_id INTEGER,
                        shared_with TEXT,  -- New column to store the user ID of the recipient if shared
                        FOREIGN KEY (parent_folder_id) REFERENCES {files_table_name}(id)
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS recently_added_files (
                        id SERIAL PRIMARY KEY,
                        filename TEXT,
                        upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    if user is None:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    user_id, username, email, hashed_password, salt, files_table_name = user
    if not verify_password(password + salt, hashed_password):
        conn.close()
        return jsonify({"error": "Invalid password"}), 401
    token = generate_token(user_id)
    conn.close()
    response = {
        "message": "Login successful",
        "token": token,
        "files_table": files_table_name,
        "username": username
    }

    # Add Cache-Control headers
    @after_this_request
    def add_cache_control(response):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    return jsonify(response), 200

@app.route('/forgot_password', methods=['POST'])
@login_required
def forgot_password():
    data = request.json
    email = data.get('email')
    
    # Validate the email
    if not email:
        return jsonify({"error": "Missing email"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, email FROM users WHERE email = %s", (email,))
    user_email = cursor.fetchone()

    if user_email is None:
        conn.close()
        return jsonify({"error": "Email not found"}), 404

    user_id, user_email = user_email
    reset_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

    cursor.execute(
        "INSERT INTO password_resets (user_id, reset_code, expires_at) VALUES (%s, %s, NOW() + INTERVAL '1 hour') "
        "ON CONFLICT (user_id) DO UPDATE SET reset_code = %s, expires_at = NOW() + INTERVAL '1 hour'",
        (user_id, reset_code, reset_code)
    )
    conn.commit()
    conn.close()

    # Send the reset code to the user's email
    email_sender = 'vicksoniangeorge322@gmail.com'
    email_password = "xwml awef hpyq issq"
    email_receiver = user_email  # Correctly set the user's email here
    email_subject = "Password Reset"
    email_body = f"Your reset code is: {reset_code}"
    
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = email_subject
    em.set_content(email_body)

    context = ssl.create_default_context()

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(email_sender, email_password)
            smtp.send_message(em)
    except smtplib.SMTPException as e:
        print(f"Error sending email: {e}")
        return jsonify({"error": "Failed to send email"}), 500

    return jsonify({"message": "Reset code sent to email"}), 200



@app.route('/verify_reset_code', methods=['POST'])
def verify_reset_code():
    data = request.json
    email = data.get('email')
    reset_code = data.get('reset_code')

    if not email or not reset_code:
        return jsonify({"error": "Missing email or reset code"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT user_id FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "Invalid email"}), 404

    user_id = user[0]
    cursor.execute(
        "SELECT reset_code FROM password_resets WHERE user_id = %s AND reset_code = %s AND expires_at > NOW()", 
        (user_id, reset_code)
    )
    valid_reset_code = cursor.fetchone()

    if not valid_reset_code:
        conn.close()
        return jsonify({"error": "Invalid or expired reset code"}), 400

    conn.close()
    return jsonify({"message": "Reset code verified"}), 200

@app.route('/resetpassword')
def reset_password():
    return render_template('new_password.html')


@app.route('/new_password', methods=['POST'])
def new_password():
    data = request.json
    email = data.get('email')
    reset_code = data.get('reset_code')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    
    if not email or not reset_code or not new_password or not confirm_password:
        return jsonify({"error": "Missing data"}), 400

    if new_password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    # Validate the new password (example: at least 8 characters)
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT user_id FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "Invalid email"}), 404

    user_id = user[0]
    cursor.execute(
        "SELECT reset_code FROM password_resets WHERE user_id = %s AND reset_code = %s AND expires_at > NOW()", 
        (user_id, reset_code)
    )
    valid_reset_code = cursor.fetchone()

    if not valid_reset_code:
        conn.close()
        return jsonify({"error": "Invalid or expired reset code"}), 400

    # Generate salt
    salt = generate_salt()
    
    # Hash the password with the custom salt
    hashed_password = hash_password(new_password, salt)
    
    cursor.execute(
        "UPDATE users SET password = %s, salt = %s WHERE user_id = %s", 
        (hashed_password, salt, user_id)
    )
    cursor.execute(
        "DELETE FROM password_resets WHERE user_id = %s", 
        (user_id,)
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "Password reset successful"}), 200


@app.route('/files/<int:file_id>')
@login_required
def get_file(file_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    files_table_name = request.user_files_table
    cursor.execute(f"SELECT filename, content FROM {files_table_name} WHERE id = %s", (file_id,))
    file_data = cursor.fetchone()
    conn.close()
    if file_data:
        filename, content = file_data
        return send_file(
            io.BytesIO(content),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    return jsonify({"error": "File not found"}), 404

@app.route('/files')
@login_required
def list_files():
    files_table_name = request.user_files_table
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT id, filename, is_folder, parent_folder_id, content, icon_data, mimetype FROM {files_table_name}")
    files = cursor.fetchall()
    folders = []
    files_list = []
    for file_id, filename, is_folder, parent_folder_id, content, icon_data, mimetype in files:
        icon_data_base64 = None
        file_type, _ = mimetypes.guess_type(filename)
        if file_type:
            icon_data = get_file_icon(file_type)
            icon_data_base64 = base64.b64encode(icon_data).decode('utf-8') if icon_data else None
        download_token = generate_download_token(file_id, request.user_files_table)
        download_link = url_for('download_files', token=download_token, _external=True)  # Update this line
        if is_folder:
            folder_contents = list_folder_contents(file_id)
            folders.append({
                "id": file_id,
                "filename": filename,
                "is_folder": True,
                "icon_data": icon_data_base64,
                "contents": [{"id": file[0], "filename": file[1]} for file in folder_contents],
                "download_link": download_link
            })
        else:
            if file_type and (file_type.startswith('image/') or file_type.startswith('video/')):
                content_base64 = base64.b64encode(content).decode('utf-8')
                content_type = f'{file_type};base64'
            else:
                content_base64 = None
                content_type = f"/files/{file_id}/content"
            files_list.append({
                "id": file_id,
                "filename": filename,
                "is_folder": False,
                "icon_data": icon_data_base64,
                "content": content_base64,
                "content_type": content_type,
                "download_link": download_link
            })
    conn.close()
    return jsonify({"folders": folders, "files": files_list})

@app.route('/files/<file_id>/content')
@login_required
def serve_file_content(file_id):
    files_table_name = request.user_files_table
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT content FROM {files_table_name} WHERE id = %s", (file_id,))
    content = cursor.fetchone()[0]
    conn.close()
    response = Response(content, mimetype='application/octet-stream')
    response.headers['Content-Disposition'] = 'attachment; filename="file"'
    return response

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    files = request.files.getlist('file')  
    if len(files) == 0:
        return jsonify({"error": "No files selected"}), 400
    total_uploaded_size = sum(file.content_length for file in files)
    if total_uploaded_size > MAX_TABLE_SIZE:
        return jsonify({"error": "Uploading files would exceed the maximum table size"}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    files_table_name = request.user_files_table
    for file in files:
        if file.filename == '':
            continue
        cursor.execute(f"INSERT INTO {files_table_name} (filename, content, mimetype) VALUES (%s, %s, %s) RETURNING id",
                   (file.filename, file.read(), file.mimetype))
        file_id_record = cursor.fetchone()
        if file_id_record is None:
            return jsonify({"error": f"Failed to insert file '{file.filename}' into '{files_table_name}'"}), 500
        file_id = file_id_record[0]
        cursor.execute("INSERT INTO recently_added_files (filename) VALUES (%s)", (file.filename,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Files uploaded successfully"}), 200

@app.route('/table_sizes', methods=['GET'])
@login_required
def get_table_sizes():
    files_table_name = request.user_files_table
    return display_table_sizes(files_table_name)

@app.route('/recently_added_files')
@login_required
def get_recently_added_files():
    minutes_limit = 30
    oldest_allowed_time = datetime.datetime.now() - timedelta(minutes=minutes_limit)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM recently_added_files WHERE upload_time < %s", (oldest_allowed_time,))
    conn.commit()
    cursor.execute("SELECT id, filename FROM recently_added_files ORDER BY upload_time DESC")
    files = cursor.fetchall()
    conn.close()
    recently_added_files = [{"id": file_id, "filename": filename} for file_id, filename in files]
    # print("Retrieved files:")
    # for file_info in recently_added_files:
        # print("ID:", file_info["id"], "- Filename:", file_info["filename"])
    return jsonify({"files": recently_added_files})

@app.route('/delete/<int:file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    conn = get_db_connection()
    cursor = conn.cursor()
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
    
    # Return a success message
    return jsonify({"message": "File deleted successfully"}), 200

def check_file_ownership(file_id):
    files_table_name = request.user_files_table
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT COUNT(*) FROM {files_table_name} WHERE id = %s", (file_id,))
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0

@app.route('/share', methods=['POST'])
@login_required
def share_file():
    data = request.json
    app.logger.debug(f'Received data: {data}')  # Add logging to debug received data
    file_ids = data.get('file_ids')
    recipient_identifier = data.get('recipient_identifier')

    if not (file_ids and recipient_identifier):
        return jsonify({"error": "Missing file IDs or recipient identifier"}), 400
    
    for file_id in file_ids:
        file_exists = check_file_ownership(file_id)
        if not file_exists:
            return jsonify({"error": f"File with ID {file_id} not found or you don't have permission to share it"}), 404
    
    recipient = get_user_by_username(recipient_identifier)
    if not recipient:
        recipient = get_user_by_email(recipient_identifier)
    if not recipient:
        return jsonify({"error": "Recipient not found"}), 404

    for file_id in file_ids:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO %s (filename, content, shared_with) SELECT filename, content, %s FROM %s WHERE id = %s",
                       (AsIs(recipient['files_table']), recipient['user_id'], AsIs(request.user_files_table), file_id))
        conn.commit()
        conn.close()

    return jsonify({"message": "Files shared successfully"}), 200


@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    if not check_file_ownership(file_id):
        return jsonify({"error": "You don't have permission to access this file"}), 403
    conn = get_db_connection()
    cursor = conn.cursor()
    files_table_name = request.user_files_table
    cursor.execute(f"SELECT filename, content FROM {files_table_name} WHERE id = %s", (file_id,))
    file_data = cursor.fetchone()
    conn.close()
    if not file_data:
        return jsonify({"error": "File not found"}), 404
    filename, content = file_data
    response = make_response(content.tobytes())
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response

def generate_download_token(file_id, user_id, expiration_time_minutes=30):
    expiration_time = datetime.datetime.now(timezone.utc) + datetime.timedelta(minutes=expiration_time_minutes)
    payload = {
        'file_id': file_id,
        'user_id': user_id,
        'exp': expiration_time
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def decode_download_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.route('/generate_download_link/<int:file_id>', methods=['POST'])
@login_required
def generate_download_link(file_id):
    user_id = request.user_files_table
    token = generate_download_token(file_id, user_id)
    download_link = url_for('download_file', token=token, _external=True)
    return jsonify({"download_link": download_link}), 200

@app.route('/download_files')
def download_files():
    token = request.args.get('token')
    if not token:
        return jsonify({"error": "Missing token"}), 400

    payload = decode_download_token(token)
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 401

    file_id = payload['file_id']
    user_id = payload['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT filename, content FROM {user_id} WHERE id = %s", (file_id,))
    file_data = cursor.fetchone()
    conn.close()

    if file_data:
        filename, content = file_data
        return send_file(
            io.BytesIO(content),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    return jsonify({"error": "File not found"}), 404


@app.route('/rename', methods=['POST'])
@login_required
def rename_file():
    try:
        data = request.json
        file_id = data.get('file_id')
        new_filename = data.get('new_filename')
        
        if not file_id or not new_filename:
            return jsonify({"error": "Missing file ID or new filename"}), 400
        
        files_table_name = request.user_files_table
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if the file exists and user has permission
        cursor.execute(f"SELECT filename FROM {files_table_name} WHERE id = %s", (file_id,))
        file_data = cursor.fetchone()
        
        if not file_data:
            conn.close()
            return jsonify({"error": "File not found"}), 404
        
        # Rename the file
        cursor.execute(f"UPDATE {files_table_name} SET filename = %s WHERE id = %s", (new_filename, file_id))
        conn.commit()
        conn.close()
        
        return jsonify({"message": "File renamed successfully"}), 200
    except Exception as e:
        # Log the exception and return a JSON error response
        app.logger.error(f"Error renaming file: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/validate_user', methods=['POST'])
@login_required
def validate_user():
    data = request.json
    recipient_identifier = data.get('recipient_identifier')
    recipient = get_user_by_username(recipient_identifier)
    if not recipient:
        recipient = get_user_by_email(recipient_identifier)
    return jsonify({"exists": recipient is not None})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
