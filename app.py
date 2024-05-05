# server.py
import psycopg2
import os
import base64
import io
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from flask import Flask, jsonify, send_file, request, session
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS



app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
CORS(app, resources={r"/*": {"origins": "*"}})


bcrypt = Bcrypt(app)
DATABASE_HOST = "dpg-coqpn5vsc6pc73de9g5g-a.virginia-postgres.render.com"
DATABASE_PORT = 5432
DATABASE_NAME = "servers_files"
DATABASE_USER = "famage"
DATABASE_PASSWORD = "mHRhoJelrAnZ3Haw1fm9RrCuo7yJ9IQ4"

def get_db_connection():
    return psycopg2.connect(
        host=DATABASE_HOST,
        port=DATABASE_PORT,
        database=DATABASE_NAME,
        user=DATABASE_USER,
        password=DATABASE_PASSWORD
    )

# Function to create tables if they do not exist
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
                        id SERIAL PRIMARY KEY,
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

def get_file_icon(extension):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT icon_data FROM icons WHERE file_extension = %s", (extension,))
    icon_data = cursor.fetchone()
    conn.close()
    return icon_data[0] if icon_data else None

def list_folder_contents(folder_id, files_table):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename FROM {} WHERE parent_folder_id = %s".format(files_table), (folder_id,))
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
        return send_file(
            io.BytesIO(content),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    return jsonify({"error": "File not found"}), 404




@app.route('/files')
def list_files():
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401

    files_table = session.get('files_table')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename, is_folder, parent_folder_id FROM {} ORDER BY filename".format(files_table))
    files = cursor.fetchall()
    
    folders = []
    files_list = []
    for file_id, filename, is_folder, parent_folder_id in files:
        icon_data = get_file_icon(os.path.splitext(filename)[1])
        icon_data_base64 = base64.b64encode(icon_data).decode('utf-8') if icon_data else None
        
        if is_folder:
            folder_contents = list_folder_contents(file_id, files_table)
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
def upload_file():
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401

    files_table = session.get('files_table')

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    files = request.files.getlist('file')

    if len(files) == 0:
        return jsonify({"error": "No files selected"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    for file in files:
        if file.filename == '':
            continue

        cursor.execute("INSERT INTO {} (filename, content) VALUES (%s, %s) RETURNING id".format(files_table), (file.filename, file.read()))
        file_id = cursor.fetchone()[0]

        cursor.execute("INSERT INTO recently_added_files (file_id, filename) VALUES (%s, %s)", (file_id, file.filename))

    conn.commit()
    conn.close()

    return jsonify({"message": "Files uploaded successfully"}), 200

@app.route('/delete/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401

    files_table = session.get('files_table')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT filename FROM {} WHERE id = %s".format(files_table), (file_id,))
    file_data = cursor.fetchone()
    if not file_data:
        conn.close()
        return jsonify({"error": "File not found"}), 404

    cursor.execute("DELETE FROM {} WHERE id = %s".format(files_table), (file_id,))
    conn.commit()
    conn.close()

    return jsonify({"message": "File deleted successfully"}), 200

@app.route('/recently_added_files')
def get_recently_added_files():
    # Define the number of minutes to keep files in the recently added list
    minutes_limit = 3  # Change this to the desired number of minutes

    # Calculate the time X minutes ago from the current time
    oldest_allowed_time = datetime.now() - timedelta(minutes=minutes_limit)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Delete files older than the specified minutes limit
    cursor.execute("DELETE FROM recently_added_files WHERE upload_time < %s", (oldest_allowed_time,))
    conn.commit()

    # Fetch the recently added files within the specified minutes limit
    cursor.execute("SELECT id, filename FROM recently_added_files ORDER BY upload_time DESC")
    files = cursor.fetchall()
    conn.close()

    recently_added_files = [{"id": file_id, "filename": filename} for file_id, filename in files]
    return jsonify({"files": recently_added_files})



def generate_salt():
    return base64.b64encode(os.urandom(20)).decode('utf-8')


def hash_password(password, salt):
    return bcrypt.generate_password_hash(password + salt).decode('utf-8')


def verify_password(password, hashed_password):
    return bcrypt.check_password_hash(hashed_password, password)


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

    cursor.execute("INSERT INTO users (username, email, password, salt, files_table) VALUES (%s, %s, %s, %s, %s)",
                   (username, email, hashed_password, salt, files_table_name))
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




#login logic handling here
# Modify the login route to set session variables
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username_or_email = data.get('username_or_email')
    password = data.get('password')

    if not (username_or_email and password):
        return jsonify({"error": "Missing username/email or password"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, username, email, password, salt, files_table FROM users WHERE username = %s OR email = %s",
                   (username_or_email, username_or_email))
    user = cursor.fetchone()

    if user is None:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    user_id, username, email, hashed_password, salt, files_table_name = user

    if not verify_password(password + salt, hashed_password):
        conn.close()
        return jsonify({"error": "Invalid password"}), 401

    # Set session variables
    session['user_id'] = user_id
    session['username'] = username
    session['email'] = email
    session['files_table'] = files_table_name

    conn.close()

    return jsonify({"message": "Login successful"}), 200


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
