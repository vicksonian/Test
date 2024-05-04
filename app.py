# server.py

from flask import Flask, jsonify, send_file, request
import psycopg2
import os
import base64
import io
from flask_cors import CORS

app = Flask(__name__)
# CORS(app)
# CORS(app, origins="http://127.0.0.1:5500")
CORS(app, resources={r"/*": {"origins": "*"}})


# PostgreSQL connection details
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
                        salt TEXT
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS password_resets (
                        id SERIAL PRIMARY KEY,
                        email TEXT,
                        reset_token TEXT,
                        expiry_time TEXT
                    )''')

    conn.commit()
    conn.close()

# Call create_tables() function to create tables when the application starts
create_tables()

def get_file_icon(extension):
    # This function should return the icon data based on the file extension
    # You can implement it to map file extensions to corresponding icons
    # For simplicity, let's assume we have icons stored in the database as well
    # and fetch them based on the file extension
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

@app.route('/files')
def list_files():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename, is_folder, parent_folder_id FROM files")
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
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO files (filename, content) VALUES (%s, %s)", (file.filename, file.read()))
    conn.commit()
    conn.close()

    return jsonify({"message": "File uploaded successfully"}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
