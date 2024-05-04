# server.py

from flask import Flask, jsonify, send_file, request
import psycopg2
import os
import base64
import io
from datetime import datetime, timedelta
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

    cursor.execute('''CREATE TABLE IF NOT EXISTS recently_added_files (
                        id SERIAL PRIMARY KEY,
                        file_id INTEGER,
                        filename TEXT,
                        upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (file_id) REFERENCES files(id)
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

    files = request.files.getlist('file')  # Retrieve list of files

    if len(files) == 0:
        return jsonify({"error": "No files selected"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    for file in files:
        if file.filename == '':
            continue  # Skip empty file

        # Insert the file into the files table
        cursor.execute("INSERT INTO files (filename, content) VALUES (%s, %s) RETURNING id", (file.filename, file.read()))
        file_id = cursor.fetchone()[0]

        # Insert the file information into the recently_added_files table
        cursor.execute("INSERT INTO recently_added_files (file_id, filename) VALUES (%s, %s)", (file_id, file.filename))

    conn.commit()
    conn.close()

    return jsonify({"message": "Files uploaded successfully"}), 200



@app.route('/delete/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the file exists
    cursor.execute("SELECT filename FROM files WHERE id = %s", (file_id,))
    file_data = cursor.fetchone()
    if not file_data:
        conn.close()
        return jsonify({"error": "File not found"}), 404

    # Delete the file from the database
    cursor.execute("DELETE FROM files WHERE id = %s", (file_id,))
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


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
