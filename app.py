# server.py

from flask import Flask, jsonify, send_file, request, make_response
import sqlite3
import os
from flask_cors import CORS
import base64
import io

app = Flask(__name__)
# CORS(app)
# CORS(app, origins="http://127.0.0.1:5500")
CORS(app, resources={r"/*": {"origins": "*"}})  # Allow all origins for all routes
DATABASE = 'servers_files.db'

def get_file_icon(extension):
    # This function should return the icon data based on the file extension
    # You can implement it to map file extensions to corresponding icons
    # For simplicity, let's assume we have icons stored in the database as well
    # and fetch them based on the file extension
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT icon_data FROM icons WHERE file_extension = ?", (extension,))
    icon_data = cursor.fetchone()
    conn.close()
    return icon_data[0] if icon_data else None

def list_folder_contents(folder_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename FROM files WHERE parent_folder_id = ?", (folder_id,))
    files = cursor.fetchall()
    conn.close()
    return files

@app.route('/files/<int:file_id>')
def get_file(file_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT filename, content FROM files WHERE id = ?", (file_id,))
    file_data = cursor.fetchone()
    conn.close()
    if file_data:
        filename, content = file_data
        # Return the file as an attachment
        return send_file(
            io.BytesIO(content),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename  # Use download_name instead of attachment_filename
        )
    return jsonify({"error": "File not found"}), 404

@app.route('/files')
def list_files():
    conn = sqlite3.connect(DATABASE)
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

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO files (filename, content) VALUES (?, ?)", (file.filename, file.read()))
    conn.commit()
    conn.close()

    return jsonify({"message": "File uploaded successfully"}), 200


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')#, ssl_context="adhoc")