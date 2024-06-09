import os
import hashlib
import magic
import requests
import threading
from flask import Flask, render_template, request
from flask_socketio import SocketIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

def calculate_md5(file_path):
    with open(file_path, 'rb') as f:
        hasher = hashlib.md5()
        while True:
            data = f.read(4096)
            if not data:
                break
            hasher.update(data)
    return hasher.hexdigest()

def check_virustotal(md5_hash, api_key):
    if not api_key:
        return 'API key not provided'
    
    url = f"https://www.virustotal.com/api/v3/files/{md5_hash}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        last_analysis_stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious = last_analysis_stats.get('malicious', 0)
        suspicious = last_analysis_stats.get('suspicious', 0)
        undetected = last_analysis_stats.get('undetected', 0)
        total = malicious + suspicious + undetected
        detection_ratio = (malicious + suspicious) / total * 100
        return detection_ratio
    else:
        return 'N/A'

def analyze_file(file_path):
    file_info = {
        'file_name': os.path.basename(file_path),
        'real_file_type': magic.from_file(file_path),
        'file_md5_hash': calculate_md5(file_path),
        'python_libraries': 'magic',
    }
    
    if file_info['real_file_type'] == 'PE32 executable (GUI) Intel 80386, for MS Windows':
        # Check for misleading headers and signatures
        with open(file_path, 'rb') as f:
            signature = f.read(2)
            if signature != b'MZ':
                file_info['misleading_header'] = True
            else:
                file_info['misleading_header'] = False
                
            f.seek(60)
            pe_offset = int.from_bytes(f.read(4), byteorder='little')
            f.seek(pe_offset)
            pe_signature = f.read(4)
            if pe_signature != b'PE\x00\x00':
                file_info['invalid_signature'] = True
            else:
                file_info['invalid_signature'] = False
    
    return file_info

def analyze_folder(folder_path, api_key, socketio):
    file_info_list = []
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            file_info = analyze_file(file_path)
            file_info['virustotal_result'] = check_virustotal(file_info['file_md5_hash'], api_key)
            file_info_list.append(file_info)
            socketio.emit('file_scanned', {'file_info': file_info}, namespace='/scan')
    return file_info_list

@app.route('/')
def index():
    return render_template('file.html')

@socketio.on('scan_folder', namespace='/scan')
def handle_scan_folder(folder_info):
    folder_path = folder_info['folder_path']
    api_key = folder_info['api_key']
    
    if os.path.isdir(folder_path):
        thread = threading.Thread(target=analyze_folder, args=(folder_path, api_key, socketio))
        thread.start()
    else:
        socketio.emit('error', {'message': 'Invalid folder path'}, namespace='/scan')

if __name__ == "__main__":
    socketio.run(app, port=5001)
