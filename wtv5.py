import uuid
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import psutil
import time
import threading
import hashlib
import os
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

process_info = []


def gather_system_info():
    global process_info
    while True:
        new_process_info = []
        for process in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent', 'memory_percent', 'connections']):
            try:
                pid = process.info['pid']
                if pid == 0:
                    continue  # Skip the system idle process (pid=0)
                name = process.info['name']
                cpu_percent = process.info['cpu_percent']
                memory_percent = process.info['memory_percent']
                connections = process.info['connections']

                connections_str = ''
                if connections is not None:
                    for conn in connections:
                        connections_str += f"{conn}\n"
# ---------------------------------------------------------------------------------------files_accessed-------------------
                files_accessed = []
                files_accessed_str = ', '.join(files_accessed)

                process_md5 = None
                
                try:
                    for file in process.open_files():
                        files_accessed.append(file.path)
                except psutil.AccessDenied:
                    files_accessed.append("Access Denied")

                files_accessed_str = ', '.join(files_accessed)

                # Calculate MD5 checksum for the process executable file
                try:
                    process_md5 = calculate_process_md5(pid)
                except (FileNotFoundError, PermissionError):
                    pass

                # Check VirusTotal for the hash
                virus_total_result = None
                if process_md5:
                    virus_total_result = get_virustotal_report(process_md5)

                new_process_info.append({
                    'id': str(uuid.uuid4()),  # Generate a unique ID for each process
                    'pid': pid,
                    'name': name,
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory_percent,
                    'connections': connections,
                    'process_md5': process_md5,
                    'files_accessed_str': files_accessed_str,
                    'virus_total_result': virus_total_result
                })

            except psutil.NoSuchProcess:
                pass

            # Update the global process_info list with the new data
            process_info = new_process_info

            # Emit an event to the client with the new data
            socketio.emit('new_data', {'process_info': process_info})

            time.sleep(2)



def calculate_process_md5(pid):
    process = psutil.Process(pid)
    executable_path = process.exe()
    if executable_path:
        hasher = hashlib.md5()
        with open(executable_path, 'rb') as f:
            while True:
                data = f.read(4096)
                if not data:
                    break
                hasher.update(data)
        return hasher.hexdigest()
    return None

def get_virustotal_report(resource):
    api_key = 'your_virustotal_api_key'
    url = f"https://www.virustotal.com/api/v3/files/{resource}"
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

@app.route('/')
def index():
    return render_template('index.html')
@socketio.on('connect')
def handle_connect():
    # Emit an event to the client with the initial data
    emit('new_data', {'process_info': process_info})

if __name__ == '__main__':
    t = threading.Thread(target=gather_system_info)
    t.daemon = True
    t.start()
    socketio.run(app)
