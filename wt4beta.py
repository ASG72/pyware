from flask import Flask, render_template, jsonify
import psutil
import time
import threading
import hashlib
import os

app = Flask(__name__)

def gather_system_info():
    while True:
        process_info = []
        for process in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent', 'memory_percent', 'connections']):
            try:
                pid = process.info['pid']
                if pid == 0:
                    continue  # Skip the system idle process (pid=0)
                name = process.info['name']
                cpu_percent = process.info['cpu_percent']
                memory_percent = process.info['memory_percent']
                connections = process.info['connections']

                process_md5 = None
                files_accessed = []
                try:
                    for file in process.open_files():
                        files_accessed.append(file.path)
                except (psutil.AccessDenied, FileNotFoundError):
                    files_accessed.append("Access Denied or File Not Found")

                files_accessed_str = ', '.join(files_accessed)
                
                # Calculate MD5 checksum for the process executable file
                try:
                    process_md5 = calculate_process_md5(pid)
                except (FileNotFoundError, PermissionError):
                    pass

                process_info.append({
                    'pid': pid,
                    'name': name,
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory_percent,
                    'connections': connections,
                    'process_md5': process_md5,
                    'files_accessed_str': files_accessed_str,
                })

            except psutil.NoSuchProcess:
                pass

        app.config['process_info'] = process_info
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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_data')
def get_data():
    return jsonify(process_info=app.config.get('process_info', []))

if __name__ == '__main__':
    t = threading.Thread(target=gather_system_info)
    t.daemon = True
    t.start()
    app.run()
