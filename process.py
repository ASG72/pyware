import uuid
from flask import Blueprint, render_template, jsonify
from . import socketio
from flask_socketio import emit
import psutil
import time
import threading
import hashlib
import os
import requests

#process_bp = Blueprint('process', __name__)

process_info = []

def gather_system_info():
    global process_info
    while True:
        new_process_info = []
        for process in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent', 'memory_percent', 'connections']):
            try:
                pid = process.info['pid']
                pid_bytes = str(pid).encode('utf-8')
                pid_hash = hashlib.md5(pid_bytes).hexdigest()
                if pid == 0:
                    continue
                name = process.info['name']
                cpu_percent = process.info['cpu_percent']
                memory_percent = process.info['memory_percent']
                connections = process.info['connections']

                connections_str = ''
                if connections is not None:
                    for conn in connections:
                        connections_str += f"{conn}\n"

                files_accessed = []
                try:
                    for file in process.open_files():
                        files_accessed.append(file.path)
                except psutil.AccessDenied:
                    files_accessed.append("Access Denied")

                files_accessed_str = ', '.join(files_accessed)

                process_md5 = None
                try:
                    process_md5 = calculate_process_md5(pid)
                except (FileNotFoundError, PermissionError):
                    pass

                virus_total_result = None
                if process_md5:
                    virus_total_result = get_virustotal_report(process_md5)

                new_process_info.append({
                    'id': pid_hash,
                    'pid': pid,
                    'name': name,
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory_percent,
                    'connections': connections_str,
                    'process_md5': process_md5,
                    'files_accessed_str': files_accessed_str,
                    'virus_total_result': virus_total_result
                })

            except psutil.NoSuchProcess:
                pass

        process_info = new_process_info
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
    api_key = '' #enter api_key
    if api_key == '':
        return 'API not given'
    else:
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

@process_bp.route('/')
def index():
    return render_template('process.html')

@socketio.on('connect')
def handle_connect():
    emit('new_data', {'process_info': process_info})

def start_gather_system_info():
    t = threading.Thread(target=gather_system_info)
    t.daemon = True
    t.start()

start_gather_system_info()
