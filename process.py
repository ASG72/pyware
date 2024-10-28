import os
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.image import load_img, img_to_array
import json
import uuid
from flask import Flask, Blueprint, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import psutil
import time
import threading
import hashlib
import requests
import matplotlib.pyplot as plt
import io
import binascii

app = Flask(__name__)
socketio = SocketIO(app)
process_bp = Blueprint('process', __name__)
app.register_blueprint(process_bp)

# Malware classifier class
class MalwareClassifier:
    def __init__(self, model_path='model_output/malware_classifier_model.keras', 
                 class_indices_path='model_output/class_indices.json'):
        self.model = load_model(model_path)
        
        with open(class_indices_path, 'r') as f:
            self.class_indices = json.load(f)
        self.classes = {v: k for k, v in self.class_indices.items()}
        
    def process_to_image(self, pid):
        """Convert process memory to image"""
        try:
            process = psutil.Process(pid)
            # Get process memory as bytes
            with open(f"/proc/{pid}/mem", 'rb') as f:
                memory_bytes = f.read(64 * 64)  # Read enough for 64x64 image
            
            # Pad or truncate to exact size
            if len(memory_bytes) < 4096:  # 64*64
                memory_bytes += b'\0' * (4096 - len(memory_bytes))
            memory_bytes = memory_bytes[:4096]
            
            # Convert to numpy array and reshape
            img_array = np.frombuffer(memory_bytes, dtype=np.uint8)
            img_array = img_array.reshape((64, 64, 1))
            img_array = img_array / 255.0
            return np.expand_dims(img_array, axis=0)
        except Exception as e:
            print(f"Error converting process to image: {str(e)}")
            return None

    def predict_process(self, pid):
        """Predict malware class for a running process"""
        try:
            img_array = self.process_to_image(pid)
            if img_array is None:
                return None
            
            predictions = self.model.predict(img_array, verbose=0)
            top_3_idx = np.argsort(predictions[0])[-3:][::-1]
            
            results = []
            for idx in top_3_idx:
                malware_family = self.classes[idx]
                confidence = float(predictions[0][idx])
                results.append({
                    "malware_family": malware_family,
                    "confidence": f"{confidence:.2%}"
                })
            
            return results
        except Exception as e:
            print(f"Error in prediction: {str(e)}")
            return None

# Initialize the classifier
classifier = MalwareClassifier()

# Global process info storage
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
                    
                # Basic process info
                process_data = {
                    'id': pid_hash,
                    'pid': pid,
                    'name': process.info['name'],
                    'cpu_percent': process.info['cpu_percent'],
                    'memory_percent': process.info['memory_percent'],
                }

                # Add malware classification results
                malware_prediction = classifier.predict_process(pid)
                if malware_prediction:
                    process_data['malware_classification'] = malware_prediction
                
                # Add VirusTotal results
                process_md5 = calculate_process_md5(pid)
                if process_md5:
                    process_data['process_md5'] = process_md5
                    virus_total_result = get_virustotal_report(process_md5)
                    process_data['virus_total_result'] = virus_total_result

                new_process_info.append(process_data)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        process_info = new_process_info
        socketio.emit('new_data', {'process_info': process_info})
        time.sleep(2)

def calculate_process_md5(pid):
    try:
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
    except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
        return None

def get_virustotal_report(resource):
    api_key = ''  # Enter your VirusTotal API key here
    if not api_key:
        return 'API key not configured'
    
    url = f"https://www.virustotal.com/api/v3/files/{resource}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            if total > 0:
                return f"{((malicious + suspicious) / total * 100):.1f}%"
        return 'N/A'
    except Exception:
        return 'Error'

@app.route('/')
def index():
    return render_template('process.html')

@socketio.on('connect')
def handle_connect():
    emit('new_data', {'process_info': process_info})

@app.route('/analyze_process/<int:pid>', methods=['POST'])
def analyze_process(pid):
    try:
        results = classifier.predict_process(pid)
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def start_gather_system_info():
    t = threading.Thread(target=gather_system_info)
    t.daemon = True
    t.start()

if __name__ == '__main__':
    start_gather_system_info()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
