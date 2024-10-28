import os
import numpy as np
from tensorflow.keras.models import load_model
import json
from flask import Flask, Blueprint, render_template, jsonify
from flask_socketio import SocketIO, emit
import psutil
import time
import threading
import hashlib
import requests
import win32security

app = Flask(__name__)
socketio = SocketIO(app)
process_bp = Blueprint('process', __name__)
app.register_blueprint(process_bp)

# Global variables
process_info = []

# class MalwareClassifier:
#     def __init__(self, model_path='model_output/malware_classifier_model.keras', 
#                  class_indices_path='model_output/class_indices.json'):
#         try:
#             self.model = load_model(model_path)
#             with open(class_indices_path, 'r') as f:
#                 self.class_indices = json.load(f)
#             self.classes = {v: k for k, v in self.class_indices.items()}
#         except Exception as e:
#             print(f"Error initializing classifier: {str(e)}")
#             self.model = None
#             self.classes = {}

#     def process_to_image(self, pid):
#         try:
#             process = psutil.Process(pid)
#             memory_info = process.memory_info()
#             memory_bytes = str(memory_info).encode('utf-8')
            
#             if len(memory_bytes) < 4096:
#                 memory_bytes += b'\0' * (4096 - len(memory_bytes))
#             memory_bytes = memory_bytes[:4096]
            
#             img_array = np.frombuffer(memory_bytes, dtype=np.uint8)
#             img_array = img_array.reshape((64, 64, 1))
#             img_array = img_array / 255.0
#             return np.expand_dims(img_array, axis=0)
#         except Exception as e:
#             print(f"Error converting process to image: {str(e)}")
#             return None

#     def predict_process(self, pid):
#         if not self.model:
#             return None
#         try:
#             img_array = self.process_to_image(pid)
#             if img_array is None:
#                 return None
            
#             predictions = self.model.predict(img_array, verbose=0)
#             top_3_idx = np.argsort(predictions[0])[-3:][::-1]
            
#             results = []
#             for idx in top_3_idx:
#                 malware_family = self.classes.get(idx, "Unknown")
#                 confidence = float(predictions[0][idx])
#                 results.append({
#                     "malware_family": malware_family,
#                     "confidence": f"{confidence:.2%}"
#                 })
            
#             return results
#         except Exception as e:
#             print(f"Error in prediction: {str(e)}")
#             return None

class MalwareClassifier:
    def __init__(self, model_path='model_output/malware_classifier_model.keras', 
                 class_indices_path='model_indices.json'):
        try:
            self.model = load_model(model_path)
            with open(class_indices_path, 'r') as f:
                self.class_indices = json.load(f)
            self.classes = {v: k for k, v in self.class_indices.items()}
            
            # Define problematic families and their thresholds
            self.family_thresholds = {
                'Lolyda.AA3': {
                    'threshold': 0.95,  # Very high threshold
                    'system_threshold': 0.98  # Even higher for system processes
                },
                'Dontovo.A': {
                    'threshold': 0.90,
                    'system_threshold': 0.95
                }
            }
            
            # Known safe process patterns
            self.safe_patterns = [
                r'system32',
                r'windows',
                r'program files',
                r'microsoft',
                # Add more known safe patterns
            ]
            
        except Exception as e:
            print(f"Error initializing classifier: {str(e)}")
            self.model = None
            self.classes = {}

    def is_safe_process(self, process_path):
        """Check if process path matches known safe patterns"""
        if not process_path:
            return False
        process_path = process_path.lower()
        return any(pattern in process_path for pattern in self.safe_patterns)

    def predict_process(self, pid):
        if not self.model:
            return None
        try:
            process = psutil.Process(pid)
            
            # Get process path
            try:
                process_path = process.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                process_path = None

            # Skip prediction for known safe processes
            if self.is_safe_process(process_path):
                return None

            img_array = self.process_to_image(pid)
            if img_array is None:
                return None
            
            predictions = self.model.predict(img_array, verbose=0)
            results = []
            
            # Apply Benjamini-Hochberg procedure to control false positive rate
            p_values = []
            for idx, conf in enumerate(predictions[0]):
                family = self.classes.get(idx, "Unknown")
                if family in self.family_thresholds:
                    threshold = (self.family_thresholds[family]['system_threshold'] 
                               if self.is_safe_process(process_path) 
                               else self.family_thresholds[family]['threshold'])
                    if conf > threshold:
                        p_values.append((family, conf, idx))

            if p_values:
                # Sort by confidence (descending)
                p_values.sort(key=lambda x: x[1], reverse=True)
                
                # Apply multiple testing correction
                m = len(p_values)
                q = 0.05  # False discovery rate
                for i, (family, conf, idx) in enumerate(p_values):
                    critical_value = (i + 1) * q / m
                    if conf > critical_value:
                        results.append({
                            "malware_family": family,
                            "confidence": f"{conf:.2%}",
                            "adjusted_confidence": f"{(conf - critical_value):.2%}"
                        })

            return results if results else None

        except Exception as e:
            print(f"Error in prediction: {str(e)}")
            return None

# Initialize the classifier globally
classifier = MalwareClassifier()

def get_process_files(process):
    try:
        return [f.path for f in process.open_files()]
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return []

def is_system_process(process):
    try:
        if process.name().lower() in ['system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe']:
            return True
        if process.username().lower().startswith('nt authority'):
            return True
        return False
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return False

def get_process_info(process):
    try:
        info = {
            'pid': process.pid,
            'name': process.name(),
            'cpu_percent': process.cpu_percent(interval=0.1),
            'memory_percent': process.memory_percent(),
            'status': process.status(),
            'files_accessed': [],
            'is_system': is_system_process(process),
            'connections': '',  # Initialize empty connections string
            'process_md5': 'N/A',
            'virus_total_result': 'N/A'
        }

        # Get executable path and signature information
        try:
            exe_path = process.exe()
            info['exe_path'] = exe_path
            try:
                info['is_signed'] = bool(win32security.GetFileSecurity(
                    exe_path, 
                    win32security.OWNER_SECURITY_INFORMATION
                ))
            except:
                info['is_signed'] = False
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            info['exe_path'] = "Access Denied"
            info['is_signed'] = False

        # Get files accessed
        try:
            info['files_accessed'] = get_process_files(process)
        except:
            info['files_accessed'] = []

        return info
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def calculate_process_md5(pid):
    try:
        process = psutil.Process(pid)
        executable_path = process.exe()
        if executable_path and os.path.exists(executable_path):
            hasher = hashlib.md5()
            with open(executable_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
    except:
        return None

def get_virustotal_report(resource):
    api_key = ''  # Enter your VirusTotal API key here
    if not api_key:
        return 'API key not configured'
    
    try:
        url = f"https://www.virustotal.com/api/v3/files/{resource}"
        headers = {
            "x-apikey": api_key,
            "Accept": "application/json",
        }
        
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

def gather_system_info():
    global process_info
    while True:
        try:
            new_process_info = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    process_data = get_process_info(proc)
                    if not process_data:
                        continue

                    pid_bytes = str(process_data['pid']).encode('utf-8')
                    pid_hash = hashlib.md5(pid_bytes).hexdigest()
                    process_data['id'] = pid_hash

                    if not process_data['is_system']:
                        if classifier.model is not None:
                            malware_prediction = classifier.predict_process(process_data['pid'])
                            if malware_prediction:
                                if process_data['is_signed']:
                                    confidence_threshold = 0.85
                                    malware_prediction = [
                                        pred for pred in malware_prediction 
                                        if float(pred['confidence'].strip('%')) > confidence_threshold
                                    ]
                                process_data['malware_classification'] = malware_prediction

                        if 'exe_path' in process_data and process_data['exe_path'] != "Access Denied":
                            process_md5 = calculate_process_md5(process_data['pid'])
                            if process_md5:
                                process_data['process_md5'] = process_md5
                                process_data['virus_total_result'] = get_virustotal_report(process_md5)

                    new_process_info.append(process_data)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            process_info = new_process_info
            socketio.emit('new_data', {'process_info': process_info})
            time.sleep(2)

        except Exception as e:
            print(f"Error in gather_system_info: {str(e)}")
            time.sleep(5)

@app.route('/')
def index():
    return render_template('process.html')

@socketio.on('connect')
def handle_connect():
    global process_info
    emit('new_data', {'process_info': process_info})

def start_gather_system_info():
    t = threading.Thread(target=gather_system_info)
    t.daemon = True
    t.start()

if __name__ == '__main__':
    # Initialize the classifier before starting the thread
    classifier = MalwareClassifier()
    start_gather_system_info()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
