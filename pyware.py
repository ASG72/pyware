# -*- coding: utf-8 -*-
"""
Created on Wed Oct  4 06:49:27 2023

@author: ARJUN A L
"""

import psutil
import hashlib
import time
from IPython.display import display, HTML, clear_output

def get_md5_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            md5_hash = hashlib.md5(data).hexdigest()
        return md5_hash
    except (FileNotFoundError, PermissionError):
        return "Not Available"

def display_process_info():
    html_output = "<table><tr><th>PID</th><th>Process Name</th><th>Number of Threads</th><th>MD5 Hash</th><th>Currently Accessing Files</th></tr>"
    while True:
        process_info = []
        for process in psutil.process_iter(['pid', 'name']):
            try:
                pid = process.info['pid']
                process_name = process.info['name']
                num_threads = process.num_threads()
                md5_hash = get_md5_hash(process.exe())
                files_accessed = []
                try:
                    for file in process.open_files():
                        files_accessed.append(file.path)
                except psutil.AccessDenied:
                    files_accessed = ["Access Denied"]

                files_accessed_str = ', '.join(files_accessed)
                process_info.append(f"<tr><td>{pid}</td><td>{process_name}</td><td>{num_threads}</td><td>{md5_hash}</td><td>{files_accessed_str}</td></tr>")
            except psutil.AccessDenied:
                pass

        clear_output(wait=True)  # Clear the output of the current cell
        display(HTML(html_output + '\n'.join(process_info) + "</table>"))

        time.sleep(1)  # Wait for 5 seconds before updating the list

if __name__ == "__main__":
    display_process_info()
