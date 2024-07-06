# Watchtower
An open tool for system inpection using python. Users can check files being accessed on realtime by each processes. New feature are coming such as checking process cheksums with virustotal api.
Currently web based gui is used to avoid gui lagging when showing chunks of data.

file.py- for checking files 
process.py - for checking processes


# Installation
git clone https://github.com/hatgrey2/watchtower.git

require python libraries Flask, Flask-socketIO

Conda-(Linux/windows)

conda activate

pip install flask

pip install flask_socketio

pip install requets

pip install psutils

pip install hashlib

pip install magic

pip install threading

cd watchtower

python process.py

python file.py

#NOTES
Currently works in windows
Linux update soon

the 2 scripts should be run seperately on different ports , the combining of scripts will be updated soon.

<In development>
