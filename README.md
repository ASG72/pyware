# Watchtower
An open tool for system inpection using python. Users can check files being accessed on realtime by each processes.Auto checking process cheksums with virustotal api.

# Web GUI
Currently web based gui is used to avoid gui lagging when showing chunks of data.

# Offline detection
Newly Added Offline detection for malware processes using CNN (Convolutional Neural Network) model.

# Usage
file.py- for checking files 
process.py - for checking processes


# Installation
git clone https://github.com/hatgrey2/watchtower.git

pip install -r requirements.txt

cd watchtower

python process.py

python file.py

#NOTES
Currently works in windows
Linux update soon

the 2 scripts should be run seperately on different ports , the combining of scripts will be updated soon.

<In development>
