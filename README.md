# Watchtower
An open tool for system inpection using python. Users can check files being accessed on realtime by each processes. New feature are coming such as checking process cheksums with virustotal api.
Currently web based gui is used to avoid gui lagging when showing chunks of data.

file.py- for checking files 
process.py - for checking processes


# Installation
git clone https://github.com/hatgrey2/watchtower.git

pip install -r reuqirements.txt

cd watchtower

python process.py

python file.py

#NOTES
Currently works in windows
Linux update soon

the 2 scripts should be run seperately on different ports , the combining of scripts will be updated soon.

<In development>
