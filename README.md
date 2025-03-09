# MacFIRE – Mac Forensic Investigation & Response Engine
![MacFIRE](https://github.com/Masriyan/MacFIRE/blob/main/image.jpg)
## Overview
**MacFIRE** is a powerful macOS forensic tool designed to assist Digital Forensics and Incident Response (DFIR) professionals in acquiring and analyzing forensic artifacts from macOS devices. It supports disk imaging, artifact collection, persistence detection, network forensics, and automated report generation.

## Features
✅ List available disks and detect external drives  
✅ Perform raw disk imaging (`dd`)  
✅ Collect forensic artifacts (logs, keychains, browser history, network connections, etc.)  
✅ Identify persistence mechanisms (launch agents, kernel extensions)  
✅ Generate an automated forensic report  
✅ Compatible with macOS Catalina (10.15) and later  

## Installation
Ensure you have Python installed on macOS:
```bash
brew install python3
```

Clone the repository:
```bash
git clone https://github.com/Masriyan/MacFIRE.git
cd MacFIRE
```

Install dependencies:
```bash
pip install -r requirements.txt  # If any Python modules are required
```

## Usage
Run the script with various forensic options:

### List available disks
```bash
python macfire.py --list-disks
```

### Detect external storage devices
```bash
python macfire.py --detect-external
```

### Unmount a disk before imaging
```bash
python macfire.py --unmount /dev/disk2
```

### Create a raw disk image
```bash
python macfire.py --create-raw /Volumes/ExternalDrive/Forensics
```

### Collect forensic artifacts
```bash
python macfire.py --collect-artifacts /Volumes/ExternalDrive/Artifacts
```

### Generate a forensic report
```bash
python macfire.py --generate-report /Volumes/ExternalDrive/Report
```

## Supported macOS Versions
- macOS Catalina (10.15) and later

## License
This project is licensed under the MIT License.

## Credits
Developed by **sudo3rs**.
