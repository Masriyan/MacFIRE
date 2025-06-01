# MacFIRE – Mac Forensic Investigation & Response Engine
![MacFIRE](https://github.com/Masriyan/MacFIRE/blob/main/image.jpg)
# macFIRE - macOS Forensic Acquisition Tool

<div align="center">
  <img src="https://img.shields.io/badge/platform-macOS-blue.svg" alt="Platform">
  <img src="https://img.shields.io/badge/python-3.6+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-red.svg" alt="License">
</div>

macFIRE is a comprehensive forensic acquisition tool for macOS systems. It enables digital forensic investigators, security professionals, and system administrators to collect vital forensic artifacts, create disk images, and generate detailed reports.

```
=============================================
  _____                ____________________ 
 |     |              |                    |
 | Mac |==============| F I R E           |
 |_____|              |____________________|

 macOS Forensic Investigation & Recovery Environment
 Version 1.1 
 by Sudo3rs
=============================================
```

## Features

- **Comprehensive Artifact Collection**: Collect and preserve critical macOS system artifacts organized by categories
- **Raw Disk Imaging**: Create forensically sound disk images with integrity verification
- **Memory Acquisition**: Capture volatile memory data and process information
- **Detailed Reporting**: Generate HTML reports summarizing collected data and system information
- **Artifact Compression**: Compress collected artifacts with integrity verification
- **Rootkit Detection**: Scan for known rootkit signatures and suspicious system modifications
- **System Timeline**: Generate chronological system activity timelines
- **Browser History Extraction**: Extract and analyze web browser data
- **Encrypted Volume Analysis**: Identify and analyze encrypted volumes and containers
- **Category-based Collection**: Selectively collect artifacts based on specific categories of interest
- **Integrity Verification**: Automatically calculate SHA-256 hashes for all acquired data
- **Progress Tracking**: Visual feedback for lengthy operations
- **Extensive Logging**: Detailed logging of all operations for audit trails
- **Error Handling**: Comprehensive error detection and reporting

## What's New in Version 1.2

- **Simplified Interface**: Streamlined banner and improved user experience
- **Expanded Capabilities**: Added several new forensic features including memory acquisition, rootkit detection, and timeline generation
- **New Artifact Categories**: Added Browser Data and Memory Acquisition categories
- **Enhanced Command Line Interface**: Organized commands into logical groups with better help text
- **Artifact Compression**: Added ability to compress collected artifacts for easier storage and transfer
- **Metadata Backup**: Added comprehensive metadata recording for all collected artifacts
- **Improved Error Handling**: Better error detection and reporting throughout the application

For a complete list of changes, see the [UPDATE.md](UPDATE.md) file.

## Supported macOS Versions

- macOS Catalina (10.15) and later
- Limited support for earlier versions

## Installation

### Prerequisites

- Python 3.6+
- macOS system
- Administrative (root) privileges for full functionality

### Setup

1. Clone the repository:
```bash
git clone https://github.com/Masriyan/macfire.git
cd macfire
```

2. Make the script executable:
```bash
chmod +x macfire.py
```

## Usage

### Basic Usage

```bash
# View help and available options
python3 macfire.py --help

# List available disks
python3 macfire.py --list-disks

# Detect external storage devices
python3 macfire.py --detect-external
```

### Collecting Forensic Artifacts

```bash
# Collect all forensic artifacts (requires root)
sudo python3 macfire.py --collect-artifacts ./evidence

# Collect specific categories of artifacts
sudo python3 macfire.py --collect-artifacts ./evidence --categories "System Security" "Network"

# Collect and compress artifacts
sudo python3 macfire.py --collect-artifacts ./evidence --compress
```

### Disk Imaging

```bash
# Create a raw disk image with hash verification (requires root)
sudo python3 macfire.py --create-raw ./disk_images

# Create a raw disk image without hash calculation (faster)
sudo python3 macfire.py --create-raw ./disk_images --skip-hash

# Unmount a disk before imaging
sudo python3 macfire.py --unmount /dev/disk2

# Verify a disk image
python3 macfire.py --verify-image ./disk_images/disk2_20250420_123456.dd
```

### Memory Acquisition

```bash
# Acquire memory artifacts
sudo python3 macfire.py --memory-dump ./memory_evidence
```

### Security Analysis

```bash
# Check for rootkits and suspicious modifications
sudo python3 macfire.py --rootkit-check ./security_check

# Identify and analyze encrypted volumes
sudo python3 macfire.py --encrypted-volumes ./encryption_info
```

### Browser History and Timeline Analysis

```bash
# Extract browser history from Safari, Chrome, and Firefox
python3 macfire.py --browser-history ./browser_data

# Generate a 7-day system timeline (default)
sudo python3 macfire.py --system-timeline ./timeline

# Generate a 30-day system timeline
sudo python3 macfire.py --system-timeline ./timeline --timeline-days 30
```

### Reporting

```bash
# Generate a forensic report from collected artifacts
python3 macfire.py --generate-report ./reports --artifacts-path ./evidence/artifacts_20250401_123456

# Create metadata for collected artifacts
python3 macfire.py --backup-metadata ./evidence/artifacts_20250401_123456
```

### Additional Options

```bash
# Minimize output
python3 macfire.py --collect-artifacts ./evidence --quiet

# Check tool version
python3 macfire.py --version
```

## Artifact Categories

macFIRE collects the following categories of artifacts:

1. **System Information**: Basic system configuration, hardware details, version info
2. **File System**: System logs, Spotlight metadata, quarantine database, etc.
3. **User Data**: User preferences, application data, browser history, messages, keychains
4. **System Security**: Security logs, TCC database, firewall rules, authorization settings
5. **Network**: Network interfaces, connections, ARP cache, routing tables, DNS configuration
6. **Running System**: Current processes, open files, launch agents, kernel extensions
7. **Browser Data**: Web browser artifacts including history, downloads, cookies, and bookmarks
8. **Memory Acquisition**: Volatile memory information and running processes

## Sample Reports

<p align="center">
https://macfire.tiiny.site
</p>

## Security and Privacy Considerations

- The tool **does not** upload or transmit any collected data
- All analysis occurs locally on the system
- Exercise caution and proper authorization when using on systems
- Review all collected artifacts for sensitive information before sharing

## For Developers

macFIRE is designed to be extended. You can add new artifact categories or collection methods by modifying the `ARTIFACTS` dictionary in the source code.

```python
# Example of adding a new artifact category
ARTIFACTS["Custom Category"] = {
    "description": "Your custom artifact category",
    "paths": [
        "/path/to/important/file",
        "/path/to/important/directory"
    ],
    "commands": [
        "your_command > ./output_file.txt"
    ]
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- Apple's macOS for providing a rich forensic landscape
- The digital forensics community for ongoing research and techniques
- Sudo3rs team for the original concept and development

## Disclaimer

This tool should only be used for legitimate forensic investigations, security research, or system administration tasks where you have proper authorization. The authors are not responsible for misuse or illegal applications.
