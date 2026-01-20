# MacFIRE - macOS Forensic Investigation & Response Engine

<div align="center">

![MacFIRE Banner](banner.png)

[![Platform](https://img.shields.io/badge/platform-macOS-blue.svg)](https://www.apple.com/macos/)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-orange.svg)](CHANGELOG.md)

**Enterprise-grade forensic acquisition and incident response tool for macOS systems**

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## 🔥 What is MacFIRE?

MacFIRE is a comprehensive forensic acquisition and incident response tool designed specifically for macOS systems. It empowers digital forensic investigators, security analysts, and incident responders to:

- **Collect** critical forensic artifacts from macOS systems
- **Analyze** system state with live triage capabilities  
- **Detect** indicators of compromise using integrated IOC scanning
- **Image** disks with forensic integrity verification
- **Report** findings with detailed HTML reports

## ✨ Features

### 🎯 Incident Response
- **Live Triage Mode** - Rapid system assessment for active incidents
- **MITRE ATT&CK Mapping** - Findings mapped to ATT&CK techniques
- **IOC Scanning** - Detect known indicators of compromise
- **Persistence Analysis** - Automated detection of persistence mechanisms

### 📦 Artifact Collection
| Category | Description |
|----------|-------------|
| System Information | Hardware, software, kernel details |
| File System | Logs, Spotlight metadata, quarantine events |
| User Data | Preferences, keychains, messages, browser data |
| System Security | TCC database, firewall rules, SIP status |
| Network | Interfaces, connections, DNS, WiFi history |
| Running System | Processes, open files, kernel extensions |
| Browser Data | Safari, Chrome, Firefox history & cookies |
| Apple Unified Logs | System logs, security events, sudo history |
| USB History | Device connection history, lockdown records |
| iCloud Artifacts | Cloud sync data, CloudKit cache |
| Persistence | LaunchAgents, LaunchDaemons, cron, login items |

### 🔧 Additional Capabilities
- **Disk Imaging** - Raw disk acquisition with SHA-256 verification
- **Memory Analysis** - Volatile data collection and process analysis
- **Rootkit Detection** - Scan for known rootkit signatures
- **Timeline Generation** - System activity chronology
- **Browser Forensics** - Extract and analyze web browser data
- **Encrypted Volume Analysis** - FileVault and APFS encryption detection

## 🚀 Installation

### Prerequisites
- macOS Catalina (10.15) or later
- Python 3.8+
- Administrative privileges (for complete artifact collection)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/Masriyan/MacFIRE.git
cd MacFIRE

# Make executable
chmod +x macfire.py

# Verify installation
python3 macfire.py --version
```

## ⚡ Quick Start

### Live Triage (Incident Response)
```bash
# Perform rapid incident assessment
sudo python3 macfire.py --live-triage ./triage_output
```

### Collect All Artifacts
```bash
# Full forensic collection
sudo python3 macfire.py --collect-artifacts ./evidence --compress
```

### List Available Categories
```bash
# See all artifact categories
python3 macfire.py --list-categories
```

### Disk Imaging
```bash
# Create forensic disk image
sudo python3 macfire.py --create-raw ./disk_images
```

## 📖 Documentation

### Command Reference

| Command | Description |
|---------|-------------|
| `--live-triage PATH` | Perform live incident triage |
| `--collect-artifacts PATH` | Collect forensic artifacts |
| `--categories CAT [CAT...]` | Collect specific categories |
| `--list-categories` | List all artifact categories |
| `--create-raw PATH` | Create raw disk image |
| `--memory-dump PATH` | Acquire memory artifacts |
| `--rootkit-check PATH` | Scan for rootkits |
| `--browser-history PATH` | Extract browser data |
| `--system-timeline PATH` | Generate activity timeline |
| `--generate-report PATH` | Create HTML report |

### Example Workflows

**Full Incident Response:**
```bash
# 1. Live triage for immediate assessment
sudo python3 macfire.py --live-triage ./ir_case001

# 2. Collect persistence-related artifacts
sudo python3 macfire.py --collect-artifacts ./ir_case001 \
    --categories "Persistence Mechanisms" "System Security" "Running System"

# 3. Generate forensic report
python3 macfire.py --generate-report ./ir_case001 --artifacts-path ./ir_case001/artifacts_*
```

**Targeted Browser Investigation:**
```bash
python3 macfire.py --browser-history ./browser_evidence
python3 macfire.py --collect-artifacts ./browser_evidence --categories "Browser Data"
```

## 🔐 Security & Privacy

- **100% Local Processing** - No data transmitted externally
- **Chain of Custody** - SHA-256 hashes for all artifacts
- **Audit Logging** - Complete operation trail
- **Minimal Footprint** - No permanent system modifications

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development setup
git clone https://github.com/Masriyan/MacFIRE.git
cd MacFIRE
python3 -m venv venv
source venv/bin/activate
```

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- **Sudo3rs** - *Lead Developer* - [security-life.org](https://security-life.org)

## ⚠️ Disclaimer

MacFIRE should only be used for legitimate forensic investigations, security research, or system administration tasks where proper authorization has been obtained. The authors are not responsible for misuse or illegal applications.

---

<div align="center">

**Made with 🔥 by the Sudo3rs Team**

[Report Bug](https://github.com/Masriyan/MacFIRE/issues) • [Request Feature](https://github.com/Masriyan/MacFIRE/issues) • [Security Policy](SECURITY.md)

</div>
