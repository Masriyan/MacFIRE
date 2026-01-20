# Changelog

All notable changes to MacFIRE will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-01-20

### 🚀 Major Release - Incident Response Enhancement

This release transforms MacFIRE from a forensic acquisition tool into a comprehensive incident response platform.

### Added

#### New Features
- **Live Triage Mode** - Rapid incident response assessment with automated checks:
  - Suspicious process detection
  - Network connection analysis
  - Persistence mechanism review
  - Recent file modification checks
  - User session monitoring
  - System integrity verification

- **MITRE ATT&CK Mapping** - Findings mapped to ATT&CK techniques for threat intelligence

- **IOC Pattern Matching** - Built-in indicators of compromise detection:
  - Suspicious paths
  - Known malicious processes
  - Common persistence locations

- **New Artifact Categories**:
  - Apple Unified Logs (system, security, sudo logs)
  - USB History (device connections, lockdown records)
  - Application History (installed apps, usage analytics)
  - iCloud Artifacts (cloud sync data, CloudKit cache)
  - Persistence Mechanisms (LaunchAgents, cron, login items)

#### Stability Improvements
- Custom exception hierarchy (`MacFIREException`, `CommandTimeoutError`, etc.)
- Timeout decorator for long-running operations (300s default)
- Retry logic with exponential backoff
- Rotating log files (10MB max, 5 backups)

#### Performance Improvements
- Parallel command execution with `ThreadPoolExecutor`
- Progress tracker with ETA calculation
- Optimized error handling in command execution

#### CLI Enhancements
- `--live-triage PATH` - Perform live incident triage
- `--list-categories` - Display all artifact categories with priorities
- Enhanced version display with dynamic version string

### Changed
- Updated version to 2.0.0
- New professional ASCII banner with colors
- Improved error messages with stderr capture
- Enhanced artifact categories with priority levels
- Better command output handling with stderr redirection

### Documentation
- Complete README.md rewrite with new banner
- Added CONTRIBUTING.md with development guidelines
- Added CHANGELOG.md (this file)
- Added requirements.txt

---

## [1.2.0] - 2025-04-01

### Added
- Memory acquisition functionality
- Rootkit detection module
- Browser history extraction
- System timeline generation
- Encrypted volume analysis
- Artifact compression with integrity verification
- Metadata backup functionality

### Changed
- Simplified banner design
- Organized commands into logical argument groups
- Enhanced error handling throughout

---

## [1.1.0] - 2025-03-01

### Added
- Category-based artifact collection
- HTML report generation
- SHA-256 integrity verification
- Progress bar visualization
- Detailed logging

### Changed
- Improved disk imaging with hash calculation
- Better macOS compatibility checking

---

## [1.0.0] - 2025-01-01

### Added
- Initial release
- Basic artifact collection
- Disk listing and external drive detection
- Raw disk imaging
- Basic forensic report generation
