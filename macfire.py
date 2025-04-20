import os
import sys
import subprocess
import shutil
import argparse
import datetime
import hashlib
import json
import platform
import time
import threading
import logging
import tempfile
import zipfile
import re
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("macfire_forensic.log")
    ]
)
logger = logging.getLogger("macFIRE")

# Simplified Banner
BANNER = """
=============================================
  _____                ____________________ 
 |     |              |                    |
 | Mac |==============| F I R E           |
 |_____|              |____________________|

 macOS Forensic Investigation & Recovery Environment
 Version 1.2 
 by Sudo3rs
=============================================
"""

# Supported macOS Versions
SUPPORTED_MACOS = "macOS Catalina (10.15) and later"

# Forensic tool configuration - organized by categories
ARTIFACTS = {
    "System Information": {
        "description": "Basic system information",
        "commands": [
            "system_profiler SPHardwareDataType > ./system_info.txt",
            "sw_vers > ./macos_version.txt",
            "hostname > ./hostname.txt",
            "whoami > ./current_user.txt",
            "date > ./acquisition_date.txt",
            "uptime > ./uptime.txt"
        ]
    },
    "File System": {
        "description": "File system artifacts and metadata",
        "paths": [
            "/var/log/system.log",
            "/private/var/db/Spotlight-V100/",
            "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
        ],
        "commands": [
            "ls -la /Volumes/ > ./mounted_volumes.txt",
            "df -h > ./disk_usage.txt",
            "sudo find / -type f -mtime -7 -not -path '*/\.*' > ./recent_files_7days.txt"
        ]
    },
    "User Data": {
        "description": "User-specific data and configurations",
        "paths": [
            "~/Library/Preferences",
            "~/Library/Application Support",
            "~/Library/Logs",
            "~/Library/Keychains/",
            "~/Library/Messages/chat.db",
            "~/Library/Safari/History.db",
            "~/Library/Application Support/Google/Chrome/Default/History",
            "~/Library/Mail",
            "~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads",
            "~/Library/Calendars",
            "~/Library/Accounts"
        ]
    },
    "System Security": {
        "description": "Security-related artifacts",
        "paths": [
            "/Library/Application Support/com.apple.TCC/TCC.db",
            "/var/log/secure.log"
        ],
        "commands": [
            "sudo log collect --last 24h --output ./security_logs.logarchive",
            "sudo pfctl -s rules > ./firewall_rules.txt",
            "security authorizationdb read system.preferences > ./system_auth.txt",
            "sudo launchctl list > ./launch_daemons.txt"
        ]
    },
    "Network": {
        "description": "Network configurations and connections",
        "commands": [
            "ifconfig > ./network_interfaces.txt",
            "arp -a > ./arp_cache.txt",
            "netstat -an > ./network_connections.txt",
            "netstat -rn > ./routing_table.txt",
            "scutil --dns > ./dns_config.txt",
            "defaults read /Library/Preferences/SystemConfiguration/com.apple.airport.preferences > ./wifi_preferences.txt"
        ]
    },
    "Running System": {
        "description": "Currently running processes and services",
        "commands": [
            "ps aux > ./running_processes.txt",
            "lsof > ./open_files.txt",
            "ls -la /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/ > ./launch_agents.txt",
            "kmutil showloaded > ./kernel_extensions.txt",
            "sysctl -a > ./system_control.txt"
        ]
    },
    "Browser Data": {
        "description": "Web browser artifacts and history",
        "paths": [
            "~/Library/Safari/History.db",
            "~/Library/Safari/Downloads.plist",
            "~/Library/Safari/Bookmarks.plist",
            "~/Library/Application Support/Google/Chrome/Default/History",
            "~/Library/Application Support/Google/Chrome/Default/Cookies",
            "~/Library/Application Support/Google/Chrome/Default/Bookmarks",
            "~/Library/Application Support/Firefox/Profiles/*/places.sqlite",
            "~/Library/Application Support/Firefox/Profiles/*/cookies.sqlite"
        ],
        "commands": [
            "find ~/Library/Safari ~/Library/Application\\ Support/Google/Chrome ~/Library/Application\\ Support/Firefox -type f -name '*history*' -o -name '*cookie*' -o -name '*bookmark*' | grep -v Cache > ./browser_files.txt"
        ]
    },
    "Memory Acquisition": {
        "description": "Memory acquisition and volatile data",
        "commands": [
            "ps aux > ./process_listing.txt",
            "lsof > ./open_files_memory.txt",
            "netstat -an > ./network_connections_memory.txt",
            "sysctl hw > ./hardware_memory_info.txt",
            "vm_stat > ./vm_statistics.txt",
            "top -l 1 > ./top_processes.txt"
        ]
    }
}

# Progress bar for visual feedback
def progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    """Display a command-line progress bar"""
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    if iteration == total:
        print()


def run_command(command, verbose=True, sudo=False):
    """Executes a shell command and returns the output"""
    try:
        if sudo and not command.startswith("sudo"):
            command = "sudo " + command
            
        if verbose:
            logger.info(f"Running: {command}")
            
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.warning(f"Command returned non-zero exit code: {result.returncode}")
            logger.warning(f"Error: {result.stderr}")
            
        return result.stdout.strip()
    except Exception as e:
        logger.error(f"Command failed: {command}")
        logger.error(str(e))
        return None


def verify_root_privileges():
    """Verifies if the script is running with root privileges"""
    if os.geteuid() != 0:
        logger.warning("This script requires root privileges for complete forensic acquisition")
        logger.warning("Some artifacts may not be collected without root access")
        return False
    return True


def check_macos_compatibility():
    """Checks if the current macOS version is supported"""
    macos_version = platform.mac_ver()[0]
    logger.info(f"Detected macOS version: {macos_version}")
    
    # Convert version string to float for comparison (e.g., "10.15.7" to 10.15)
    major_minor = ".".join(macos_version.split(".")[:2])
    version_float = float(major_minor)
    
    if version_float < 10.15:
        logger.warning(f"Current macOS version ({macos_version}) may not be fully supported")
        logger.warning(f"Recommended: {SUPPORTED_MACOS}")
        return False
    return True


def list_disks():
    """Lists available disks on macOS"""
    logger.info("Listing available disks:")
    output = run_command("diskutil list")
    print(output)
    return output


def detect_external_drive():
    """Detects external storage devices"""
    logger.info("Detecting external storage devices...")
    output = run_command("diskutil list external")
    if output:
        print(output)
        return output
    else:
        logger.info("No external drives detected.")
        return None


def unmount_disk(disk):
    """Unmounts a specified disk"""
    logger.info(f"Unmounting disk: {disk}")
    output = run_command(f"diskutil unmountDisk {disk}")
    logger.info(output)
    return output


def create_raw_image(disk, output_path, calculate_hash=True):
    """Creates a RAW disk image using dd with progress monitoring"""
    try:
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Get disk size for progress calculation
        disk_info = run_command(f"diskutil info {disk}")
        disk_size = 0
        for line in disk_info.splitlines():
            if "Disk Size" in line:
                try:
                    # Extract the size in bytes from the line
                    size_str = line.split("(")[1].split()[0].replace(",", "")
                    disk_size = int(size_str)
                    break
                except:
                    pass
        
        # Setup output files
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        disk_name = disk.split("/")[-1]
        output_file = output_dir / f"{disk_name}_{timestamp}.dd"
        info_file = output_dir / f"{disk_name}_{timestamp}_info.txt"
        
        # Save disk info
        with open(info_file, "w") as f:
            f.write(f"Disk: {disk}\n")
            f.write(f"Acquisition started: {datetime.datetime.now()}\n")
            f.write(f"Disk information:\n{disk_info}\n")
        
        # Create raw image with progress monitoring
        logger.info(f"Creating raw disk image from {disk} to {output_file}")
        
        # Use dcfldd if available for built-in hashing and progress
        dcfldd_available = run_command("which dcfldd", verbose=False)
        
        if dcfldd_available:
            hash_args = "sha256" if calculate_hash else ""
            cmd = f"dcfldd if={disk} of={output_file} bs=4M {hash_args} statusinterval=16"
            run_command(cmd)
        else:
            # Use dd with separate progress monitoring
            dd_process = subprocess.Popen(
                f"dd if={disk} of={output_file} bs=4M status=progress",
                shell=True,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Wait for dd to finish
            dd_process.wait()
            
            # Calculate hash if requested
            if calculate_hash and output_file.exists():
                logger.info(f"Calculating SHA-256 hash of disk image...")
                sha256 = calculate_file_hash(str(output_file))
                hash_file = output_dir / f"{disk_name}_{timestamp}.sha256"
                with open(hash_file, "w") as f:
                    f.write(f"{sha256} *{output_file.name}\n")
                logger.info(f"Hash saved to {hash_file}")
        
        # Update info file with completion info
        with open(info_file, "a") as f:
            f.write(f"Acquisition completed: {datetime.datetime.now()}\n")
            if calculate_hash:
                f.write(f"SHA-256: {sha256}\n")
        
        logger.info("Image created successfully.")
        return str(output_file)
    
    except Exception as e:
        logger.error(f"Failed to create raw image: {e}")
        return None


def verify_disk_image_integrity(image_path, hash_file=None):
    """Verifies the integrity of a disk image using its hash file"""
    try:
        image_path = Path(image_path)
        
        # If no hash file provided, look for one with the same name
        if not hash_file:
            potential_hash_file = image_path.with_suffix('.sha256')
            if potential_hash_file.exists():
                hash_file = potential_hash_file
            else:
                logger.error(f"No hash file found for {image_path}")
                return False
        
        # Read the expected hash from the hash file
        hash_file = Path(hash_file)
        with open(hash_file, 'r') as f:
            hash_content = f.read().strip()
            expected_hash = hash_content.split()[0]
        
        logger.info(f"Verifying integrity of {image_path}")
        logger.info(f"Expected hash: {expected_hash}")
        
        # Calculate the current hash
        current_hash = calculate_file_hash(str(image_path))
        logger.info(f"Calculated hash: {current_hash}")
        
        # Compare hashes
        if current_hash == expected_hash:
            logger.info("Image integrity verified: PASS")
            return True
        else:
            logger.warning("Image integrity check: FAIL - Hashes do not match")
            return False
            
    except Exception as e:
        logger.error(f"Failed to verify disk image integrity: {e}")
        return False


def calculate_file_hash(file_path, algorithm='sha256', block_size=65536):
    """Calculate hash of a file"""
    hash_obj = hashlib.new(algorithm)
    with open(file_path, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            hash_obj.update(block)
    return hash_obj.hexdigest()


def compress_artifacts(artifacts_path, output_path=None):
    """Compresses collected artifacts into a ZIP file"""
    try:
        artifacts_dir = Path(artifacts_path)
        
        if not artifacts_dir.exists() or not artifacts_dir.is_dir():
            logger.error(f"Artifacts directory not found: {artifacts_dir}")
            return None
            
        # Determine output path
        if not output_path:
            output_path = artifacts_dir.parent
        
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create ZIP filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_file = output_dir / f"{artifacts_dir.name}_{timestamp}.zip"
        
        logger.info(f"Compressing artifacts to {zip_file}")
        
        # Create ZIP file
        artifact_count = 0
        file_count = sum([len(files) for _, _, files in os.walk(artifacts_dir)])
        
        with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(artifacts_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, artifacts_dir.parent)
                    zipf.write(file_path, arcname)
                    
                    artifact_count += 1
                    if file_count > 0:
                        progress_bar(artifact_count, file_count, 
                                     prefix='Compressing artifacts:', 
                                     suffix=f'({artifact_count}/{file_count})')
        
        logger.info(f"Compression complete. Archive saved at: {zip_file}")
        
        # Calculate and save hash
        zip_hash = calculate_file_hash(str(zip_file))
        hash_file = zip_file.with_suffix('.sha256')
        with open(hash_file, 'w') as f:
            f.write(f"{zip_hash} *{zip_file.name}\n")
        
        logger.info(f"Archive hash: {zip_hash}")
        return str(zip_file)
        
    except Exception as e:
        logger.error(f"Failed to compress artifacts: {e}")
        return None


def acquire_memory_dump(output_path):
    """Acquires a memory dump using available methods on macOS"""
    try:
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        memory_dir = output_dir / f"memory_dump_{timestamp}"
        memory_dir.mkdir()
        
        logger.info(f"Acquiring memory artifacts to {memory_dir}...")
        
        # Check for OSXPmem availability
        osxpmem_path = run_command("which osxpmem", verbose=False)
        
        if osxpmem_path:
            # Use OSXPmem for memory acquisition
            memory_file = memory_dir / "memory.raw"
            logger.info(f"Using OSXPmem to acquire memory to {memory_file}")
            
            cmd = f"sudo {osxpmem_path} {memory_file}"
            result = run_command(cmd)
            
            if result and os.path.exists(memory_file):
                logger.info("Memory acquisition successful using OSXPmem")
                return str(memory_dir)
        
        # Alternative: Collect process memory information
        logger.info("Direct memory acquisition not available. Collecting process memory information...")
        
        # Create process listings
        run_command("ps aux > " + str(memory_dir / "processes.txt"))
        run_command("lsof > " + str(memory_dir / "open_files.txt"))
        run_command("sudo dtrace -n 'syscall:::entry { @[execname] = count(); }' -c 'sleep 5' > " + 
                    str(memory_dir / "syscalls.txt"))
        
        # Get VM statistics
        run_command("vm_stat > " + str(memory_dir / "vm_stat.txt"))
        run_command("top -l 1 > " + str(memory_dir / "top.txt"))
        
        # Get loaded kernel extensions
        run_command("kextstat > " + str(memory_dir / "kextstat.txt"))
        
        logger.info(f"Memory artifact collection complete. Saved to {memory_dir}")
        return str(memory_dir)
        
    except Exception as e:
        logger.error(f"Failed to acquire memory: {e}")
        return None


def check_for_rootkits(output_path):
    """Checks for known rootkit signatures and suspicious system modifications"""
    try:
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        rootkit_check_file = output_dir / f"rootkit_check_{timestamp}.txt"
        
        logger.info("Checking for rootkits and suspicious system modifications...")
        
        with open(rootkit_check_file, 'w') as f:
            f.write("=== macFIRE Rootkit Check Report ===\n")
            f.write(f"Generated: {datetime.datetime.now()}\n\n")
            
            # Check for hidden files in system locations
            f.write("=== Hidden Files in System Locations ===\n")
            hidden_files = run_command("sudo find /System /Library /usr -name '.*' -type f | grep -v '.DS_Store'")
            f.write(hidden_files or "No suspicious hidden files found.\n")
            f.write("\n")
            
            # Check for unexpected SUID/SGID binaries
            f.write("=== Unexpected SUID/SGID Binaries ===\n")
            suid_files = run_command("sudo find /System /usr /bin /sbin -perm -4000 -o -perm -2000")
            f.write(suid_files or "No unexpected SUID/SGID binaries found.\n")
            f.write("\n")
            
            # Check for unusual kernel extensions
            f.write("=== Loaded Kernel Extensions ===\n")
            kexts = run_command("kextstat")
            f.write(kexts or "No kernel extensions information available.\n")
            f.write("\n")
            
            # Check startup items
            f.write("=== Startup Items ===\n")
            startup_items = run_command("ls -la /Library/StartupItems/ /System/Library/StartupItems/ 2>/dev/null")
            f.write(startup_items or "No startup items found.\n")
            f.write("\n")
            
            # Check launch agents and daemons
            f.write("=== Launch Agents and Daemons ===\n")
            launch_items = run_command("ls -la /Library/LaunchAgents/ /Library/LaunchDaemons/ "
                                      "/System/Library/LaunchAgents/ /System/Library/LaunchDaemons/ "
                                      "~/Library/LaunchAgents/ 2>/dev/null")
            f.write(launch_items or "No launch agents/daemons found.\n")
            f.write("\n")
            
            # Check for suspicious processes
            f.write("=== Suspicious Processes ===\n")
            processes = run_command("ps aux | grep -i '[r]ootkit\\|[h]ack\\|[i]nject'")
            f.write(processes or "No suspicious processes found.\n")
            f.write("\n")
            
            # Check for suspicious network connections
            f.write("=== Suspicious Network Connections ===\n")
            connections = run_command("netstat -an | grep ESTABLISHED")
            f.write(connections or "No established network connections found.\n")
            
        logger.info(f"Rootkit check complete. Report saved to {rootkit_check_file}")
        return str(rootkit_check_file)
        
    except Exception as e:
        logger.error(f"Failed to check for rootkits: {e}")
        return None


def extract_browser_history(output_path):
    """Extracts and parses browser history from common browsers"""
    try:
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        browser_dir = output_dir / f"browser_history_{timestamp}"
        browser_dir.mkdir()
        
        logger.info(f"Extracting browser history to {browser_dir}...")
        
        # Define browser database paths
        browsers = {
            "Safari": {
                "history": "~/Library/Safari/History.db",
                "downloads": "~/Library/Safari/Downloads.plist"
            },
            "Chrome": {
                "history": "~/Library/Application Support/Google/Chrome/Default/History",
                "downloads": "~/Library/Application Support/Google/Chrome/Default/History"
            },
            "Firefox": {
                "history": "~/Library/Application Support/Firefox/Profiles/*/places.sqlite",
                "downloads": "~/Library/Application Support/Firefox/Profiles/*/downloads.sqlite"
            }
        }
        
        # Process each browser
        for browser, paths in browsers.items():
            browser_output_dir = browser_dir / browser
            browser_output_dir.mkdir()
            
            logger.info(f"Processing {browser} history...")
            
            # Copy database files
            for db_type, db_path in paths.items():
                expanded_path = os.path.expanduser(db_path)
                
                # Handle wildcards in path (e.g., Firefox profiles)
                if '*' in expanded_path:
                    matching_files = list(Path(expanded_path.split('*')[0]).glob('*' + expanded_path.split('*')[1]))
                    for file_path in matching_files:
                        if file_path.exists():
                            dest_path = browser_output_dir / f"{db_type}_{file_path.name}"
                            try:
                                shutil.copy2(file_path, dest_path)
                                logger.info(f"Copied {browser} {db_type} database: {file_path}")
                            except Exception as e:
                                logger.error(f"Failed to copy {file_path}: {e}")
                else:
                    if os.path.exists(expanded_path):
                        dest_path = browser_output_dir / f"{db_type}_{os.path.basename(expanded_path)}"
                        try:
                            shutil.copy2(expanded_path, dest_path)
                            logger.info(f"Copied {browser} {db_type} database: {expanded_path}")
                        except Exception as e:
                            logger.error(f"Failed to copy {expanded_path}: {e}")
        
        # Generate a simple report
        report_file = browser_dir / "browser_extraction_report.txt"
        with open(report_file, 'w') as f:
            f.write("=== Browser History Extraction Report ===\n")
            f.write(f"Generated: {datetime.datetime.now()}\n\n")
            
            for browser in browsers:
                browser_dir_path = browser_dir / browser
                if browser_dir_path.exists():
                    f.write(f"=== {browser} Artifacts ===\n")
                    for file in browser_dir_path.glob('*'):
                        f.write(f"- {file.name}\n")
                    f.write("\n")
            
            f.write("\nNote: To analyze these files, specialized tools or SQL queries may be required.\n")
        
        logger.info(f"Browser history extraction complete. Saved to {browser_dir}")
        return str(browser_dir)
        
    except Exception as e:
        logger.error(f"Failed to extract browser history: {e}")
        return None


def get_system_timeline(output_path, days=7):
    """Creates a system activity timeline based on file modification times and logs"""
    try:
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        timeline_file = output_dir / f"system_timeline_{timestamp}.csv"
        
        logger.info(f"Generating system timeline for the last {days} days...")
        
        # Write CSV header
        with open(timeline_file, 'w') as f:
            f.write("Timestamp,Event Type,Description,Path\n")
        
        # Get recently modified files
        logger.info("Finding recently modified files...")
        cmd = f"sudo find /Users /Applications /Library /System/Library /var/log -type f -mtime -{days} -not -path '*/\\.*' 2>/dev/null"
        recent_files = run_command(cmd)
        
        if recent_files:
            files_list = recent_files.splitlines()
            file_count = len(files_list)
            logger.info(f"Found {file_count} recently modified files")
            
            # Process each file and add to timeline
            with open(timeline_file, 'a') as f:
                for i, file_path in enumerate(files_list):
                    if i % 100 == 0:
                        progress_bar(i, file_count, 
                                     prefix='Building timeline:', 
                                     suffix=f'({i}/{file_count})')
                    
                    try:
                        # Get file stats
                        stats = os.stat(file_path)
                        mtime = datetime.datetime.fromtimestamp(stats.st_mtime)
                        
                        # Determine event type based on path
                        if "/var/log/" in file_path:
                            event_type = "Log"
                        elif "/Library/LaunchAgents/" in file_path or "/Library/LaunchDaemons/" in file_path:
                            event_type = "Launch Item"
                        elif "/Library/Preferences/" in file_path:
                            event_type = "Preference"
                        elif "/Applications/" in file_path:
                            event_type = "Application"
                        else:
                            event_type = "File Modification"
                            
                        # Add to timeline
                        f.write(f"{mtime},{event_type},\"Modified\",\"{file_path}\"\n")
                    except Exception as e:
                        logger.debug(f"Error processing file {file_path}: {e}")
                        continue
            
            # Complete the progress bar
            progress_bar(file_count, file_count, 
                         prefix='Building timeline:', 
                         suffix='Complete')
        
        # Add system log entries
        logger.info("Adding system log entries to timeline...")
        log_cmd = f"log show --style syslog --last {days}d > {output_dir}/temp_syslog.txt"
        run_command(log_cmd)
        
        syslog_path = output_dir / "temp_syslog.txt"
        if syslog_path.exists():
                            # Parse syslog entries and add to timeline
            with open(syslog_path, 'r') as log_file, open(timeline_file, 'a') as timeline:
                for line in log_file:
                    try:
                        # Basic syslog parsing
                        match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+).*?(\w+)\s+([^:]+):\s+(.*)', line)
                        if match:
                            timestamp_str, _, process, message = match.groups()
                            try:
                                # Try to parse the timestamp
                                current_year = datetime.datetime.now().year
                                timestamp = datetime.datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                                
                                # Add to timeline
                                timeline.write(f"{timestamp},System Log,\"{process}\",\"{message.replace(',', ' ')}\"\n")
                            except:
                                pass
                    except Exception as e:
                        continue
            
            # Clean up temp file
            syslog_path.unlink()
        
        logger.info(f"Timeline generation complete. Saved to {timeline_file}")
        
        # Sort the timeline by timestamp
        logger.info("Sorting timeline by timestamp...")
        sorted_timeline_file = output_dir / f"system_timeline_sorted_{timestamp}.csv"
        
        # Read the original file and sort
        with open(timeline_file, 'r') as f:
            header = f.readline()
            lines = f.readlines()
        
        # Sort lines by the timestamp field
        sorted_lines = sorted(lines, key=lambda x: x.split(',')[0] if len(x.split(',')) > 0 else "")
        
        # Write the sorted file
        with open(sorted_timeline_file, 'w') as f:
            f.write(header)
            f.writelines(sorted_lines)
        
        logger.info(f"Sorted timeline saved to {sorted_timeline_file}")
        return str(sorted_timeline_file)
        
    except Exception as e:
        logger.error(f"Failed to generate system timeline: {e}")
        return None


def acquire_encrypted_volumes(output_path):
    """Identifies and acquires information about encrypted volumes"""
    try:
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        encrypted_info_file = output_dir / f"encrypted_volumes_{timestamp}.txt"
        
        logger.info("Acquiring information about encrypted volumes...")
        
        with open(encrypted_info_file, 'w') as f:
            f.write("=== Encrypted Volumes Report ===\n")
            f.write(f"Generated: {datetime.datetime.now()}\n\n")
            
            # Get FileVault status
            f.write("=== FileVault Status ===\n")
            filevault_status = run_command("sudo fdesetup status")
            f.write(filevault_status or "FileVault status information not available.\n")
            f.write("\n")
            
            # List all volumes
            f.write("=== All Volumes ===\n")
            all_volumes = run_command("diskutil list")
            f.write(all_volumes or "No volumes information available.\n")
            f.write("\n")
            
            # Get encrypted APFS volumes
            f.write("=== APFS Encrypted Volumes ===\n")
            apfs_volumes = run_command("diskutil apfs list | grep -A 10 Encrypted")
            f.write(apfs_volumes or "No encrypted APFS volumes found.\n")
            f.write("\n")
            
            # Get encrypted Core Storage volumes
            f.write("=== CoreStorage Encrypted Volumes ===\n")
            cs_volumes = run_command("diskutil cs list | grep -A 10 Encrypted")
            f.write(cs_volumes or "No encrypted CoreStorage volumes found.\n")
            f.write("\n")
            
            # Check for TrueCrypt/VeraCrypt
            f.write("=== TrueCrypt/VeraCrypt Detection ===\n")
            tc_files = run_command("find /Volumes -name '.tc_file' -o -name '.vera_file' 2>/dev/null")
            f.write(tc_files or "No TrueCrypt/VeraCrypt indicators found.\n")
            f.write("\n")
            
            # Additional encryption info
            f.write("=== Additional Encryption Information ===\n")
            encryption_info = run_command("security list-keychains")
            f.write(encryption_info or "No additional encryption information available.\n")
            
        logger.info(f"Encrypted volumes information acquired. Report saved to {encrypted_info_file}")
        return str(encrypted_info_file)
        
    except Exception as e:
        logger.error(f"Failed to acquire encrypted volumes information: {e}")
        return None


def backup_metadata(artifacts_path):
    """Creates metadata backup for all collected artifacts"""
    try:
        artifacts_dir = Path(artifacts_path)
        
        if not artifacts_dir.exists() or not artifacts_dir.is_dir():
            logger.error(f"Artifacts directory not found: {artifacts_dir}")
            return None
            
        metadata_file = artifacts_dir / "metadata_backup.json"
        logger.info(f"Creating metadata backup for artifacts in {artifacts_dir}")
        
        metadata = {
            "timestamp": datetime.datetime.now().isoformat(),
            "collector": run_command("whoami", verbose=False),
            "hostname": run_command("hostname", verbose=False),
            "macos_version": run_command("sw_vers -productVersion", verbose=False),
            "artifacts": {}
        }
        
        # Recursively process all files in the artifacts directory
        for root, dirs, files in os.walk(artifacts_dir):
            rel_path = os.path.relpath(root, artifacts_dir)
            
            for file in files:
                # Skip the metadata file itself
                if file == metadata_file.name:
                    continue
                    
                file_path = os.path.join(root, file)
                try:
                    stat_info = os.stat(file_path)
                    file_hash = calculate_file_hash(file_path)
                    
                    metadata["artifacts"][os.path.join(rel_path, file)] = {
                        "size": stat_info.st_size,
                        "created": datetime.datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                        "modified": datetime.datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                        "accessed": datetime.datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                        "sha256": file_hash
                    }
                except Exception as e:
                    logger.warning(f"Failed to get metadata for {file_path}: {e}")
        
        # Save metadata to JSON file
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Metadata backup created at {metadata_file}")
        return str(metadata_file)
        
    except Exception as e:
        logger.error(f"Failed to create metadata backup: {e}")
        return None


def collect_artifacts(output_path, categories=None):
    """Collects forensic artifacts from macOS"""
    try:
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create timestamped directory for this collection
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        collection_dir = output_dir / f"artifacts_{timestamp}"
        collection_dir.mkdir()
        
        logger.info(f"Collecting forensic artifacts to {collection_dir}...")
        
        # Use all categories if none specified
        if not categories:
            categories = list(ARTIFACTS.keys())
        
        artifact_count = 0
        total_artifacts = sum(
            len(ARTIFACTS[cat].get("paths", [])) + len(ARTIFACTS[cat].get("commands", []))
            for cat in categories
        )
        
        # Track collection stats
        collection_stats = {
            "start_time": datetime.datetime.now().isoformat(),
            "categories": {},
            "collected_count": 0,
            "failed_count": 0
        }
        
        # Process each category
        for category in categories:
            if category not in ARTIFACTS:
                logger.warning(f"Category not found: {category}")
                continue
                
            logger.info(f"Processing category: {category}")
            
            # Create category directory
            category_dir = collection_dir / category.replace(" ", "_")
            category_dir.mkdir()
            
            category_stats = {
                "description": ARTIFACTS[category]["description"],
                "collected": [],
                "failed": []
            }
            
            # Copy files
            for path in ARTIFACTS[category].get("paths", []):
                expanded_path = os.path.expanduser(path)
                dest_name = Path(expanded_path).name
                dest_path = category_dir / dest_name
                
                try:
                    artifact_count += 1
                    progress_bar(artifact_count, total_artifacts, 
                                 prefix='Collecting artifacts:', 
                                 suffix=f'({artifact_count}/{total_artifacts})')
                    
                    if os.path.exists(expanded_path):
                        if os.path.isdir(expanded_path):
                            shutil.copytree(expanded_path, dest_path)
                        else:
                            shutil.copy2(expanded_path, dest_path)
                        logger.info(f"Collected: {path}")
                        category_stats["collected"].append(path)
                        collection_stats["collected_count"] += 1
                    else:
                        logger.warning(f"Path not found: {path}")
                        category_stats["failed"].append({"path": path, "reason": "Path not found"})
                        collection_stats["failed_count"] += 1
                        
                except Exception as e:
                    logger.error(f"Failed to collect {path}: {e}")
                    category_stats["failed"].append({"path": path, "reason": str(e)})
                    collection_stats["failed_count"] += 1
            
            # Run commands
            for command in ARTIFACTS[category].get("commands", []):
                artifact_count += 1
                progress_bar(artifact_count, total_artifacts, 
                             prefix='Collecting artifacts:', 
                             suffix=f'({artifact_count}/{total_artifacts})')
                
                try:
                    # Extract output filename from command if it contains redirection
                    if " > " in command:
                        output_file = command.split(" > ")[1].strip()
                        cmd = command.replace(output_file, str(category_dir / Path(output_file).name))
                    else:
                        # For commands without redirection, create a default output file
                        cmd_name = command.split()[0]
                        cmd = f"{command} > {category_dir / f'{cmd_name}_output.txt'}"
                    
                    result = run_command(cmd)
                    logger.info(f"Executed: {command}")
                    category_stats["collected"].append(command)
                    collection_stats["collected_count"] += 1
                    
                except Exception as e:
                    logger.error(f"Failed to execute {command}: {e}")
                    category_stats["failed"].append({"command": command, "reason": str(e)})
                    collection_stats["failed_count"] += 1
            
            collection_stats["categories"][category] = category_stats
        
        # Complete the progress bar
        progress_bar(total_artifacts, total_artifacts, 
                     prefix='Collecting artifacts:', 
                     suffix='Complete')
        
        # Finalize collection stats
        collection_stats["end_time"] = datetime.datetime.now().isoformat()
        collection_stats["duration_seconds"] = (
            datetime.datetime.fromisoformat(collection_stats["end_time"]) - 
            datetime.datetime.fromisoformat(collection_stats["start_time"])
        ).total_seconds()
        
        # Save collection stats
        stats_file = collection_dir / "collection_stats.json"
        with open(stats_file, "w") as f:
            json.dump(collection_stats, f, indent=2)
        
        # Create metadata backup
        backup_metadata(collection_dir)
        
        logger.info(f"Artifact collection complete. Collected {collection_stats['collected_count']} artifacts.")
        logger.info(f"Collection stats saved to {stats_file}")
        
        return str(collection_dir)
    
    except Exception as e:
        logger.error(f"Failed to collect artifacts: {e}")
        return None


def generate_report(output_path, artifacts_path=None):
    """Generates a forensic report summarizing collected data."""
    try:
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = output_dir / f"forensic_report_{timestamp}.html"
        
        # Get system information
        hostname = run_command("hostname", verbose=False) or "Unknown"
        mac_version = run_command("sw_vers", verbose=False) or "Unknown"
        hw_info = run_command("system_profiler SPHardwareDataType", verbose=False) or "Unknown"
        
        # Begin HTML report
        with open(report_file, "w") as report:
            report.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>macOS Forensic Report - {timestamp}</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background-color: #3498db; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; background-color: #f9f9f9; border-radius: 5px; }}
        .artifact {{ margin: 10px 0; }}
        .artifact-path {{ font-family: monospace; background-color: #f0f0f0; padding: 3px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #3498db; color: white; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .footer {{ margin-top: 30px; font-size: 0.8em; text-align: center; color: #7f8c8d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>macOS Forensic Report</h1>
            <p>Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <div class="section">
            <h2>System Information</h2>
            <pre>{hw_info}</pre>
            <h3>macOS Version</h3>
            <pre>{mac_version}</pre>
            <h3>Hostname</h3>
            <pre>{hostname}</pre>
        </div>
        
        <div class="section">
            <h2>Acquisition Summary</h2>
            <p>Acquisition performed by: {run_command("whoami", verbose=False) or "Unknown"}</p>
            <p>Tool version: macOS Forensic Investigation & Recovery Environment v1.1</p>
            <p>Acquisition timestamp: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
""")

            # If artifacts were collected, include stats
            if artifacts_path:
                artifacts_dir = Path(artifacts_path)
                stats_file = artifacts_dir / "collection_stats.json"
                
                if stats_file.exists():
                    with open(stats_file, "r") as f:
                        stats = json.load(f)
                    
                    report.write(f"""
            <h3>Artifact Collection Statistics</h3>
            <p>Collection started: {stats["start_time"]}</p>
            <p>Collection completed: {stats["end_time"]}</p>
            <p>Duration: {stats["duration_seconds"]:.2f} seconds</p>
            <p>Artifacts collected: {stats["collected_count"]}</p>
            <p>Artifacts failed: {stats["failed_count"]}</p>
            
            <h3>Categories</h3>
            <table>
                <tr>
                    <th>Category</th>
                    <th>Description</th>
                    <th>Collected</th>
                    <th>Failed</th>
                </tr>
""")
                    
                    for category, cat_stats in stats["categories"].items():
                        report.write(f"""
                <tr>
                    <td>{category}</td>
                    <td>{cat_stats["description"]}</td>
                    <td>{len(cat_stats["collected"])}</td>
                    <td>{len(cat_stats["failed"])}</td>
                </tr>
""")
                    
                    report.write("</table>")
            
            # Add artifact descriptions
            report.write(f"""
        </div>
        
        <div class="section">
            <h2>Collected Artifacts</h2>
""")

            for category, artifacts in ARTIFACTS.items():
                report.write(f"""
            <h3>{category}</h3>
            <p>{artifacts["description"]}</p>
            
            <h4>Files & Directories</h4>
            <ul>
""")
                for path in artifacts.get("paths", []):
                    report.write(f'<li class="artifact"><span class="artifact-path">{path}</span></li>\n')
                
                report.write(f"""
            </ul>
            
            <h4>Commands</h4>
            <ul>
""")
                for cmd in artifacts.get("commands", []):
                    report.write(f'<li class="artifact"><span class="artifact-path">{cmd}</span></li>\n')
                
                report.write("</ul>\n")
            
            # Close the HTML document
            report.write(f"""
        </div>
        
        <div class="footer">
            <p>Generated by macOS Forensic Investigation & Recovery Environment v1.1</p>
            <p>Sudo3rs &copy; {datetime.datetime.now().year}</p>
        </div>
    </div>
</body>
</html>
""")
        
        logger.info(f"Forensic report saved at: {report_file}")
        return str(report_file)
    
    except Exception as e:
        logger.error(f"Failed to generate forensic report: {e}")
        return None


def main():
    print(BANNER)
    logger.info(f"Supported macOS Versions: {SUPPORTED_MACOS}")
    
    # Create parser with description
    parser = argparse.ArgumentParser(
        description="macOS Forensic Investigation & Recovery Environment - Collect and analyze forensic artifacts from macOS systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Example usage:\n"
               f"  sudo python3 {os.path.basename(__file__)} --collect-artifacts ./evidence\n"
               f"  sudo python3 {os.path.basename(__file__)} --create-raw ./disk_images\n"
               f"  python3 {os.path.basename(__file__)} --list-disks\n"
    )
    
    # Basic functions
    parser.add_argument("--list-disks", action="store_true", help="List available disks")
    parser.add_argument("--detect-external", action="store_true", help="Detect external storage devices")
    parser.add_argument("--unmount", type=str, help="Unmount a specified disk (e.g., /dev/disk2)")
    
    # Disk imaging
    disk_group = parser.add_argument_group('Disk Imaging')
    disk_group.add_argument("--create-raw", type=str, metavar="OUTPUT_PATH", help="Create a raw disk image and store it in the given path")
    disk_group.add_argument("--skip-hash", action="store_true", help="Skip hash calculation when creating disk images (faster)")
    disk_group.add_argument("--verify-image", type=str, metavar="IMAGE_PATH", help="Verify the integrity of a disk image")
    disk_group.add_argument("--verify-hash-file", type=str, metavar="HASH_FILE", help="Specify hash file for image verification")
    
    # Artifact collection
    collection_group = parser.add_argument_group('Artifact Collection')
    collection_group.add_argument("--collect-artifacts", type=str, metavar="OUTPUT_PATH", help="Collect forensic artifacts and store them in the given path")
    collection_group.add_argument("--categories", type=str, nargs="+", help="Specific artifact categories to collect (default: all)")
    collection_group.add_argument("--compress", action="store_true", help="Compress artifacts after collection")
    
    # Memory acquisition
    memory_group = parser.add_argument_group('Memory Acquisition')
    memory_group.add_argument("--memory-dump", type=str, metavar="OUTPUT_PATH", help="Acquire system memory artifacts")
    
    # Additional analysis
    analysis_group = parser.add_argument_group('Analysis Options')
    analysis_group.add_argument("--rootkit-check", type=str, metavar="OUTPUT_PATH", help="Check for rootkits and suspicious system modifications")
    analysis_group.add_argument("--browser-history", type=str, metavar="OUTPUT_PATH", help="Extract and analyze browser history")
    analysis_group.add_argument("--system-timeline", type=str, metavar="OUTPUT_PATH", help="Generate a system activity timeline")
    analysis_group.add_argument("--timeline-days", type=int, default=7, help="Number of days to include in timeline (default: 7)")
    analysis_group.add_argument("--encrypted-volumes", type=str, metavar="OUTPUT_PATH", help="Identify and analyze encrypted volumes")
    
    # Reporting
    report_group = parser.add_argument_group('Reporting')
    report_group.add_argument("--generate-report", type=str, metavar="OUTPUT_PATH", help="Generate a forensic report")
    report_group.add_argument("--artifacts-path", type=str, help="Path to artifacts for report generation")
    report_group.add_argument("--backup-metadata", type=str, metavar="ARTIFACTS_PATH", help="Create metadata backup for collected artifacts")
    
    # Misc options
    parser.add_argument("--quiet", action="store_true", help="Minimize output (quiet mode)")
    parser.add_argument("--version", action="version", version="macOS Forensic Investigation & Recovery Environment v1.1")
    
    args = parser.parse_args()
    
    # Set logging level based on quiet flag
    if args.quiet:
        logger.setLevel(logging.WARNING)
    
    # Check root privileges for certain operations
    operations_needing_root = [
        args.create_raw, args.collect_artifacts, args.memory_dump, 
        args.rootkit_check, args.system_timeline
    ]
    
    if any(operations_needing_root):
        if not verify_root_privileges():
            logger.warning("Some operations may fail without root privileges")
            user_input = input("Continue anyway? (y/n): ").lower()
            if user_input != 'y':
                logger.info("Exiting.")
                return
    
    # Check macOS compatibility
    check_macos_compatibility()
    
    # Execute requested operation
    if args.list_disks:
        list_disks()
    
    elif args.detect_external:
        detect_external_drive()
    
    elif args.unmount:
        unmount_disk(args.unmount)
    
    elif args.create_raw:
        disk = input("Enter the disk path (e.g., /dev/disk2): ")
        confirm = input(f"WARNING: Creating a raw image of {disk}. Continue? (y/n): ").lower()
        if confirm == 'y':
            create_raw_image(disk, args.create_raw, not args.skip_hash)
        else:
            logger.info("Disk imaging cancelled.")
    
    elif args.verify_image:
        verify_disk_image_integrity(args.verify_image, args.verify_hash_file)
    
    elif args.collect_artifacts:
        artifacts_path = collect_artifacts(args.collect_artifacts, args.categories)
        
        # Compress if requested
        if artifacts_path and args.compress:
            compress_artifacts(artifacts_path)
        
        # Offer to generate a report
        if artifacts_path:
            generate_report_option = input("Would you like to generate a report of collected artifacts? (y/n): ").lower()
            if generate_report_option == 'y':
                generate_report(args.collect_artifacts, artifacts_path)
    
    elif args.generate_report:
        generate_report(args.generate_report, args.artifacts_path)
    
    elif args.memory_dump:
        acquire_memory_dump(args.memory_dump)
    
    elif args.rootkit_check:
        check_for_rootkits(args.rootkit_check)
    
    elif args.browser_history:
        extract_browser_history(args.browser_history)
    
    elif args.system_timeline:
        get_system_timeline(args.system_timeline, args.timeline_days)
    
    elif args.encrypted_volumes:
        acquire_encrypted_volumes(args.encrypted_volumes)
    
    elif args.backup_metadata:
        backup_metadata(args.backup_metadata)
    
    elif args.compress and args.artifacts_path:
        compress_artifacts(args.artifacts_path)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("\nOperation interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        sys.exit(1)
