import os
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

# Banner (Customize as needed)
BANNER = """
=================================

    .__________________________.
    | .___________________. |==|
    | | ................. | |  |
    | | ::::Apple ][::::: | |  |
    | | ::::::::::::::::: | |  |
    | | ::::::::::::::::: | |  |
    | | ::::::::::::::::: | |  |
    | | ::::::::::::::::: | |  |
    | | ::::::::::::::::: | | ,|
    | !___________________! |(c|
    !_______________________!__!
   /                            \\
  /  [][][][][][][][][][][][][]  \\
 /  [][][][][][][][][][][][][][]  \\
(  [][][][][____________][][][][]  )
 \\ ------------------------------ /
  \\______________________________/
                      _____ ___ ____  _____ 
 _ __ ___   __ _  ___|  ___|_ _|  _ \\| ____|
| '_ ` _ \\ / _` |/ __| |_   | || |_) |  _|  
| | | | | | (_| | (__|  _|  | ||  _ <| |___ 
|_| |_| |_|\\__,_|\\___|_|   |___|_| \\_\\_____| 
 macOS Forensic Acquisition Tool v1.1
 by Sudo3rs
=================================
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


def calculate_file_hash(file_path, algorithm='sha256', block_size=65536):
    """Calculate hash of a file"""
    hash_obj = hashlib.new(algorithm)
    with open(file_path, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            hash_obj.update(block)
    return hash_obj.hexdigest()


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
            <p>Tool version: macOS Forensic Acquisition Tool v1.1</p>
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
            <p>Generated by macOS Forensic Acquisition Tool v1.1</p>
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
        description="macOS Forensic Acquisition Tool - Collect and analyze forensic artifacts from macOS systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Example usage:\n"
               f"  sudo python3 {os.path.basename(__file__)} --collect-artifacts ./evidence\n"
               f"  sudo python3 {os.path.basename(__file__)} --create-raw ./disk_images\n"
               f"  python3 {os.path.basename(__file__)} --list-disks\n"
    )
    
    # Add arguments
    parser.add_argument("--list-disks", action="store_true", help="List available disks")
    parser.add_argument("--detect-external", action="store_true", help="Detect external storage devices")
    parser.add_argument("--unmount", type=str, help="Unmount a specified disk (e.g., /dev/disk2)")
    parser.add_argument("--create-raw", type=str, metavar="OUTPUT_PATH", help="Create a raw disk image and store it in the given path")
    parser.add_argument("--skip-hash", action="store_true", help="Skip hash calculation when creating disk images (faster)")
    parser.add_argument("--collect-artifacts", type=str, metavar="OUTPUT_PATH", help="Collect forensic artifacts and store them in the given path")
    parser.add_argument("--categories", type=str, nargs="+", help="Specific artifact categories to collect (default: all)")
    parser.add_argument("--generate-report", type=str, metavar="OUTPUT_PATH", help="Generate a forensic report")
    parser.add_argument("--artifacts-path", type=str, help="Path to artifacts for report generation")
    parser.add_argument("--quiet", action="store_true", help="Minimize output (quiet mode)")
    parser.add_argument("--version", action="version", version="macOS Forensic Acquisition Tool v1.1")
    
    args = parser.parse_args()
    
    # Set logging level based on quiet flag
    if args.quiet:
        logger.setLevel(logging.WARNING)
    
    # Check root privileges for certain operations
    if args.create_raw or args.collect_artifacts:
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
    
    elif args.collect_artifacts:
        artifacts_path = collect_artifacts(args.collect_artifacts, args.categories)
        
        # Offer to generate a report
        if artifacts_path:
            generate_report_option = input("Would you like to generate a report of collected artifacts? (y/n): ").lower()
            if generate_report_option == 'y':
                generate_report(args.collect_artifacts, artifacts_path)
    
    elif args.generate_report:
        generate_report(args.generate_report, args.artifacts_path)
    
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
