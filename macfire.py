import os
import subprocess
import shutil
import argparse
import datetime

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
   /                            \
  /  [][][][][][][][][][][][][]  \
 /  [][][][][][][][][][][][][][]  \
(  [][][][][____________][][][][]  )
 \ ------------------------------ /
  \______________________________/
                      _____ ___ ____  _____ 
 _ __ ___   __ _  ___|  ___|_ _|  _ \| ____|
| '_ ` _ \ / _` |/ __| |_   | || |_) |  _|  
| | | | | | (_| | (__|  _|  | ||  _ <| |___ 
|_| |_| |_|\__,_|\___|_|   |___|_| \_\_____| 
 macOS Forensic Acquisition Tool
 by Sudo3rs
=================================
"""

# Supported macOS Versions
SUPPORTED_MACOS = "macOS Catalina (10.15) and later"

# Forensic tool configuration
ARTIFACTS = {
    "System Logs": "/var/log/system.log",
    "User Preferences": "~/Library/Preferences",
    "Application Support": "~/Library/Application Support",
    "User Logs": "~/Library/Logs",
    "TCC Database": "/Library/Application Support/com.apple.TCC/TCC.db",
    "Unified Logs": "log collect --output ./forensics_logs.logarchive",
    "Keychain Data": "~/Library/Keychains/",
    "iMessage Logs": "~/Library/Messages/chat.db",
    "Safari History": "~/Library/Safari/History.db",
    "Chrome History": "~/Library/Application Support/Google/Chrome/Default/History",
    "Spotlight Index": "/private/var/db/Spotlight-V100/",
    "Quarantine Database": "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
    "Network Connections": "netstat -an > ./network_connections.txt",
    "Running Processes": "ps aux > ./running_processes.txt",
    "Startup Items": "ls /Library/LaunchAgents/ > ./startup_items.txt",
    "Kernel Extensions": "kmutil showloaded > ./kernel_extensions.txt",
    "Security Logs": "cp /var/log/secure.log ./security_logs.txt"
}


def run_command(command):
    """Executes a shell command and returns the output"""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        print(f"[ERROR] Command failed: {command}")
        print(e)
        return None


def list_disks():
    """Lists available disks on macOS"""
    print("[+] Listing available disks:")
    output = run_command("diskutil list")
    print(output)


def detect_external_drive():
    """Detects external storage devices"""
    print("[+] Detecting external storage devices...")
    output = run_command("diskutil list external")
    if output:
        print(output)
    else:
        print("[-] No external drives detected.")


def unmount_disk(disk):
    """Unmounts a specified disk"""
    print(f"[+] Unmounting disk: {disk}")
    run_command(f"diskutil unmountDisk {disk}")


def create_raw_image(disk, output_path):
    """Creates a RAW disk image using dd"""
    try:
        os.makedirs(output_path, exist_ok=True)
        output_file = os.path.join(output_path, "disk_image.dd")
        print(f"[+] Creating raw disk image from {disk} to {output_file}")
        run_command(f"dd if={disk} of={output_file} bs=4M")
        print("[+] Image created successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to create raw image: {e}")


def collect_artifacts(output_path):
    """Collects forensic artifacts from macOS"""
    try:
        os.makedirs(output_path, exist_ok=True)
        print("[+] Collecting forensic artifacts...")
        
        for name, path in ARTIFACTS.items():
            dest_path = os.path.join(output_path, name.replace(" ", "_") + "_artifact")
            if os.path.exists(os.path.expanduser(path)):
                if os.path.isdir(os.path.expanduser(path)):
                    shutil.copytree(os.path.expanduser(path), dest_path)
                else:
                    shutil.copy(os.path.expanduser(path), dest_path)
                print(f"[+] Collected: {name}")
            else:
                run_command(path)  # Run commands like 'netstat', 'ps', 'kmutil'
                print(f"[+] Executed command: {path}")
        print("[+] Artifact collection complete.")
    except Exception as e:
        print(f"[ERROR] Failed to collect artifacts: {e}")


def generate_report(output_path):
    """Generates a forensic report summarizing collected data."""
    try:
        report_path = os.path.join(output_path, "forensic_report.txt")
        with open(report_path, "w") as report:
            report.write("macOS Forensic Report\n")
            report.write(f"Generated on: {datetime.datetime.now()}\n\n")
            for name, path in ARTIFACTS.items():
                report.write(f"Artifact: {name}\nPath/Command: {path}\n\n")
        print(f"[+] Forensic report saved at: {report_path}")
    except Exception as e:
        print(f"[ERROR] Failed to generate forensic report: {e}")


def main():
    print(BANNER)
    print(f"Supported macOS Versions: {SUPPORTED_MACOS}\n")
    
    parser = argparse.ArgumentParser(description="macOS Forensic Acquisition Tool")
    parser.add_argument("--list-disks", action="store_true", help="List available disks")
    parser.add_argument("--detect-external", action="store_true", help="Detect external storage devices")
    parser.add_argument("--unmount", type=str, help="Unmount a specified disk (e.g., /dev/disk2)")
    parser.add_argument("--create-raw", type=str, metavar="OUTPUT_PATH", help="Create a raw disk image and store it in the given path")
    parser.add_argument("--collect-artifacts", type=str, metavar="OUTPUT_PATH", help="Collect forensic artifacts and store them in the given path")
    parser.add_argument("--generate-report", type=str, metavar="OUTPUT_PATH", help="Generate a forensic report")
    args = parser.parse_args()
    
    if args.list_disks:
        list_disks()
    elif args.detect_external:
        detect_external_drive()
    elif args.unmount:
        unmount_disk(args.unmount)
    elif args.create_raw:
        disk = input("Enter the disk path (e.g., /dev/disk2): ")
        create_raw_image(disk, args.create_raw)
    elif args.collect_artifacts:
        collect_artifacts(args.collect_artifacts)
    elif args.generate_report:
        generate_report(args.generate_report)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
