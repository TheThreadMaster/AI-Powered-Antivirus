import os
import hashlib
import json
import datetime
import psutil
import pefile

LOG_FILE = "antivirus_log.txt"
DETAILED_LOG_FILE = "antivirus_detailed_log.txt"

# Dictionary for known virus signature hashes
VIRUS_SIGNATURES = {}

def load_signatures(signature_file="virus_signatures.json"):
    """Loads virus signatures from a JSON file."""
    global VIRUS_SIGNATURES
    try:
        with open(signature_file, 'r') as f:
            VIRUS_SIGNATURES = json.load(f)
        log_event(f"Loaded {len(VIRUS_SIGNATURES)} signatures from {signature_file}", level="INFO")
    except FileNotFoundError:
        log_event(f"Signature file {signature_file} not found. No signatures loaded.", level="WARNING")
        VIRUS_SIGNATURES = {}
    except json.JSONDecodeError:
        log_event(f"Error decoding signature file {signature_file}. No signatures loaded.", level="ERROR")
        VIRUS_SIGNATURES = {}

def log_event(message, level="INFO", detailed=False):
    """Logs an event to the appropriate log file."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{level}] {message}"
    
    with open(LOG_FILE, 'a') as f:
        f.write(log_entry + "\n")
    
    if detailed:
        with open(DETAILED_LOG_FILE, 'a') as f:
            f.write(log_entry + "\n")

def calculate_file_hash(file_path, hash_algo='sha256'):
    """Calculates the hash of a file."""
    hasher = hashlib.new(hash_algo)
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        log_event(f"File not found: {file_path}", level="ERROR", detailed=True)
        return None
    except Exception as e:
        log_event(f"Error hashing file {file_path}: {e}", level="ERROR", detailed=True)
        return None

def scan_file(file_path):
    """Scans a single file for viruses based on signatures."""
    # GUI Update: Indicate which file is being scanned
    print(f"STATUS:Scanning file: {os.path.basename(file_path)}") 
    log_event(f"Scanning file: {file_path}", level="INFO", detailed=True)
    file_hash = calculate_file_hash(file_path)
    if file_hash and file_hash in VIRUS_SIGNATURES.values():
        virus_name = [name for name, sig in VIRUS_SIGNATURES.items() if sig == file_hash][0]
        log_event(f"Virus detected! File: {file_path}, Virus: {virus_name}", level="CRITICAL")
        return True, virus_name
    
    # Placeholder for PE file analysis (heuristic)
    try:
        pe = pefile.PE(file_path, fast_load=True)
        # Example: Check for suspicious import functions
        suspicious_imports = ["LoadLibraryA", "GetProcAddress", "CreateRemoteThread", "WriteProcessMemory"]
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode() in suspicious_imports:
                        log_event(f"Suspicious import found in {file_path}: {imp.name.decode()}", level="WARNING", detailed=True)
                        # This is a basic heuristic, could be expanded
                        # return True, "Suspicious PE Structure (Import)"
    except pefile.PEFormatError:
        log_event(f"Not a valid PE file or corrupted: {file_path}", level="DEBUG", detailed=True)
    except Exception as e:
        log_event(f"Error analyzing PE file {file_path}: {e}", level="ERROR", detailed=True)

    log_event(f"File clean: {file_path}", level="INFO", detailed=True)
    return False, None

def scan_directory(dir_path):
    """Scans all files in a directory (recursively)."""
    log_event(f"Scanning directory: {dir_path}", level="INFO")
    print(f"STATUS:Preparing to scan directory: {dir_path}")

    file_list = []
    for root, _, files in os.walk(dir_path):
        for file in files:
            file_list.append(os.path.join(root, file))
    
    total_files = len(file_list)
    print(f"PROGRESS_TOTAL_FILES:{total_files}")
    log_event(f"Total files to scan in {dir_path}: {total_files}", level="INFO")

    detections = 0
    scanned_files_count = 0

    for file_path in file_list:
        scanned_files_count += 1
        # GUI Update: Current file number and path
        print(f"PROGRESS_CURRENT_FILE:{scanned_files_count}:{file_path}") 
        try:
            is_infected, virus_name = scan_file(file_path)
            if is_infected:
                detections += 1
                # GUI Update: Threat detected
                print(f"THREAT:{file_path}:{virus_name}") 
        except Exception as e:
            log_event(f"Error scanning file {file_path}: {e}", level="ERROR", detailed=True)
            print(f"ERROR:Error scanning {os.path.basename(file_path)}: {e}")
    
    log_event(f"Directory scan complete for {dir_path}. Detections: {detections}", level="INFO")
    print(f"STATUS:Scan complete. Total files scanned: {scanned_files_count}. Detections: {detections}")
    return detections

if __name__ == "__main__":
    print("STATUS:Antivirus Engine Initializing...")
    load_signatures() # Load default signatures
    if VIRUS_SIGNATURES:
        print(f"STATUS:Signatures loaded: {len(VIRUS_SIGNATURES)}")
    else:
        print("STATUS:No signatures loaded. Check virus_signatures.json.")

    # Example Usage (scan a specific directory)
    target_directory = "." # Scan current directory
    import sys
    if len(sys.argv) > 1:
        target_directory = sys.argv[1]
        if not os.path.isdir(target_directory):
            print(f"ERROR: {target_directory} is not a valid directory.")
            log_event(f"Invalid directory provided: {target_directory}", level="ERROR")
            sys.exit(1)
    
    abs_target_dir = os.path.abspath(target_directory)
    print(f"STATUS:Starting scan in directory: {abs_target_dir}")
    scan_directory(abs_target_dir)
    print("STATUS:Scan finished. Check logs for details.")
