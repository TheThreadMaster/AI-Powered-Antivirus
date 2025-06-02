# Simple Antivirus Project

This project is a basic antivirus scanner built with Python. It includes a command-line scanner and a simple Tkinter-based GUI.

## Project Structure

- `antivirus.py`: The core scanning engine. Handles signature loading, file hashing, PE file analysis (basic heuristics), and logging.
- `antivirus_gui.py`: A simple Tkinter GUI to select a directory and initiate a scan. Displays output from the scanner.
- `requirements.txt`: Lists Python package dependencies (`psutil`, `pefile`).
- `virus_signatures.json`: Stores virus signatures (currently based on SHA256 hashes).
- `suspicious_pseudo_pe.exe`: An empty file whose hash is included in `virus_signatures.json` for testing detection.
- `antivirus_log.txt`: General log file for scan events.
- `antivirus_detailed_log.txt`: More detailed log file, especially for debugging or verbose output.
- `antivirus_output.txt`: Captures the standard output of `antivirus.py` when run via the GUI, primarily for displaying detections in the GUI.
- `README.md`: This file.

## Setup

1.  **Ensure Python is installed.** (Python 3.7+ recommended).
2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```
3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## How to Run

### 1. Command-Line Scanner (`antivirus.py`)

You can run the command-line scanner directly. It will scan the current directory by default, or you can provide a specific directory path as an argument.

```bash
python antivirus.py [path_to_directory_to_scan]
```

**Examples:**

-   Scan the current directory:
    ```bash
    python antivirus.py
    ```
-   Scan a specific directory (e.g., `C:\Users\YourUser\Documents`):
    ```bash
    python antivirus.py "C:\Users\YourUser\Documents"
    ```

Detections will be printed to the console, and logs will be written to `antivirus_log.txt` and `antivirus_detailed_log.txt`.

### 2. GUI Scanner (`antivirus_gui.py`)

To use the graphical interface:

```bash
python antivirus_gui.py
```

This will open a window where you can:
-   Browse and select a directory to scan.
-   Click "Start Scan" to begin.
-   View scan progress and detections in the output area.

Logs are also generated as with the command-line scanner.

## Adding Virus Signatures

To add new virus signatures:

1.  Calculate the SHA256 hash of the malicious file.
2.  Open `virus_signatures.json`.
3.  Add a new entry with a descriptive virus name as the key and its SHA256 hash as the value. For example:
    ```json
    {
        "TestVirus.Generic": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "SuspiciousPE.EmptyFile": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "NewVirus.Trojan": "your_new_file_hash_here"
    }
    ```

## Notes

-   This is a simplified antivirus for educational purposes. It primarily relies on hash-based signature detection and very basic PE file heuristics.
-   Real-world antivirus software uses far more sophisticated detection techniques (e.g., advanced heuristics, behavioral analysis, machine learning, cloud-based lookups).
-   The PE file analysis is rudimentary and can be expanded significantly.
-   Error handling can be further improved.