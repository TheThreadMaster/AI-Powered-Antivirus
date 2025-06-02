
# 🛡️ AI-Powered Antivirus

An open-source antivirus solution that leverages artificial intelligence to detect and neutralize malware threats.
This project combines traditional signature-based detection with machine learning techniques to enhance threat identification capabilities.

---

## 🚀 Features

- **AI-Driven Detection**: Utilizes machine learning algorithms to identify malicious patterns in executable files.
- **Signature-Based Scanning**: Employs a database of known virus signatures for quick identification.
- **User-Friendly GUI**: Interactive interface for scanning files and viewing results.
- **Detailed Logging**: Maintains comprehensive logs for each scan, aiding in analysis and debugging.

---

## 🗂️ Project Structure

```
AI-Powered-Antivirus/
├── antivirus.py                # Core scanning engine
├── antivirus_gui.py            # Graphical User Interface
├── virus_signatures.json       # Database of known virus signatures
├── suspicious_pseudo_pe.exe    # Sample executable for testing
├── requirements.txt            # Python dependencies
├── antivirus_log.txt           # General scan logs
├── antivirus_detailed_log.txt  # Detailed scan logs
├── antivirus_output.txt        # Output from recent scans
└── README.md                   # Project documentation
```

---

## 🛠️ Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/TheThreadMaster/AI-Powered-Antivirus.git
   cd AI-Powered-Antivirus
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🖥️ Usage

- **Run the Antivirus Scanner**:
  ```bash
  python antivirus.py
  ```

- **Launch the GUI**:
  ```bash
  python antivirus_gui.py
  ```

- **Scan a Specific File**:
  ```bash
  python antivirus.py path/to/your/file.exe
  ```

---

## 📄 Sample Output

Upon scanning, the tool will provide output indicating whether the file is clean or infected. Detailed logs are saved in `antivirus_log.txt` and `antivirus_detailed_log.txt`.

---

## 🤝 Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any enhancements or bug fixes.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 📬 Contact

For any questions or suggestions, please open an issue on the repository.

---

*Note: This project is for educational purposes and should not be used as a primary antivirus solution.*
