import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import threading
import subprocess
import os

# Assuming antivirus.py is in the same directory
ANTIVIRUS_SCRIPT = os.path.join(os.path.dirname(__file__), "antivirus.py")
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "antivirus_output.txt")
LOG_FILE = os.path.join(os.path.dirname(__file__), "antivirus_log.txt")

class AntivirusGUI:
    def __init__(self, master):
        self.master = master
        master.title("Antivirus Scanner Pro") # Changed title
        master.geometry("750x650") # Slightly larger window

        self.scan_process = None
        self.scan_thread = None
        self.threats_found_count = 0 # Initialize threat counter

        # --- Top Frame for Path Selection ---
        top_frame = tk.Frame(master)
        top_frame.pack(pady=10, fill=tk.X, padx=10)

        self.label = tk.Label(top_frame, text="Select a directory to scan:")
        self.label.pack(side=tk.LEFT, padx=(0, 5))

        self.path_entry = tk.Entry(top_frame, width=60)
        self.path_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

        self.browse_button = tk.Button(top_frame, text="Browse", command=self.browse_directory)
        self.browse_button.pack(side=tk.LEFT, padx=(5,0))

        # --- Controls Frame ---
        controls_frame = tk.Frame(master)
        controls_frame.pack(pady=5, padx=10, fill=tk.X)

        self.scan_button = tk.Button(controls_frame, text="Start Scan", command=self.start_scan_thread, width=15)
        self.scan_button.pack(side=tk.LEFT, padx=(0,10))

        self.cancel_button = tk.Button(controls_frame, text="Cancel Scan", command=self.cancel_scan, state=tk.DISABLED, width=15)
        self.cancel_button.pack(side=tk.LEFT)
        
        # --- Options Placeholder ---
        options_frame = tk.LabelFrame(master, text="Scan Options", padx=10, pady=10)
        options_frame.pack(pady=10, padx=10, fill=tk.X)
        tk.Checkbutton(options_frame, text="Scan Archives (.zip, .rar)").pack(anchor=tk.W)
        tk.Checkbutton(options_frame, text="Heuristic Analysis (Experimental)").pack(anchor=tk.W)
        tk.Label(options_frame, text="(Options are currently for display only)").pack(anchor=tk.W, pady=(5,0))

        # --- Progress Bar ---
        self.progress_label = tk.Label(master, text="Current file: N/A")
        self.progress_label.pack(pady=(5,0), padx=10, anchor=tk.W)
        self.progress_bar = ttk.Progressbar(master, orient="horizontal", length=100, mode="determinate")
        self.progress_bar.pack(pady=(0,5), padx=10, fill=tk.X)

        # --- Results Area ---
        self.results_area_label = tk.Label(master, text="Scan Output & Detections:")
        self.results_area_label.pack(pady=(10,2), padx=10, anchor=tk.W) # Adjusted padding
        self.results_area = scrolledtext.ScrolledText(master, width=80, height=15) # Increased height
        self.results_area.pack(pady=(0,5), padx=10, fill=tk.BOTH, expand=True)
        self.results_area.configure(state='disabled')

        # --- Status Bar ---
        self.status_label = tk.Label(master, text="Status: Idle", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

        if os.path.exists(OUTPUT_FILE):
            try:
                os.remove(OUTPUT_FILE)
            except OSError as e:
                print(f"Error removing old output file: {e}")

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, directory)

    def update_results_area(self, message):
        self.results_area.configure(state='normal')
        self.results_area.insert(tk.END, message + "\n")
        self.results_area.configure(state='disabled')
        self.results_area.see(tk.END) # Scroll to the bottom

    def monitor_scan_output(self):
        if not self.scan_process:
            return

        self.results_area.configure(state='normal')
        self.results_area.delete('1.0', tk.END)
        self.results_area.configure(state='disabled')
        self.progress_bar['value'] = 0
        self.progress_label.config(text="Current file: N/A")

        with open(OUTPUT_FILE, 'w') as f_out:
            f_out.write("Scan initiated...\n")

        self.update_results_area("Scan process starting...")
        self.threats_found_count = 0 # Reset threat count for new scan

        for line_bytes in iter(self.scan_process.stdout.readline, b''):
            if not self.scan_process: # Check if scan was cancelled
                break
            line = line_bytes.decode('utf-8', errors='replace').strip()
            if line:
                # Write to output file, but exclude the final status message later
                if not line.startswith("Scan finished. Exit code:"):
                    with open(OUTPUT_FILE, 'a') as f_out:
                        f_out.write(line + "\n")
                
                if line.startswith("STATUS:"):
                    status_msg = line.replace("STATUS:", "", 1)
                    self.status_label.config(text=f"Status: {status_msg}")
                    self.update_results_area(status_msg)
                elif line.startswith("PROGRESS_TOTAL_FILES:"):
                    try:
                        total_files = int(line.split(':')[1])
                        self.progress_bar['maximum'] = total_files
                        self.update_results_area(f"Total files to scan: {total_files}")
                    except (IndexError, ValueError):
                        self.update_results_area(f"Malformed progress data: {line}")
                elif line.startswith("PROGRESS_CURRENT_FILE:"):
                    try:
                        parts = line.split(':', 2)
                        current_file_num = int(parts[1])
                        current_file_path = parts[2]
                        self.progress_bar['value'] = current_file_num
                        self.progress_label.config(text=f"Scanning: {os.path.basename(current_file_path)} ({current_file_num}/{self.progress_bar['maximum']})")
                    except (IndexError, ValueError):
                         self.update_results_area(f"Malformed progress data: {line}")
                elif line.startswith("THREAT:"):
                    self.threats_found_count += 1
                    threat_info = line.replace("THREAT:", "", 1).split(':', 1)
                    file_path = threat_info[0]
                    virus_name = threat_info[1] if len(threat_info) > 1 else "Unknown Virus"
                    self.update_results_area(f"!!! THREAT DETECTED !!! File: {file_path} - Virus: {virus_name}")
                    self.results_area.tag_add("threat", tk.END + "-2l", tk.END + "-1l") # Highlight previous line
                    self.results_area.tag_config("threat", background="yellow", foreground="red", font=("TkDefaultFont", 9, "bold"))
                elif line.startswith("ERROR:"):
                    error_msg = line.replace("ERROR:", "", 1)
                    self.update_results_area(f"ERROR: {error_msg}")
                else:
                    self.update_results_area(line) # General output from script
        
        if self.scan_process: # if not cancelled
            self.scan_process.stdout.close()
            return_code = self.scan_process.wait()
            # final_status_msg is now handled by the new status logic
            # self.update_results_area(final_status_msg) # Don't show this raw message
            # with open(OUTPUT_FILE, 'a') as f_out: # Don't write this to output file
            #     f_out.write(final_status_msg + "\n")

            if self.threats_found_count > 0:
                final_gui_status = f"Status: Threats found! ({self.threats_found_count} detected). Check logs."
                messagebox.showwarning("Scan Complete", f"Scan finished. {self.threats_found_count} threat(s) detected. Check output and '{LOG_FILE}' for details.")
            else:
                final_gui_status = "Status: No threats found."
                messagebox.showinfo("Scan Complete", f"Scan finished. No threats detected. Check '{LOG_FILE}' for details.")
            self.status_label.config(text=final_gui_status)
            self.update_results_area(f"Scan finished. {('Threats found: ' + str(self.threats_found_count)) if self.threats_found_count > 0 else 'No threats found.'}")

        else: # Scan was cancelled
            self.status_label.config(text="Status: Scan Cancelled by user.")
            self.update_results_area("Scan was cancelled by the user.")

        self.scan_button.config(state=tk.NORMAL)
        self.cancel_button.config(state=tk.DISABLED)
        self.browse_button.config(state=tk.NORMAL)
        self.path_entry.config(state=tk.NORMAL)
        self.progress_bar['value'] = 0
        self.progress_label.config(text="Current file: N/A")
        self.scan_process = None # Reset scan process

    def start_scan_thread(self):
        scan_path = self.path_entry.get()
        if not scan_path or not os.path.isdir(scan_path):
            messagebox.showerror("Error", "Please select a valid directory to scan.")
            return

        self.status_label.config(text="Status: Initializing scan...")
        self.scan_button.config(state=tk.DISABLED)
        self.cancel_button.config(state=tk.NORMAL)
        self.browse_button.config(state=tk.DISABLED)
        self.path_entry.config(state=tk.DISABLED)
        self.progress_bar['value'] = 0
        self.progress_label.config(text="Current file: N/A")
        self.threats_found_count = 0 # Reset before scan
        
        try:
            python_executable = "python" # Or sys.executable for better path finding
            self.scan_process = subprocess.Popen(
                [python_executable, ANTIVIRUS_SCRIPT, scan_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, # Combine stdout and stderr for simplicity here
                text=False, 
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            self.scan_thread = threading.Thread(target=self.monitor_scan_output)
            self.scan_thread.daemon = True
            self.scan_thread.start()

        except Exception as e:
            messagebox.showerror("Execution Error", f"Failed to start scan: {e}")
            self.status_label.config(text="Status: Error starting scan")
            self.scan_button.config(state=tk.NORMAL)
            self.cancel_button.config(state=tk.DISABLED)
            self.browse_button.config(state=tk.NORMAL)
            self.path_entry.config(state=tk.NORMAL)
            self.scan_process = None

    def cancel_scan(self):
        if self.scan_process and self.scan_process.poll() is None: # Check if process is running
            try:
                # Attempt to terminate the process group (more effective for subprocesses)
                # On Windows, Popen.terminate() should be enough for a simple script
                # For more complex scenarios with child processes, psutil might be needed
                self.scan_process.terminate() # Sends SIGTERM
                # Optionally, wait a bit and then self.scan_process.kill() if still alive
                self.update_results_area("Scan cancellation requested...")
                self.status_label.config(text="Status: Cancelling scan...")
            except Exception as e:
                self.update_results_area(f"Error trying to cancel scan: {e}")
                messagebox.showerror("Cancel Error", f"Could not terminate scan process: {e}")
        else:
            self.update_results_area("No active scan to cancel.")
        
        # GUI updates are handled at the end of monitor_scan_output when thread finishes
        # or immediately if process was already done.
        if not (self.scan_thread and self.scan_thread.is_alive()):
            self.scan_button.config(state=tk.NORMAL)
            self.cancel_button.config(state=tk.DISABLED)
            self.browse_button.config(state=tk.NORMAL)
            self.path_entry.config(state=tk.NORMAL)
            self.status_label.config(text="Status: Idle/Cancelled")
            self.scan_process = None # Ensure it's reset

if __name__ == "__main__":
    root = tk.Tk()
    gui = AntivirusGUI(root)
    root.mainloop()