import os
import threading
import shutil
import customtkinter as ctk
from tkinter import filedialog, messagebox
from scan.scanner import Scanner


class Home(ctk.CTkFrame):
    def __init__(self, parent, quarantine_dir="quarantine", signatures_dir="virus_signature"):
        super().__init__(parent)
        self.parent = parent
        self.scanner = Scanner(signatures_dir)
        self.quarantine_dir = quarantine_dir
        os.makedirs(self.quarantine_dir, exist_ok=True)

        # scanning state
        self.is_scanning = False
        self.stop_requested = False

        # UI Elements
        self._build_ui()

    def _build_ui(self):
        # Title and description
        self.title_label = ctk.CTkLabel(self, text="Welcome to Ahavah AI Antivirus!", 
                                        font=ctk.CTkFont(size=20, weight="bold"))
        self.title_label.pack(pady=(20, 10))

        self.desc_label = ctk.CTkLabel(self, text="Ahavah AI is your trusted antivirus solution.")
        self.desc_label.pack(pady=(0, 20))

        # Buttons Frame
        btn_frame = ctk.CTkFrame(self)
        btn_frame.pack(pady=10)

        self.full_scan_btn = ctk.CTkButton(btn_frame, text="Full System Scan", 
                                           width=150, command=self.on_full_scan)
        self.full_scan_btn.grid(row=0, column=0, padx=10)

        self.folder_scan_btn = ctk.CTkButton(btn_frame, text="Select Folder to Scan", 
                                             width=150, command=self.on_folder_scan)
        self.folder_scan_btn.grid(row=0, column=1, padx=10)

        self.stop_btn = ctk.CTkButton(btn_frame, text="Stop Scan", 
                                      width=100, fg_color="#FF5555", command=self.request_stop)
        self.stop_btn.grid(row=0, column=2, padx=10)
        self.stop_btn.configure(state="disabled")

        # Progress bar
        self.progress = ctk.CTkProgressBar(self, width=600)
        self.progress.set(0)
        self.progress.pack(pady=(20, 10))

        # Log box
        self.logbox = ctk.CTkTextbox(self, width=700, height=300)
        self.logbox.pack(pady=(0, 20))

    def log(self, message):
        self.logbox.insert(ctk.END, message + "\n")
        self.logbox.see(ctk.END)

    def request_stop(self):
        if self.is_scanning:
            self.stop_requested = True
            self.log("Stop requested. Finishing current file then stopping...")

    def on_full_scan(self):
        start_path = "/" if os.name != 'nt' else "C:\\"
        self._start_scan(start_path)

    def on_folder_scan(self):
        path = filedialog.askdirectory()
        if path:
            self._start_scan(path)

    def _start_scan(self, path):
        if self.is_scanning:
            messagebox.showinfo("Scan in Progress", "A scan is already running.")
            return

        # prepare
        self.is_scanning = True
        self.stop_requested = False
        self.full_scan_btn.configure(state="disabled")
        self.folder_scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.logbox.delete("0.0", ctk.END)
        self.progress.set(0)

        # run in background
        threading.Thread(target=self._scan_path, args=(path,), daemon=True).start()

    def _scan_path(self, path):
        # count total files
        total_files = 0
        for root, _, files in os.walk(path):
            total_files += len(files)
        scanned = 0

        self.log(f"Starting scan on: {path} ({total_files} files)")

        for root, _, files in os.walk(path):
            if self.stop_requested:
                break
            for fname in files:
                if self.stop_requested:
                    break
                file_path = os.path.join(root, fname)
                try:
                    infected = self.scanner.scan_file(file_path)
                    if infected:
                        self.log(f"[INFECTED] {file_path}")
                        self._quarantine(file_path)
                except PermissionError:
                    self.log(f"[ACCESS DENIED] {file_path}")
                except Exception as e:
                    self.log(f"[ERROR] {file_path}: {e}")
                finally:
                    scanned += 1
                    if total_files > 0:
                        self.progress.set(scanned / total_files)

        self.log("🔍 Scan complete!" if not self.stop_requested else "🔍 Scan stopped by user.")
        # reset buttons
        self.full_scan_btn.configure(state="normal")
        self.folder_scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.is_scanning = False

    def _quarantine(self, file_path):
        try:
            dest = os.path.join(self.quarantine_dir, os.path.basename(file_path))
            shutil.move(file_path, dest)
            self.log(f"[QUARANTINED] {file_path} -> {dest}")
        except Exception as e:
            self.log(f"[QUARANTINE FAILED] {file_path}: {e}")


