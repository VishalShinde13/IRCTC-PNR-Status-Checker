import subprocess
import sys

REQUIRED_PACKAGES = ['cryptography', 'requests']
for package in REQUIRED_PACKAGES:
    try:
        __import__(package)
    except ImportError:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
from requests import post
from requests.exceptions import RequestException
from json import loads

import tkinter as tk
from tkinter import ttk, messagebox

# --- Modern Color Palette ---
PRIMARY_BG = "#22223b"
ACCENT_BG = "#4a4e69"
HIGHLIGHT_BG = "#9a8c98"
ENTRY_BG = "#f2e9e4"
BUTTON_BG = "#38b000"
BUTTON_FG = "#fff"
TEXT_BG = "#232634"
TEXT_FG = "#f2e9e4"
TITLE_FG = "#f2e9e4"
LABEL_FG = "#c9ada7"
PASSENGER_BG = "#383e56"
PREDICTION_GOOD = "#38b000"
PREDICTION_MED = "#f9c74f"
PREDICTION_BAD = "#f94144"

def encrypt_pnr(pnr):
    data = bytes(pnr, 'utf-8')
    backend = default_backend()
    padder = padding.PKCS7(128).padder()
    data = padder.update(data) + padder.finalize()
    key = b'8080808080808080'
    iv = b'8080808080808080'
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    enc_pnr = b64encode(ct)
    return enc_pnr.decode('utf-8')

def get_pnr_status(pnr):
    encrypted_pnr = encrypt_pnr(pnr)
    json_data = {'pnrNumber': encrypted_pnr}
    try:
        response = post(
            'https://railways.easemytrip.com/Train/PnrchkStatus',
            json=json_data, timeout=10, verify=True
        )
        response.raise_for_status()
        api_json = loads(response.content)
        return api_json
    except RequestException as e:
        return f"Network/API Error: {e}"
    except ValueError as e:
        return f"Invalid server response: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"

class PNRCheckerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🚄 Indian Railways PNR Status Checker")
        self.geometry("700x620")
        self.configure(bg=PRIMARY_BG)
        self.resizable(False, False)

        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('TButton', font=('Segoe UI', 13), background=BUTTON_BG, foreground=BUTTON_FG, padding=6)
        style.map('TButton',
            background=[('active', '#70e000')],
            foreground=[('active', BUTTON_FG)]
        )

        self.title_label = tk.Label(self,
            text="🧾 Indian Railways PNR Status Checker",
            font=("Segoe UI", 22, "bold"),
            bg=ACCENT_BG, fg=TITLE_FG, pady=16
        )
        self.title_label.pack(fill="x", pady=(0, 10))

        input_frame = tk.Frame(self, bg=PRIMARY_BG)
        input_frame.pack(fill="x", padx=30, pady=(0, 10))

        self.pnr_label = tk.Label(input_frame, text="Enter 10-digit PNR Number:", font=("Segoe UI", 14), bg=PRIMARY_BG, fg=LABEL_FG)
        self.pnr_label.grid(row=0, column=0, sticky="w")

        self.pnr_entry = tk.Entry(input_frame, font=("Segoe UI", 16), width=18, bg=ENTRY_BG, fg="#222", borderwidth=0, relief="flat", highlightthickness=1, highlightbackground=HIGHLIGHT_BG)
        self.pnr_entry.grid(row=1, column=0, padx=2, pady=8, sticky="w")
        self.pnr_entry.focus()

        self.submit_button = ttk.Button(input_frame, text="Check PNR Status", command=self.check_pnr)
        self.submit_button.grid(row=1, column=1, padx=16, pady=8, sticky="e")

        self.help_button = ttk.Button(input_frame, text="Help", command=self.show_help)
        self.help_button.grid(row=1, column=2, padx=8, pady=8, sticky="e")

        # Results area
        self.result_frame = tk.Frame(self, bg=PRIMARY_BG)
        self.result_frame.pack(padx=20, pady=(0, 10), fill="both", expand=True)

        self.footer_label = tk.Label(self,
            text="Made with ❤️ for Indian Railway travelers | VishalShinde13",
            font=("Segoe UI", 11, "italic"),
            bg=PRIMARY_BG, fg="#999"
        )
        self.footer_label.pack(side="bottom", fill="x", pady=8)

        credit = tk.Label(self, text="Modern UI by Python", font=("Segoe UI", 8, "italic"), bg=PRIMARY_BG, fg="#444")
        credit.pack(side="bottom", pady=(0,3))

    def show_help(self):
        messagebox.showinfo(
            "Help - How to Use",
            "1. Enter your 10-digit PNR number in the input box.\n"
            "2. Click 'Check PNR Status' to see your train and passenger status.\n"
            "3. You will see:\n"
            "   - Route, Train, Quota, Class, Date\n"
            "   - Each passenger's current status, coach, and seat/berth if allotted."
        )

    def clear_results(self):
        for widget in self.result_frame.winfo_children():
            widget.destroy()

    def check_pnr(self):
        pnr = self.pnr_entry.get().strip()
        self.clear_results()

        if not pnr.isdigit() or len(pnr) != 10:
            tk.Label(self.result_frame, text="❌ Please enter a valid 10-digit numeric PNR number.",
                     font=("Segoe UI", 13, "bold"),
                     fg=PREDICTION_BAD, bg=PRIMARY_BG).pack(anchor="w", padx=12, pady=12)
            return

        tk.Label(self.result_frame, text="Checking PNR status, please wait...",
                 font=("Segoe UI", 12, "italic"),
                 fg=LABEL_FG, bg=PRIMARY_BG).pack(anchor="w", padx=12, pady=6)
        self.update()
        response = get_pnr_status(pnr)

        self.clear_results()
        if not isinstance(response, dict):
            tk.Label(self.result_frame, text=response,
                     font=("Segoe UI", 13, "bold"),
                     fg=PREDICTION_BAD, bg=PRIMARY_BG).pack(anchor="w", padx=12, pady=12)
            return

        try:
            # Journey details header
            boarding_station = response.get("BrdPointName", "")
            destination_station = response.get("DestStnName", "")
            quota = response.get("quota", "")
            class_name = response.get("className", "")
            train_number = response.get("trainNumber", "")
            train_name = response.get("trainName", "")
            date_of_journey = response.get("dateOfJourney", "")
            chart_prepared = response.get("chartPrepared", "Unknown")

            tk.Label(self.result_frame, text="PNR STATUS", font=("Segoe UI", 16, "bold"),
                     fg=TITLE_FG, bg=PRIMARY_BG).pack(anchor="w", padx=6, pady=(0, 3))
            tk.Label(self.result_frame, text="------------------------------------------------------------------",
                     font=("Consolas", 12), fg=HIGHLIGHT_BG, bg=PRIMARY_BG).pack(anchor="w", padx=6)

            tk.Label(self.result_frame, text=f"{boarding_station} ➔ {destination_station}",
                     font=("Segoe UI", 13, "bold"), fg=LABEL_FG, bg=PRIMARY_BG).pack(anchor="w", padx=6, pady=(4, 0))
            tk.Label(self.result_frame, text=f"{train_number} - {train_name}",
                     font=("Segoe UI", 13), fg=LABEL_FG, bg=PRIMARY_BG).pack(anchor="w", padx=6)
            tk.Label(self.result_frame, text=f"Quota: {quota}",
                     font=("Segoe UI", 12), fg=LABEL_FG, bg=PRIMARY_BG).pack(anchor="w", padx=6, pady=(2,0))
            tk.Label(self.result_frame, text=f"Journey Class: {class_name}",
                     font=("Segoe UI", 12), fg=LABEL_FG, bg=PRIMARY_BG).pack(anchor="w", padx=6)
            tk.Label(self.result_frame, text=f"Date Of Journey: {date_of_journey}",
                     font=("Segoe UI", 12), fg=LABEL_FG, bg=PRIMARY_BG).pack(anchor="w", padx=6)
            tk.Label(self.result_frame, text=f"Chart Prepared: {chart_prepared}",
                     font=("Segoe UI", 12, "italic"), fg=LABEL_FG, bg=PRIMARY_BG).pack(anchor="w", padx=6, pady=(0, 4))

            tk.Label(self.result_frame, text="Passengers:", font=("Segoe UI", 14, "bold"),
                     fg=TITLE_FG, bg=PRIMARY_BG).pack(anchor="w", padx=6, pady=(8,2))
            for passenger in response.get("passengerList", []):
                passenger_serial_number = passenger.get("passengerSerialNumber", "?")
                current_status = passenger.get("currentStatus", "N/A")
                current_coach_id = passenger.get("currentCoachId", "N/A")
                current_berth_no = passenger.get("currentBerthNo", "N/A")
                # Compose status line as in your print statement
                status_line = f"Passenger {passenger_serial_number}: {current_status} / {current_coach_id} / {current_berth_no}"
                passbg = PASSENGER_BG if int(passenger_serial_number) % 2 == 1 else ACCENT_BG
                tk.Label(self.result_frame, text=status_line,
                         font=("Segoe UI", 12, "bold"),
                         fg=TEXT_FG, bg=passbg, padx=7, pady=6, relief="flat").pack(anchor="w", padx=16, pady=2, fill="x")
        except KeyError as e:
            tk.Label(self.result_frame, text=f"Invalid JSON data format. Missing key: {e}",
                     font=("Segoe UI", 13, "bold"),
                     fg=PREDICTION_BAD, bg=PRIMARY_BG).pack(anchor="w", padx=12, pady=12)

if __name__ == "__main__":
    app = PNRCheckerApp()
    app.mainloop()
