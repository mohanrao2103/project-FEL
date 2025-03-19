import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from tkintermapview import TkinterMapView
import pandas as pd
import threading
import time
import os
from datetime import datetime

class SecureCommunicationSystem:
    def _init_(self, root: tk.Tk) -> None:
        """Initialize the Secure Communication System with Real-Time Map."""
        self.root = root
        self.root.title("Secure Communication System with Real-Time Map")
        self.root.geometry("1200x700")
        self.root.configure(bg="#f0f0f0")
        
        # Main Frame - Split into Left (Existing UI) and Right (Map)
        main_frame = tk.Frame(root)
        main_frame.pack(fill="both", expand=True)
        
        # Left Panel - Secure Communication System UI
        self.left_panel = tk.Frame(main_frame, width=600, bg="#f0f0f0")
        self.left_panel.pack(side="left", fill="both", expand=True)
        
        ttk.Label(self.left_panel, text="Secure Communication System", font=("Arial", 16)).pack(pady=10)
        
        # Authentication UI
        self.init_auth_ui()
        
        # Right Panel - Real-Time Map
        self.right_panel = tk.Frame(main_frame, width=600)
        self.right_panel.pack(side="right", fill="both", expand=True)
        
        self.map_widget = TkinterMapView(self.right_panel, width=600, height=700, corner_radius=0)
        self.map_widget.pack(fill="both", expand=True)
        self.map_widget.set_position(20.0, 78.0)  # Centered on India
        self.map_widget.set_zoom(5)
        
        # Start monitoring CSV updates
        self.start_monitoring()
    
    def init_auth_ui(self):
        """Initialize Authentication UI."""
        ttk.Label(self.left_panel, text="User Authentication", font=("Arial", 12)).pack(pady=5)
        
        login_button = tk.Button(self.left_panel, text="Login", font=("Arial", 12), bg="#2196F3", fg="white", width=15, height=2, command=self.login)
        login_button.pack(pady=5)
        
        signup_button = tk.Button(self.left_panel, text="Signup", font=("Arial", 12), bg="#4CAF50", fg="white", width=15, height=2, command=self.signup)
        signup_button.pack(pady=5)
        
        # Communication Log
        ttk.Label(self.left_panel, text="Communication Log", font=("Arial", 12)).pack(pady=5)
        self.log_display = scrolledtext.ScrolledText(self.left_panel, height=10, width=70, font=("Arial", 10))
        self.log_display.pack(fill="both", expand=True, padx=10, pady=5)
    
    def login(self):
        """Handle user login."""
        messagebox.showinfo("Login", "Login functionality placeholder")
    
    def signup(self):
        """Handle user signup."""
        messagebox.showinfo("Signup", "Signup functionality placeholder")
    
    def load_map(self):
        """Load tank locations from CSV and update the map."""
        self.map_widget.delete_all_marker()
        if not os.path.exists("tank_locations.csv"):
            return
        
        df = pd.read_csv("tank_locations.csv")
        for _, row in df.iterrows():
            self.map_widget.set_marker(row["Latitude"], row["Longitude"], text=f"{row['Tank_ID']}")
    
    def monitor_csv(self):
        """Monitor CSV file and update map when modified."""
        last_modified = os.path.getmtime("tank_locations.csv") if os.path.exists("tank_locations.csv") else None
        while True:
            time.sleep(2)
            if os.path.exists("tank_locations.csv"):
                new_modified = os.path.getmtime("tank_locations.csv")
                if new_modified != last_modified:
                    last_modified = new_modified
                    self.load_map()
    
    def start_monitoring(self):
        """Start a thread to monitor the CSV file."""
        threading.Thread(target=self.monitor_csv, daemon=True).start()
    
if __name__ == "_main_":
    root = tk.Tk()
    app = SecureCommunicationSystem(root)
    root.mainloop()