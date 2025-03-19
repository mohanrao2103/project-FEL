import threading
import time
import pandas as pd
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
from datetime import datetime
import random
import string
import csv
import base64
import os
import hashlib
from typing import Optional, Dict, List, Tuple
import logging
from zkp_auth import ZKPAuthenticator
from sympy import mod_inverse, isprime
from tkintermapview import TkinterMapView

# Import cryptographic modules
from key_loader import get_random_keys
from encryption import encrypt_data
from decryption import decrypt_data
from digital_signature import generate_signature, verify_signature
from quantum_generator import get_random_sequence_from_csv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('secure_comm.log'),
        logging.StreamHandler()
    ]
)

# Constants
CSV_FILE = 'credentials.csv'
MIN_PASSWORD_LENGTH = 8
PASSWORD_REQUIREMENTS = {
    'length': MIN_PASSWORD_LENGTH,
    'uppercase': True,
    'lowercase': True,
    'numbers': True,
    'special': True
}

class SecureCommunicationSystem:
    def __init__(self, root: tk.Tk) -> None:
        """Initialize the Secure Communication System."""
        self.root = root
        self.root.title("Secure Communication System")
        self.root.geometry("900x700")
        self.root.configure(bg="#f0f0f0")
        
        # Initialize class variables
        self.online_users: List[str] = []
        self.communication_log: List[str] = []
        self.current_user: Optional[str] = None
        self.selected_recipient: Optional[str] = None
        self.last_encryption: Optional[Dict] = None
        self.crypto_initialized = False
        self.authenticated_tanks: List[str] = []  # Track authenticated tanks
        self.tank_status: Dict[int, tk.Label] = {}  # Initialize tank_status as an empty dictionary
        
        # Initialize ZKP authenticator
        self.zkp_auth = ZKPAuthenticator()
        
        # Initialize cryptographic components
        self._initialize_crypto()
        
        # Start with login screen
        self.show_login_screen()

    def _initialize_crypto(self) -> None:
        """Initialize cryptographic components with error handling."""
        try:
            # Get encryption keys
            (
                self.key_aes,
                self.key_des,
                self.key_tdes,
                self.private_key_rsa,
                self.public_key_rsa,
                self.private_key_ecc,
                self.public_key_ecc
            ) = get_random_keys()

            # Get a random encryption sequence
            self.methods, self.sequence_hash = get_random_sequence_from_csv()

            logging.info(f"Cryptography initialized with sequence: {' -> '.join(self.methods)}")
            self.crypto_initialized = True
        except Exception as e:
            logging.error(f"Failed to initialize cryptography: {e}")
            self.crypto_initialized = False
            messagebox.showerror(
                "Initialization Error",
                "Failed to initialize cryptographic components. Some features may be limited."
            )

    def show_login_screen(self) -> None:
        """Display the login screen."""
        # Clear existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()

        # Create login frame
        login_frame = tk.Frame(self.root, bg="#f0f0f0")
        login_frame.place(relx=0.5, rely=0.5, anchor="center")

        # Title
        title_label = tk.Label(login_frame, 
            text="Secure Communication System",
            font=("Arial", 24, "bold"), 
            bg="#f0f0f0")
        title_label.pack(pady=20)

        # Login box
        login_box = tk.Frame(login_frame, 
            bg="#ffffff", 
            bd=2, 
            relief="raised",
            padx=30, 
            pady=30)
        login_box.pack(padx=20, pady=20)

        # Login button
        login_button = tk.Button(login_box, 
            text="LOGIN",
            font=("Arial", 12, "bold"),
            bg="#2196F3",
            fg="white",
            width=15,
            height=2,
            command=self.show_login_window)
        login_button.grid(row=0, column=0, pady=10, padx=5)

        # Signup button
        signup_button = tk.Button(login_box,
            text="SIGNUP",
            font=("Arial", 12, "bold"),
            bg="#4CAF50",
            fg="white",
            width=15,
            height=2,
            command=self.show_signup_window)
        signup_button.grid(row=0, column=1, pady=10, padx=5)

        # Crypto status
        status_text = "Cryptography: " + ("Initialized" if self.crypto_initialized else "Error")
        status_color = "#4a7abc" if self.crypto_initialized else "#cc0000"
        crypto_status = tk.Label(login_frame,
            text=status_text,
            font=("Arial", 10),
            fg=status_color,
            bg="#f0f0f0")
        crypto_status.pack(pady=5)

    def show_login_window(self) -> None:
        """Show the login window."""
        login_win = tk.Toplevel(self.root)
        login_win.title("Login")
        login_win.geometry("300x300")

        frame = tk.Frame(login_win, padx=20, pady=10)
        frame.pack(expand=True, fill='both')

        # Username field
        tk.Label(frame, text="Username:", font=('Arial', 10, 'bold')).pack(pady=5)
        username_entry = tk.Entry(frame, width=30)
        username_entry.pack(pady=5)

        # Password field
        tk.Label(frame, text="Password:", font=('Arial', 10, 'bold')).pack(pady=5)
        password_entry = tk.Entry(frame, show="*", width=30)
        password_entry.pack(pady=5)

        def login_action():
            """Handle login action."""
            username = username_entry.get()
            password = password_entry.get()
            
            if not username or not password:
                messagebox.showerror("Login Error", "Please fill in all fields")
                return
                
            if self.verify_login(username, password):
                self.current_user = username
                self.online_users.append(username)
                login_win.destroy()
                self.show_main_interface()
            else:
                messagebox.showerror("Login Error", "Invalid credentials")

        # Login button
        login_button = tk.Button(frame,
            text="Login",
            command=login_action,
            width=20,
            bg='#2196F3',
            fg='white',
            font=('Arial', 10, 'bold'))
        login_button.pack(pady=20)

    def show_signup_window(self) -> None:
        """Show the signup window."""
        signup_win = tk.Toplevel(self.root)
        signup_win.title("Signup")
        signup_win.geometry("300x400")

        frame = tk.Frame(signup_win, padx=20, pady=10)
        frame.pack(expand=True, fill='both')

        # Username field
        tk.Label(frame, text="Username:", font=('Arial', 10, 'bold')).pack(pady=5)
        username_entry = tk.Entry(frame, width=30)
        username_entry.pack(pady=5)

        # Password field
        tk.Label(frame, text="Password:", font=('Arial', 10, 'bold')).pack(pady=5)
        password_entry = tk.Entry(frame, show="*", width=30)
        password_entry.pack(pady=5)

        # Confirm Password field
        tk.Label(frame, text="Confirm Password:", font=('Arial', 10, 'bold')).pack(pady=5)
        confirm_password_entry = tk.Entry(frame, show="*", width=30)
        confirm_password_entry.pack(pady=5)

        def signup_action():
            """Handle signup action."""
            username = username_entry.get()
            password = password_entry.get()
            confirm_password = confirm_password_entry.get()

            if not username or not password or not confirm_password:
                messagebox.showerror("Signup Error", "Please fill in all fields")
                return

            if password != confirm_password:
                messagebox.showerror("Signup Error", "Passwords do not match")
                return

            if not self.validate_password(password):
                return

            if self.username_exists(username):
                messagebox.showerror("Signup Error", "Username already exists")
                return

            if self.store_credentials(username, password):
                messagebox.showinfo("Success", "Account created successfully")
                signup_win.destroy()
            else:
                messagebox.showerror("Error", "Failed to create account")

        # Signup button
        signup_button = tk.Button(frame,
            text="Signup",
            command=signup_action,
            width=20,
            bg='#4CAF50',
            fg='white',
            font=('Arial', 10, 'bold'))
        signup_button.pack(pady=20)

    def validate_password(self, password: str) -> bool:
        """Validate password against requirements."""
        if len(password) < PASSWORD_REQUIREMENTS['length']:
            messagebox.showerror("Invalid Password", 
                f"Password must be at least {PASSWORD_REQUIREMENTS['length']} characters long")
            return False

        if PASSWORD_REQUIREMENTS['uppercase'] and not any(c.isupper() for c in password):
            messagebox.showerror("Invalid Password", "Password must contain at least one uppercase letter")
            return False

        if PASSWORD_REQUIREMENTS['lowercase'] and not any(c.islower() for c in password):
            messagebox.showerror("Invalid Password", "Password must contain at least one lowercase letter")
            return False

        if PASSWORD_REQUIREMENTS['numbers'] and not any(c.isdigit() for c in password):
            messagebox.showerror("Invalid Password", "Password must contain at least one number")
            return False

        if PASSWORD_REQUIREMENTS['special'] and not any(not c.isalnum() for c in password):
            messagebox.showerror("Invalid Password", "Password must contain at least one special character")
            return False

        return True

    def username_exists(self, username: str) -> bool:
        """Check if username exists in credentials file."""
        if not os.path.exists(CSV_FILE):
            return False

        with open(CSV_FILE, 'r') as file:
            reader = csv.reader(file)
            next(reader, None)  # Skip header
            return any(row[0] == username for row in reader)

    def store_credentials(self, username: str, password: str) -> bool:
        """Store user credentials securely."""
        try:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
            # Register user with ZKP authenticator
            secret_key = self.zkp_auth.register_user(username)
            logging.info(f"User {username} registered with ZKP secret key: {secret_key}")
        
            # Create CSV file if it doesn't exist
            if not os.path.exists(CSV_FILE):
                with open(CSV_FILE, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(['username', 'password', 'zkp_secret'])
    
            # Append the new credentials
            with open(CSV_FILE, 'a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([username, hashed_password, secret_key])
            
            logging.info(f"Credentials stored successfully for user: {username}")
            return True
        except Exception as e:
            logging.error(f"Failed to store credentials: {e}")
            return False

    def verify_login(self, username: str, password: str) -> bool:
        """Verify login credentials."""
        if not os.path.exists(CSV_FILE):
            return False

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        with open(CSV_FILE, 'r') as file:
            reader = csv.reader(file)
            next(reader, None)  # Skip header
            for row in reader:
                if row[0] == username and row[1] == hashed_password:
                    return True
        return False

    def show_main_interface(self) -> None:
        """Show the main interface."""
        # Clear existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()

        # Create main frame
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill="both", expand=True)

        # Top bar
        top_bar = tk.Frame(main_frame, bg="#4a7abc", height=50)
        top_bar.pack(fill="x")

        # User info
        user_label = tk.Label(top_bar,
            text=f"Logged in as: {self.current_user}",
            font=("Arial", 12),
            bg="#4a7abc",
            fg="white")
        user_label.pack(side="left", padx=20, pady=10)

        # Logout button
        logout_button = tk.Button(top_bar,
            text="Logout",
            font=("Arial", 10),
            bg="#f0f0f0",
            command=self.logout)
        logout_button.pack(side="right", padx=20, pady=10)

        # Content area
        content_frame = tk.Frame(main_frame, bg="#f0f0f0")
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Left panel - Available users and selecting users
        left_panel = tk.Frame(content_frame, bg="#ffffff", bd=1, relief="solid", width=300)
        left_panel.pack(side="left", fill="y", padx=10, pady=10)

        # Middle panel - Tabs (Authentication, Query, Encryption, Decryption, Communication Log)
        middle_panel = tk.Frame(content_frame, bg="#ffffff", bd=1, relief="solid", width=400)
        middle_panel.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        # Right panel - Real-Time Map
        right_panel = tk.Frame(content_frame, bg="#ffffff", bd=1, relief="solid", width=400)
        right_panel.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        # Add the map widget
        self.map_widget = TkinterMapView(right_panel, width=600, height=700, corner_radius=0)
        self.map_widget.pack(fill="both", expand=True)
        self.map_widget.set_position(20.0, 78.0)  # Centered on India
        self.map_widget.set_zoom(5)

        # Start monitoring CSV updates
        self.start_monitoring()

        # Users label
        users_label = tk.Label(left_panel,
            text="Available Users",
            font=("Arial", 14, "bold"),
            bg="#4a7abc",
            fg="white")
        users_label.pack(fill="x", pady=1)

        # User selection checkboxes
        self.user_checkboxes = {}
        self.selected_users = tk.StringVar(value=[])  # Track selected users

        def toggle_select_all():
            """Toggle selection of all users."""
            if select_all_var.get():
                # Select all users
                for username, var in self.user_checkboxes.items():
                    var.set(1)
            else:
                # Deselect all users
                for username, var in self.user_checkboxes.items():
                    var.set(0)

        # "Select All" checkbox
        select_all_var = tk.IntVar()
        select_all_checkbox = tk.Checkbutton(left_panel,
            text="Select All Users",
            variable=select_all_var,
            command=toggle_select_all,
            font=("Arial", 12),
            bg="#ffffff")
        select_all_checkbox.pack(anchor="w", padx=10, pady=5)

        # Populate user list with checkboxes
        if os.path.exists(CSV_FILE):
            with open(CSV_FILE, 'r') as file:
                reader = csv.reader(file)
                next(reader, None)  # Skip header
                for row in reader:
                    username = row[0]
                    if username != self.current_user:
                        var = tk.IntVar()
                        checkbox = tk.Checkbutton(left_panel,
                            text=username,
                            variable=var,
                            font=("Arial", 12),
                            bg="#ffffff")
                        checkbox.pack(anchor="w", padx=10, pady=2)
                        self.user_checkboxes[username] = var

        # Select users button
        select_button = tk.Button(left_panel,
            text="Select Users",
            font=("Arial", 12),
            bg="#4a7abc",
            fg="white",
            command=self.select_users)
        select_button.pack(fill="x", padx=10, pady=10)

        # User listbox
        self.user_listbox = tk.Listbox(left_panel,
            font=("Arial", 12),
            height=15,
            selectmode="single")
        self.user_listbox.pack(fill="both", expand=True, padx=10, pady=10)

        # Populate the left panel
        self.init_left_panel(left_panel)

        # Select user button
        select_button = tk.Button(left_panel,
            text="Select User",
            font=("Arial", 12),
            bg="#4a7abc",
            fg="white",
            command=self.select_user)
        select_button.pack(fill="x", padx=10, pady=10)

        # Create notebook for tabs
        self.tab_control = ttk.Notebook(right_panel)
        # Create notebook for tabs in the middle panel
        self.tab_control = ttk.Notebook(middle_panel)

        # Create tabs
        self.auth_tab = tk.Frame(self.tab_control)
        self.query_tab = tk.Frame(self.tab_control)
        self.encryption_tab = tk.Frame(self.tab_control)
        self.decryption_tab = tk.Frame(self.tab_control)
        self.log_tab = tk.Frame(self.tab_control)

        # Add tabs to notebook
        self.tab_control.add(self.auth_tab, text="Authentication")
        self.tab_control.add(self.query_tab, text="Query")
        self.tab_control.add(self.encryption_tab, text="Encryption")
        self.tab_control.add(self.decryption_tab, text="Decryption")
        self.tab_control.add(self.log_tab, text="Communication Log")
        
        self.tab_control.pack(expand=True, fill="both")

        # Initialize tabs
        self.setup_auth_tab()
        self.setup_query_tab()
        self.setup_encryption_tab()
        self.setup_decryption_tab()
        self.setup_log_tab()
    
    def init_left_panel(self, left_panel: tk.Frame) -> None:
        """Initialize the left panel with available users and selection options."""
        # Users label
        users_label = tk.Label(left_panel,
            text="Available Users",
            font=("Arial", 14, "bold"),
            bg="#4a7abc",
            fg="white")
        users_label.pack(fill="x", pady=1)
    
        # User selection checkboxes
        self.user_checkboxes = {}
        self.selected_users = tk.StringVar(value=[])  # Track selected users
    
        def toggle_select_all():
            """Toggle selection of all users."""
            select_all = select_all_var.get()
            for username, var in self.user_checkboxes.items():
                var.set(select_all)  # Set each checkbox to match the "Select All" state
    
        # "Select All" checkbox
        select_all_var = tk.IntVar()
        select_all_checkbox = tk.Checkbutton(left_panel,
            text="Select All Users",
            variable=select_all_var,
            command=toggle_select_all,
            font=("Arial", 12),
            bg="#ffffff")
        select_all_checkbox.pack(anchor="w", padx=10, pady=5)
    
        # Populate user list with checkboxes
        if os.path.exists(CSV_FILE):
            with open(CSV_FILE, 'r') as file:
                reader = csv.reader(file)
                next(reader, None)  # Skip header
                for row in reader:
                    username = row[0]
                    if username != self.current_user:
                        var = tk.IntVar()
                        checkbox = tk.Checkbutton(left_panel,
                            text=username,
                            variable=var,
                            font=("Arial", 12),
                            bg="#ffffff")
                        checkbox.pack(anchor="w", padx=10, pady=2)
                        self.user_checkboxes[username] = var
    
        # Select users button
        select_button = tk.Button(left_panel,
            text="Select Users",
            font=("Arial", 12),
            bg="#4a7abc",
            fg="white",
            command=self.select_users)
        select_button.pack(fill="x", padx=10, pady=10)

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

    def select_users(self) -> None:
        """Handle user selection."""
        selected_users = [username for username, var in self.user_checkboxes.items() if var.get() == 1]
        if not selected_users:
            messagebox.showinfo("Selection Required", "Please select at least one user")
            return

        self.selected_recipient = selected_users  # Store the selected users
        selected_users_str = ", ".join(selected_users)

        # Update authentication tab
        self.auth_status_label.config(
        text=f"Selected Users: {selected_users_str}\nReady for ZKP Authentication")
        self.auth_button.config(state="normal")

        # Update query tab
        self.query_status_label.config(
            text=f"Selected Users: {selected_users_str}\nStatus: Not Queried")
        self.query_button.config(state="normal")

        # Enable encryption
        self.encrypt_button.config(state="normal")

        # Add to log
        self.add_to_log(f"Selected users {selected_users_str} for communication")

    def refresh_user_list(self) -> None:
        """Refresh the list of available users."""
        self.user_listbox.delete(0, tk.END)
        
        if os.path.exists(CSV_FILE):
            with open(CSV_FILE, 'r') as file:
                reader = csv.reader(file)
                next(reader, None)  # Skip header
                for row in reader:
                    if row[0] != self.current_user:
                        self.user_listbox.insert(tk.END, row[0])

    def select_user(self) -> None:
        """Handle user selection."""
        selection = self.user_listbox.curselection()
        if not selection:
            messagebox.showinfo("Selection Required", "Please select a user")
            return

        self.selected_recipient = self.user_listbox.get(selection[0])
        
        # Update authentication tab
        self.auth_status_label.config(
            text=f"Selected User: {self.selected_recipient}\nReady for ZKP Authentication")
        self.auth_button.config(state="normal")

        # Update query tab
        self.query_status_label.config(
            text=f"Selected User: {self.selected_recipient}\nStatus: Not Queried")
        self.query_button.config(state="normal")

        # Enable encryption
        self.encrypt_button.config(state="normal")
        
        # Add to log
        self.add_to_log(f"Selected user {self.selected_recipient} for communication")

    def setup_auth_tab(self) -> None:
        """Setup the authentication tab."""
        # Status frame
        status_frame = tk.Frame(self.auth_tab, bg="#e6f0ff", bd=1, relief="solid")
        status_frame.place(relx=0.5, rely=0.3, anchor="center", width=400, height=150)

        self.auth_status_label = tk.Label(status_frame,
            text="No user selected\nUsing Zero-Knowledge Proof Authentication",
            font=("Arial", 14),
            bg="#e6f0ff")
        self.auth_status_label.pack(pady=20)

        # Authentication button
        self.auth_button = tk.Button(self.auth_tab,
            text="Authenticate with ZKP",
            font=("Arial", 12),
            bg="#4a7abc",
            fg="white",
            state="disabled",
            command=self.authenticate_connection)
        self.auth_button.place(relx=0.5, rely=0.6, anchor="center")

    def setup_query_tab(self) -> None:
        """Setup the query tab."""
        # Query frame
        query_frame = tk.Frame(self.query_tab, bg="#e6f0ff", bd=1, relief="solid")
        query_frame.place(relx=0.5, rely=0.3, anchor="center", width=400, height=200)

        # Query label
        query_label = tk.Label(query_frame,
            text="Query User Status",
            font=("Arial", 14, "bold"),
            bg="#4a7abc",
            fg="white")
        query_label.pack(fill="x")

        self.query_status_label = tk.Label(query_frame,
            text="No user selected",
            font=("Arial", 12),
            bg="#e6f0ff")
        self.query_status_label.pack(pady=20)

        # Message input label
        message_label = tk.Label(query_frame,
            text="Enter Message:",
            font=("Arial", 12),
            bg="#e6f0ff")
        message_label.pack(anchor="w", padx=10, pady=(10, 0))

        # Message input box
        self.query_message_text = tk.Text(query_frame,
            height=5,
            width=40,
            font=("Arial", 11))
        self.query_message_text.pack(padx=10, pady=5)

        # Response input label
        response_label = tk.Label(query_frame,
            text="Enter Response:",
            font=("Arial", 12),
            bg="#e6f0ff")
        response_label.pack(anchor="w", padx=10, pady=(10, 0))

        # Response input box
        self.query_response_text = tk.Entry(query_frame,
            font=("Arial", 11),
            width=40)
        self.query_response_text.pack(padx=10, pady=5)

        # Send message button
        send_message_button = tk.Button(query_frame,
            text="Send Message",
            font=("Arial", 12),
            bg="#4a7abc",
            fg="white",
            command=self.send_query_message)
        send_message_button.pack(pady=10)

        # Query button
        self.query_button = tk.Button(self.query_tab,
            text="Send Query",
            font=("Arial", 12),
            bg="#4a7abc",
            fg="white",
            state="disabled",
            command=self.send_query)
        self.query_button.place(relx=0.5, rely=0.6, anchor="center")

    def setup_encryption_tab(self) -> None:
        """Setup the encryption tab."""
        encryption_frame = tk.Frame(self.encryption_tab, bg="#ffffff")
        encryption_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Message input
        tk.Label(encryption_frame,
            text="Enter Message to Encrypt:",
            font=("Arial", 12),
            bg="#ffffff").pack(anchor="w", pady=(0, 5))

        self.message_text = tk.Text(encryption_frame,
            height=5,
            width=40,
            font=("Arial", 11))
        self.message_text.pack(fill="x", pady=(0, 20))

        # Encryption method selection
        method_frame = tk.Frame(encryption_frame, bg="#ffffff")
        method_frame.pack(fill="x", pady=10)

        tk.Label(method_frame,
            text="Encryption Method:",
            font=("Arial", 12),
            bg="#ffffff").pack(side="left")

        self.method_var = tk.StringVar(value="Advanced")
        ttk.Combobox(method_frame,
            textvariable=self.method_var,
            values=["Simple", "Advanced"],
            width=10,
            state="readonly").pack(side="left", padx=10)

        # Encrypt button
        self.encrypt_button = tk.Button(encryption_frame,
            text="Encrypt & Send",
            font=("Arial", 12),
            bg="#4a7abc",
            fg="white",
            state="disabled",
            command=self.encrypt_and_send)
        self.encrypt_button.pack(pady=20)

        # Result display
        tk.Label(encryption_frame,
            text="Encrypted Message:",
            font=("Arial", 12),
            bg="#ffffff").pack(anchor="w", pady=(20, 5))

        self.encrypted_result = tk.Text(encryption_frame,
            height=5,
            width=40,
            font=("Arial", 11),
            state="disabled")
        self.encrypted_result.pack(fill="x")

    def setup_decryption_tab(self) -> None:
        """Setup the decryption tab."""
        decryption_frame = tk.Frame(self.decryption_tab, bg="#ffffff")
        decryption_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Received message display
        tk.Label(decryption_frame,
            text="Received Encrypted Message:",
            font=("Arial", 12),
            bg="#ffffff").pack(anchor="w", pady=(0, 5))

        self.received_text = tk.Text(decryption_frame,
            height=5,
            width=40,
            font=("Arial", 11),
            state="disabled")
        self.received_text.pack(fill="x", pady=(0, 20))

        # Decrypt button
        self.decrypt_button = tk.Button(decryption_frame,
            text="Decrypt Message",
            font=("Arial", 12),
            bg="#4a7abc",
            fg="white",
            state="disabled",
            command=self.decrypt_message)
        self.decrypt_button.pack(pady=20)

        # Decrypted message display
        tk.Label(decryption_frame,
            text="Decrypted Message:",
            font=("Arial", 12),
            bg="#ffffff").pack(anchor="w", pady=(20, 5))

        self.decrypted_result = tk.Text(decryption_frame,
            height=5,
            width=40,
            font=("Arial", 11),
            state="disabled")
        self.decrypted_result.pack(fill="x")

        # Signature status
        self.signature_status = tk.Label(decryption_frame,
            text="",
            font=("Arial", 10),
            bg="#ffffff")
        self.signature_status.pack(pady=5)

    def setup_log_tab(self) -> None:
        """Setup the communication log tab."""
        log_frame = tk.Frame(self.log_tab, bg="#ffffff")
        log_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Log title
        tk.Label(log_frame,
            text="Communication Log",
            font=("Arial", 14, "bold"),
            bg="#4a7abc",
            fg="white").pack(fill="x")

        # Log display
        self.log_display = scrolledtext.ScrolledText(log_frame,
            height=20,
            width=60,
            font=("Arial", 11))
        self.log_display.pack(fill="both", expand=True, pady=10)

        # Refresh button
        tk.Button(log_frame,
            text="Refresh Log",
            font=("Arial", 12),
            bg="#4a7abc",
            fg="white",
            command=self.refresh_log).pack(pady=10)

    def authenticate_connection(self) -> None:
        """Authenticate connection using Zero-Knowledge Proof."""
        if not self.selected_recipient:
            return
    
        # Generate challenges for tanks
        self.challenges = {}
        self.challenge_buffer = {}  # Clear previous challenges
        self.authenticated_tanks = []  # Track authenticated tanks

        for tank_id in range(1, 6):  # Assuming 5 tanks
            tank_name = f"Tank{tank_id}"  # Ensure consistent naming
            success, challenge, message = self.zkp_auth.generate_challenge(tank_name)
            if success:
                self.challenges[tank_id] = challenge
                self.challenge_buffer[tank_name] = challenge  # Store in challenge_buffer
            else:
                self.challenges[tank_id] = None
                logging.error(f"Failed to generate challenge for Tank {tank_id}: {message}")
    
        logging.info(f"Generated challenges: {self.challenges}")
        self.auth_status_label.config(text=f"Challenges sent: {self.challenges}")
    
        # Display verification boxes
        self.display_verification_boxes()
    
        # Start the countdown timer
        timer_value = 180  # Set timer to 30 seconds
        self.start_timer(timer_value)

        # Automatically send queries to authenticated tanks
        self.root.after(2000, self.send_automated_queries)
    
    def send_automated_queries(self) -> None:
        """Send automated queries to authenticated tanks."""
        for tank_id, status_label in self.tank_status.items():
            if status_label.cget("bg") == "green":  # Only authenticated tanks
                self.selected_recipient = f"Tank{tank_id}"  # Set the selected recipient
                self.send_query()  # Use the send_query method to handle the query process
    
                # # Prompt user for response to "Are you ready?"
                # response = self.get_user_input(f"Query for {tank_name}", "Are you ready?")
                # if not response:
                #     logging.info(f"No response received from {tank_name}")
                #     continue
    
                # logging.info(f"Response from {tank_name}: {response}")
    
                # if response.lower() in ["yes", "okk", "ready"]:
                #     # Prompt user for location response
                #     location_response = self.get_user_input(f"Query for {tank_name}", "Give me your location")
                #     if location_response:
                #         logging.info(f"Location response from {tank_name}: {location_response}")
                #     else:
                #         logging.info(f"No location response received from {tank_name}")
    def send_query_message(self) -> None:
        """Send a message to the selected user and handle the response."""
        if not self.selected_recipient:
            messagebox.showwarning("No Recipient", "Please select a recipient before sending a message.")
            return

        # Get the message from the text box
        message = self.query_message_text.get("1.0", "end-1c").strip()
        if not message:
            messagebox.showwarning("Empty Message", "Please enter a message before sending.")
            return

        # Log the message sending action
        logging.info(f"Sending message to {self.selected_recipient}: {message}")
        self.add_to_log(f"Message sent to {self.selected_recipient}: {message}")

        # Clear the message input box
        self.query_message_text.delete("1.0", "end")

        # Simulate receiving a response
        response = self.query_response_text.get().strip().lower()
        self.query_response_text.delete(0, "end")  # Clear the response input box

        if response in ["yes", "okk", "ready"]:
            # Automatically send "Give me your location" message
            location_message = "Give me your location"
            logging.info(f"Automatically sending message to {self.selected_recipient}: {location_message}")
            self.add_to_log(f"Message sent to {self.selected_recipient}: {location_message}")
            messagebox.showinfo("Message Sent", f"Message successfully sent to {self.selected_recipient}: {location_message}")
        else:
            # Log invalid response
            logging.info(f"Received invalid response from {self.selected_recipient}: {response}")
            self.add_to_log(f"Invalid response received from {self.selected_recipient}: {response}")
            messagebox.showwarning("Invalid Response", f"Received invalid response: {response}")
        def get_user_input(self, title: str, prompt: str) -> Optional[str]:
            """Display a dialog box to get input from the user."""
            input_win = tk.Toplevel(self.root)
            input_win.title(title)
            input_win.geometry("300x150")
            input_win.grab_set()  # Make the dialog modal

            tk.Label(input_win, text=prompt, font=("Arial", 12)).pack(pady=10)

            response_var = tk.StringVar()
            response_entry = tk.Entry(input_win, textvariable=response_var, font=("Arial", 12), width=25)
            response_entry.pack(pady=10)

            def submit_response():
                input_win.destroy()

            submit_button = tk.Button(input_win, text="Submit", font=("Arial", 12), command=submit_response)
            submit_button.pack(pady=10)

            input_win.wait_window()  # Wait for the dialog to close
            return response_var.get().strip()

    def display_verification_boxes(self) -> None:
        """Display verification boxes for each tank."""
        if hasattr(self, 'verification_frame'):
            self.verification_frame.destroy()  # Clear previous verification boxes
    
        self.verification_frame = tk.Frame(self.auth_tab, bg="#e6f0ff")
        self.verification_frame.place(relx=0.5, rely=0.7, anchor="center", width=400, height=200)
    
        self.tank_status = {}
        self.right_panel_status = {}  # Track status labels in the right panel

        for tank_id in range(1, 6):  # Assuming 5 tanks
            frame = tk.Frame(self.verification_frame, bg="#e6f0ff")
            frame.pack(fill="x", pady=5)
    
            tk.Label(frame, text=f"Tank {tank_id}:", font=("Arial", 12), bg="#e6f0ff").pack(side="left", padx=10)
    
            entry = tk.Entry(frame, width=10)
            entry.pack(side="left", padx=10)
    
            button = tk.Button(frame, text="Verify", command=lambda tid=tank_id, e=entry: self.verify_tank_response(tid, e))
            button.pack(side="left", padx=10)
    
            status_label = tk.Label(frame, text="⏳", font=("Arial", 12), bg="#e6f0ff", width=5)
            status_label.pack(side="left", padx=10)
    
            self.tank_status[tank_id] = status_label

            # Add status label to the right panel
            right_status_label = tk.Label(self.auth_tab, text=f"Tank {tank_id}: ⏳", font=("Arial", 12), bg="#ffffff")
            right_status_label.place(relx=0.8, rely=0.2 + (tank_id * 0.05), anchor="w")
            self.right_panel_status[tank_id] = right_status_label
    
    def verify_tank_response(self, tank_id: int, entry: tk.Entry) -> None:
        """Verify the response for a specific tank."""
        response = entry.get()
        if not response:
            messagebox.showerror("Input Required", f"Please enter a response for Tank {tank_id}")
            return
    
        tank_name = f"Tank{tank_id}"  # Ensure consistent naming
        if tank_name not in self.challenge_buffer:
            messagebox.showerror("Error", f"No challenge found for Tank {tank_id}")
            return
    
        # Get the challenge and expected response
        challenge = self.challenge_buffer[tank_name]
        secret_key = self.zkp_auth.secret_keys.get(tank_name, None)
        if not secret_key:
            messagebox.showerror("Error", f"No secret key found for {tank_name}")
            return

        expected_response = self.get_expected_response(challenge, secret_key)

        # Verify the response
        if response == expected_response:
            self.tank_status[tank_id].config(text="✔", bg="green")
            self.right_panel_status[tank_id].config(text=f"Tank {tank_id}: ✔", bg="green")
            logging.info(f"Verification result for {tank_name}: Authentication successful")
        else:
            self.tank_status[tank_id].config(text="✘", bg="red")
            self.right_panel_status[tank_id].config(text=f"Tank {tank_id}: ✘", bg="red")
            logging.info(f"Verification result for {tank_name}: Authentication failed")
    
        ## Update the status label
        #if success:
        #    self.tank_status[tank_id].config(text="✔", bg="green")
        #else:
        #    self.tank_status[tank_id].config(text="✘", bg="red")

    def get_expected_response(self, challenge, secret_key):
        """Returns the expected response based on the challenge type."""
        if challenge == 0:
            return hex(random.randint(1, 100))
        elif challenge == 1:
            return hashlib.sha256(str(secret_key).encode()).hexdigest()
        elif challenge == 2:
            return str(pow(7, 13, 10007))  # Use the same test_modulo value
        elif challenge == 3:
            timestamp = int(time.time())
            return hashlib.sha256((str(secret_key) + str(timestamp)).encode()).hexdigest()
        elif challenge == 4:
            return str(mod_inverse(17, 10007))
        elif challenge == 5:
            return str(self.fibonacci(10))
        elif challenge == 6:
            return "Prime" if isprime(9973) else "Not Prime"
        return "Invalid"
    
    @staticmethod
    def fibonacci(n):
        """Returns the nth Fibonacci number."""
        a, b = 0, 1
        for _ in range(n):
            a, b = b, a + b
        return a

    def start_timer(self, time_limit: int) -> None:
        """Start the countdown timer for authentication."""
        self.timer_label = tk.Label(self.auth_tab, text=f"Timer: {time_limit}s", font=("Arial", 12), bg="#e6f0ff")
        self.timer_label.place(relx=0.5, rely=0.9, anchor="center")
    
        def countdown():
            for i in range(time_limit, 0, -1):
                if not self.timer_label.winfo_exists():  # Check if the widget still exists
                    logging.warning("Timer label destroyed before countdown completed.")
                    return
                self.timer_label.config(text=f"Timer: {i}s")
                time.sleep(1)

            if self.timer_label.winfo_exists():  # Check again before updating
                self.timer_label.config(text="⏳ Timer expired!")
    
            # Mark unresponsive tanks as yellow
            for tank_id, status_label in self.tank_status.items():
                if status_label.cget("bg") not in ("green", "red"):
                    status_label.config(text="❓", bg="yellow")

        threading.Thread(target=countdown, daemon=True).start()

    def send_query(self) -> None:
        """Send a query to the selected user."""
        if not self.selected_recipient:
            logging.warning("No recipient selected for query.")
            return

        # Check if tank_status is initialized
        if not hasattr(self, 'tank_status') or not self.tank_status:
            messagebox.showerror("Error", "Tank status is not initialized. Please authenticate tanks first.")
            logging.error("Tank status is not initialized. Cannot send query.")
            return

        # Check if the selected recipient is authenticated
        for tank_id, status_label in self.tank_status.items():
            tank_name = f"Tank{tank_id}"
            if tank_name == self.selected_recipient and status_label.cget("bg") == "green":
                logging.info(f"Sending query to {self.selected_recipient}")
                self.query_status_label.config(text=f"Querying {self.selected_recipient} status...")
                self.root.update()

                # Prompt user for response to "Are you ready?"
                response = self.get_user_input(f"Query for {self.selected_recipient}", "Are you ready?")
                if not response:
                    logging.info(f"No response received from {self.selected_recipient}")
                    self.query_status_label.config(
                        text=f"Selected User: {self.selected_recipient}\nStatus: No Response")
                    return

                logging.info(f"Response from {self.selected_recipient}: {response}")

                # If the response is valid, proceed to the next query
                if response.lower() in ["yes", "okk", "ready"]:
                    location_response = self.get_user_input(f"Query for {self.selected_recipient}", "Give me your location")
                    if location_response:
                        logging.info(f"Location response from {self.selected_recipient}: {location_response}")
                        self.add_to_log(f"Location response from {self.selected_recipient}: {location_response}")
                    else:
                        logging.info(f"No location response received from {self.selected_recipient}")
                else:
                    self.query_status_label.config(
                        text=f"Selected User: {self.selected_recipient}\nStatus: Not Ready")
                    logging.info(f"{self.selected_recipient} is not ready")
                return

        # If the selected recipient is not authenticated
        logging.warning(f"Query failed: {self.selected_recipient} is not authenticated")
        self.query_status_label.config(
            text=f"Selected User: {self.selected_recipient}\nStatus: Not Authenticated")
        
    # def send_query(self) -> None:
    #     """Send a query to the selected user."""
    #     if not self.selected_recipient:
    #         return

    #     logging.info(f"Sending query to {self.selected_recipient}")
    #     self.query_status_label.config(text="Querying user status...")
    #     self.root.update()
    #     self.root.after(1000)  # Simulate delay

    #     # Simulate status
    #     status = random.choice(["Online", "Away", "Busy", "Offline"])
    #     self.query_status_label.config(
    #         text=f"Selected User: {self.selected_recipient}\nStatus: {status}")
    #     logging.info(f"Query result for {self.selected_recipient}: {status}")

    #     self.add_to_log(f"Queried {self.selected_recipient} - Status: {status}")

    def encrypt_and_send(self) -> None:
        """Encrypt and send a message."""
        if not self.selected_recipient:
            return

        message = self.message_text.get("1.0", "end-1c").strip()
        if not message:
            messagebox.showwarning("Input Required", "Please enter a message")
            return

        try:
            # Generate signature
            signature = generate_signature(message, self.private_key_rsa)

            # Encrypt message
            ivs, encrypted_data, tags = encrypt_data(
                message,
                self.methods,
                self.key_aes,
                self.key_des,
                self.key_tdes,
                self.public_key_rsa,
                self.public_key_ecc
            )

            # Store encryption info
            self.last_encryption = {
                "ivs": ivs,
                "data": encrypted_data,
                "tags": tags,
                "signature": signature,
                "original": message
            }

            # Display encrypted message
            self.encrypted_result.config(state="normal")
            self.encrypted_result.delete("1.0", tk.END)
            self.encrypted_result.insert("1.0", encrypted_data[:100] + "..." if len(encrypted_data) > 100 else encrypted_data)
            self.encrypted_result.config(state="disabled")

            # Enable decryption
            self.received_text.config(state="normal")
            self.received_text.delete("1.0", tk.END)
            self.received_text.insert("1.0", encrypted_data)
            self.received_text.config(state="disabled")
            self.decrypt_button.config(state="normal")

            # Log the action
            self.add_to_log(f"Sent encrypted message to {self.selected_recipient}")
            
            messagebox.showinfo("Success", "Message encrypted and sent successfully")
        except Exception as e:
            logging.error(f"Encryption error: {e}")
            messagebox.showerror("Error", f"Failed to encrypt message: {str(e)}")

    def decrypt_message(self) -> None:
        """Decrypt a received message."""
        if not hasattr(self, 'last_encryption'):
            messagebox.showwarning("No Message", "No message to decrypt")
            return

        try:
            # Decrypt message
            decrypted = decrypt_data(
                self.last_encryption["ivs"],
                self.last_encryption["data"],
                self.last_encryption["tags"],
                self.methods,
                self.key_aes,
                self.key_des,
                self.key_tdes,
                self.private_key_rsa,
                self.private_key_ecc
            )

            # Verify signature
            is_valid = verify_signature(
                decrypted,
                self.last_encryption["signature"],
                self.public_key_rsa
            )

            # Display decrypted message
            self.decrypted_result.config(state="normal")
            self.decrypted_result.delete("1.0", tk.END)
            self.decrypted_result.insert("1.0", decrypted)
            self.decrypted_result.config(state="disabled")

            # Update signature status
            if is_valid:
                self.signature_status.config(
                    text="Digital signature verified: Message integrity confirmed",
                    fg="green")
            else:
                self.signature_status.config(
                    text="WARNING: Digital signature verification failed!",
                    fg="red")

            # Log the action
            self.add_to_log(f"Decrypted message from {self.selected_recipient}")
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            messagebox.showerror("Error", f"Failed to decrypt message: {str(e)}")

    def add_to_log(self, message: str) -> None:
        """Add a message to the communication log."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.communication_log.append(log_entry)
        self.refresh_log()

    def refresh_log(self) -> None:
        """Refresh the communication log display."""
        self.log_display.delete("1.0", tk.END)
        for entry in self.communication_log:
            self.log_display.insert(tk.END, entry)
        self.log_display.see(tk.END)

    def logout(self) -> None:
        """Handle user logout."""
        if self.current_user in self.online_users:
            self.online_users.remove(self.current_user)

        self.current_user = None
        self.selected_recipient = None
        self.show_login_screen()

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = SecureCommunicationSystem(root)
        root.mainloop()
    except Exception as e:
        logging.critical(f"Application crashed: {e}")
        raise