import tkinter as tk
from tkinter import messagebox, ttk
from datetime import datetime
import random
import string
import csv
import base64
import os

# Import cryptographic modules
from key_loader import get_random_keys
from encryption import encrypt_data
from decryption import decrypt_data
from digital_signature import generate_signature, verify_signature
from quantum_generator import get_random_sequence_from_csv

# Import external modules
from commandar import Commander
from commandar_gui import CommanderGUI
from tank import Tank
from tank_gui import TankGUI

class SecureCommunicationSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Communication System")
        self.root.geometry("900x700")
        self.root.configure(bg="#f0f0f0")
        
        # Load users from CSV if available, otherwise use default
        self.load_users()
        
        # Track online users (would be handled by a server in a real system)
        self.online_users = []
        
        # Communication log
        self.communication_log = []
        
        # Current user
        self.current_user = None
        
        # Selected recipient
        self.selected_recipient = None
        
        # Cryptographic keys and data
        self.initialize_crypto()
        
        # Start with login screen
        self.show_login_screen()
    
    def load_users(self):
        try:
            self.users = {}
            with open('users.csv', 'r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    self.users[row['id']] = {
                        "password": row['password'],
                        "name": row['id'].capitalize(),
                        "role": row['role']
                    }
            print(f"Loaded {len(self.users)} users from users.csv")
        except Exception as e:
            print(f"Error loading users: {e}")
            # Default users if CSV fails
            self.users = {
                "admin": {"password": "admin123", "name": "Administrator", "role": "admin"},
                "user1": {"password": "user123", "name": "John Doe", "role": "user"},
                "user2": {"password": "user456", "name": "Jane Smith", "role": "user"},
                "user3": {"password": "user789", "name": "Robert Johnson", "role": "user"},
                "user4": {"password": "user101", "name": "Emily Davis", "role": "user"}
            }
    
    def initialize_crypto(self):
        try:
            # Get encryption keys
            self.key_aes, self.key_des, self.key_tdes, self.private_key_rsa, self.public_key_rsa, self.private_key_ecc, self.public_key_ecc = get_random_keys()
            
            # Get a random encryption sequence
            self.methods, self.sequence_hash = get_random_sequence_from_csv()
            
            print(f"Initialized cryptography with sequence: {' -> '.join(self.methods)}")
            self.crypto_initialized = True
        except Exception as e:
            print(f"Error initializing cryptography: {e}")
            self.crypto_initialized = False
    
    def show_login_screen(self):
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Create login frame
        self.login_frame = tk.Frame(self.root, bg="#f0f0f0")
        self.login_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Title
        title_label = tk.Label(self.login_frame, text="Secure Communication System", 
                              font=("Arial", 20, "bold"), bg="#f0f0f0")
        title_label.pack(pady=20)
        
        # Login box
        login_box = tk.Frame(self.login_frame, bg="#ffffff", bd=2, relief="raised",
                            padx=30, pady=30)
        login_box.pack(padx=20, pady=20)
        
        # Username
        username_label = tk.Label(login_box, text="User ID:", font=("Arial", 12), bg="#ffffff")
        username_label.grid(row=0, column=0, sticky="w", pady=10)
        
        self.username_entry = tk.Entry(login_box, font=("Arial", 12), width=25)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10)
        
        # Password
        password_label = tk.Label(login_box, text="Password:", font=("Arial", 12), bg="#ffffff")
        password_label.grid(row=1, column=0, sticky="w", pady=10)
        
        self.password_entry = tk.Entry(login_box, font=("Arial", 12), width=25, show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)
        
        # Login button
        login_button = tk.Button(login_box, text="LOGIN", font=("Arial", 12, "bold"), 
                               bg="#4a7abc", fg="white", width=15, height=1,
                               command=self.authenticate)
        login_button.grid(row=2, column=0, columnspan=2, pady=20)
        
        # Crypto status
        status_text = "Cryptography: " + ("Initialized" if self.crypto_initialized else "Error")
        status_color = "#4a7abc" if self.crypto_initialized else "#cc0000"
        crypto_status = tk.Label(self.login_frame, text=status_text, 
                               font=("Arial", 10), fg=status_color, bg="#f0f0f0")
        crypto_status.pack(pady=5)
    
    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Authentication Failed", "Please enter both ID and password")
            return
        
        if username in self.users and self.users[username]["password"] == password:
            self.current_user = username
            # Add to online users if not already there
            if username not in self.online_users:
                self.online_users.append(username)
            
            # Simulate other users being online randomly
            for user in self.users:
                if user != username and user not in self.online_users and random.choice([True, False]):
                    self.online_users.append(user)
            
            messagebox.showinfo("Authentication Successful", f"Welcome {self.users[username]['name']}!")
            self.show_main_interface()
        else:
            messagebox.showerror("Authentication Failed", "Invalid username or password")
    
    def show_main_interface(self):
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Create main frame
        self.main_frame = tk.Frame(self.root, bg="#f0f0f0")
        self.main_frame.pack(fill="both", expand=True)
        
        # Top bar with user info and logout
        top_bar = tk.Frame(self.main_frame, bg="#4a7abc", height=50)
        top_bar.pack(fill="x")
        
        user_label = tk.Label(top_bar, text=f"Logged in as: {self.users[self.current_user]['name']}", 
                             font=("Arial", 12), bg="#4a7abc", fg="white")
        user_label.pack(side="left", padx=20, pady=10)
        
        logout_button = tk.Button(top_bar, text="Logout", font=("Arial", 10), 
                                 bg="#f0f0f0", command=self.logout)
        logout_button.pack(side="right", padx=20, pady=10)
        
        # Main content area
        content_frame = tk.Frame(self.main_frame, bg="#f0f0f0")
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Left panel - User selection
        left_panel = tk.Frame(content_frame, bg="#ffffff", bd=1, relief="solid", width=300)
        left_panel.pack(side="left", fill="y", padx=10, pady=10)
        
        users_label = tk.Label(left_panel, text="Available Users", font=("Arial", 14, "bold"), 
                              bg="#4a7abc", fg="white")
        users_label.pack(fill="x", pady=1)
        
        # User list
        self.user_listbox = tk.Listbox(left_panel, font=("Arial", 12), height=15, 
                                      selectbackground="#4a7abc")
        self.user_listbox.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Populate user list with online users except current user
        for user in self.online_users:
            if user != self.current_user:
                self.user_listbox.insert(tk.END, f"{self.users[user]['name']} ({user})")
        
        # Select user button
        select_button = tk.Button(left_panel, text="Select User", font=("Arial", 12), 
                                 bg="#4a7abc", fg="white", command=self.select_user)
        select_button.pack(fill="x", padx=10, pady=10)
        
        # Encryption info
        if self.crypto_initialized:
            crypto_info = tk.Label(left_panel, text=f"Encryption: {len(self.methods)} layers", 
                                 font=("Arial", 10), bg="#ffffff")
            crypto_info.pack(pady=5)
        
        # Right panel - Communication area
        right_panel = tk.Frame(content_frame, bg="#ffffff", bd=1, relief="solid")
        right_panel.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        
        # Tabs for different interfaces
        self.tab_control = ttk.Notebook(right_panel)
        
        # Authentication tab
        self.auth_tab = tk.Frame(self.tab_control, bg="#ffffff")
        self.tab_control.add(self.auth_tab, text="Authentication")
        
        # Query tab
        self.query_tab = tk.Frame(self.tab_control, bg="#ffffff")
        self.tab_control.add(self.query_tab, text="Query")
        
        # Encryption tab
        self.encryption_tab = tk.Frame(self.tab_control, bg="#ffffff")
        self.tab_control.add(self.encryption_tab, text="Encryption")
        
        # Decryption tab
        self.decryption_tab = tk.Frame(self.tab_control, bg="#ffffff")
        self.tab_control.add(self.decryption_tab, text="Decryption")
        
        # Communication Log tab
        self.log_tab = tk.Frame(self.tab_control, bg="#ffffff")
        self.tab_control.add(self.log_tab, text="Communication Log")
        
        self.tab_control.pack(fill="both", expand=True)
        
        # Initialize tabs
        self.setup_auth_tab()
        self.setup_query_tab()
        self.setup_encryption_tab()
        self.setup_decryption_tab()
        self.setup_log_tab()
    
    def setup_auth_tab(self):
        # Authentication status display
        status_frame = tk.Frame(self.auth_tab, bg="#e6f0ff", bd=1, relief="solid")
        status_frame.place(relx=0.5, rely=0.3, anchor="center", width=400, height=150)
        
        self.auth_status_label = tk.Label(status_frame, text="No user selected", 
                                        font=("Arial", 14), bg="#e6f0ff")
        self.auth_status_label.pack(pady=20)
        
        # Authentication button
        self.auth_button = tk.Button(self.auth_tab, text="Authenticate Connection", 
                                   font=("Arial", 12), bg="#4a7abc", fg="white",
                                   state="disabled", command=self.authenticate_connection)
        self.auth_button.place(relx=0.5, rely=0.6, anchor="center")

        # Add buttons for CommanderGUI and TankGUI
        self.add_external_gui_buttons()
    def add_external_gui_buttons(self):
        """Add buttons to launch CommanderGUI and TankGUI."""
        external_gui_frame = tk.Frame(self.auth_tab, bg="#e6f0ff", bd=1, relief="solid")
        external_gui_frame.place(relx=0.5, rely=0.8, anchor="center", width=400, height=100)

        # Button to launch CommanderGUI
        commander_button = tk.Button(
            external_gui_frame, text="Open Commander GUI", font=("Arial", 12),
            bg="#4a7abc", fg="white", command=self.launch_commander_gui
        )
        commander_button.pack(side="left", padx=20, pady=10)

        # Button to launch TankGUI
        tank_button = tk.Button(
            external_gui_frame, text="Open Tank GUI", font=("Arial", 12),
            bg="#4a7abc", fg="white", command=self.launch_tank_gui
        )
        tank_button.pack(side="right", padx=20, pady=10)

    def launch_commander_gui(self):
        """Launch the Commander GUI in a new window."""
        commander_window = tk.Toplevel(self.root)
        commander_window.title("Commander Control Panel")
        commander_gui = CommanderGUI(commander_window)

    def launch_tank_gui(self):
        """Launch the Tank GUI in a new window."""
        tank_window = tk.Toplevel(self.root)
        tank_window.title("Tank Control Panel")
        tank_gui = TankGUI(tank_window)
        
    def setup_query_tab(self):
        # Query interface
        query_frame = tk.Frame(self.query_tab, bg="#e6f0ff", bd=1, relief="solid")
        query_frame.place(relx=0.5, rely=0.3, anchor="center", width=400, height=200)
        
        query_label = tk.Label(query_frame, text="Query User Status", 
                              font=("Arial", 14, "bold"), bg="#4a7abc", fg="white")
        query_label.pack(fill="x")
        
        self.query_status_label = tk.Label(query_frame, text="No user selected", 
                                         font=("Arial", 12), bg="#e6f0ff")
        self.query_status_label.pack(pady=20)
        
        # Query button
        self.query_button = tk.Button(self.query_tab, text="Send Query", 
                                    font=("Arial", 12), bg="#4a7abc", fg="white",
                                    state="disabled", command=self.send_query)
        self.query_button.place(relx=0.5, rely=0.6, anchor="center")
    
    def setup_encryption_tab(self):
        # Encryption interface
        encryption_frame = tk.Frame(self.encryption_tab, bg="#ffffff")
        encryption_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Message input
        message_label = tk.Label(encryption_frame, text="Enter Message to Encrypt:", 
                                font=("Arial", 12), bg="#ffffff")
        message_label.pack(anchor="w", pady=(0, 5))
        
        self.message_text = tk.Text(encryption_frame, height=5, width=40, font=("Arial", 11))
        self.message_text.pack(fill="x", pady=(0, 20))
        
        # Encryption method selection
        method_frame = tk.Frame(encryption_frame, bg="#ffffff")
        method_frame.pack(fill="x", pady=10)
        
        method_label = tk.Label(method_frame, text="Encryption Method:", 
                               font=("Arial", 12), bg="#ffffff")
        method_label.pack(side="left")
        
        self.method_var = tk.StringVar(value="Advanced")
        method_options = ttk.Combobox(method_frame, textvariable=self.method_var, 
                                     values=["Simple", "Advanced"], width=10, state="readonly")
        method_options.pack(side="left", padx=10)
        
        # Simple encryption level (only for Simple mode)
        level_frame = tk.Frame(encryption_frame, bg="#ffffff")
        level_frame.pack(fill="x", pady=10)
        
        level_label = tk.Label(level_frame, text="Simple Encryption Level:", 
                              font=("Arial", 12), bg="#ffffff")
        level_label.pack(side="left")
        
        self.level_var = tk.StringVar(value="1")
        level_options = ttk.Combobox(level_frame, textvariable=self.level_var, 
                                    values=["1", "2", "3", "4", "5"], width=5)
        level_options.pack(side="left", padx=10)
        
        # Advanced encryption info (only for Advanced mode)
        if self.crypto_initialized:
            adv_frame = tk.Frame(encryption_frame, bg="#e6f0ff", bd=1, relief="solid")
            adv_frame.pack(fill="x", pady=10)
            
            sequence_text = f"Using {len(self.methods)} layer encryption: {' → '.join(self.methods)}"
            sequence_label = tk.Label(adv_frame, text=sequence_text, 
                                    font=("Arial", 10), bg="#e6f0ff", wraplength=400)
            sequence_label.pack(pady=5)
        
        # Encrypt button
        self.encrypt_button = tk.Button(encryption_frame, text="Encrypt & Send", 
                                      font=("Arial", 12), bg="#4a7abc", fg="white",
                                      state="disabled", command=self.encrypt_and_send)
        self.encrypt_button.pack(pady=20)
        
        # Result display
        result_label = tk.Label(encryption_frame, text="Encrypted Message:", 
                               font=("Arial", 12), bg="#ffffff")
        result_label.pack(anchor="w", pady=(20, 5))
        
        self.encrypted_result = tk.Text(encryption_frame, height=5, width=40, 
                                      font=("Arial", 11), state="disabled")
        self.encrypted_result.pack(fill="x")
    
    def setup_decryption_tab(self):
        # Decryption interface
        decryption_frame = tk.Frame(self.decryption_tab, bg="#ffffff")
        decryption_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Received message display
        received_label = tk.Label(decryption_frame, text="Received Encrypted Message:", 
                                 font=("Arial", 12), bg="#ffffff")
        received_label.pack(anchor="w", pady=(0, 5))
        
        self.received_text = tk.Text(decryption_frame, height=5, width=40, 
                                    font=("Arial", 11), state="disabled")
        self.received_text.pack(fill="x", pady=(0, 20))
        
        # Decryption method selection
        method_frame = tk.Frame(decryption_frame, bg="#ffffff")
        method_frame.pack(fill="x", pady=10)
        
        method_label = tk.Label(method_frame, text="Decryption Method:", 
                               font=("Arial", 12), bg="#ffffff")
        method_label.pack(side="left")
        
        self.decrypt_method_var = tk.StringVar(value="Advanced")
        decrypt_method_options = ttk.Combobox(method_frame, textvariable=self.decrypt_method_var, 
                                            values=["Simple", "Advanced"], width=10, state="readonly")
        decrypt_method_options.pack(side="left", padx=10)
        
        # Simple decryption level (only for Simple mode)
        level_frame = tk.Frame(decryption_frame, bg="#ffffff")
        level_frame.pack(fill="x", pady=10)
        
        level_label = tk.Label(level_frame, text="Simple Decryption Level:", 
                              font=("Arial", 12), bg="#ffffff")
        level_label.pack(side="left")
        
        self.decrypt_level_var = tk.StringVar(value="1")
        decrypt_level_options = ttk.Combobox(level_frame, textvariable=self.decrypt_level_var, 
                                           values=["1", "2", "3", "4", "5"], width=5)
        decrypt_level_options.pack(side="left", padx=10)
        
        # Decrypt button
        self.decrypt_button = tk.Button(decryption_frame, text="Decrypt Message", 
                                      font=("Arial", 12), bg="#4a7abc", fg="white",
                                      state="disabled", command=self.decrypt_message)
        self.decrypt_button.pack(pady=20)
        
        # Result display
        decrypted_label = tk.Label(decryption_frame, text="Decrypted Message:", 
                                  font=("Arial", 12), bg="#ffffff")
        decrypted_label.pack(anchor="w", pady=(20, 5))
        
        self.decrypted_result = tk.Text(decryption_frame, height=5, width=40, 
                                      font=("Arial", 11), state="disabled")
        self.decrypted_result.pack(fill="x")
        
        # Signature verification status
        self.signature_status = tk.Label(decryption_frame, text="", 
                                       font=("Arial", 10), bg="#ffffff")
        self.signature_status.pack(pady=5)
    
    def setup_log_tab(self):
        # Communication log interface
        log_frame = tk.Frame(self.log_tab, bg="#ffffff")
        log_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        log_label = tk.Label(log_frame, text="Communication Log", 
                            font=("Arial", 14, "bold"), bg="#4a7abc", fg="white")
        log_label.pack(fill="x")
        
        # Log display
        self.log_display = tk.Text(log_frame, height=20, width=60, 
                                  font=("Arial", 11), state="disabled")
        self.log_display.pack(fill="both", expand=True, pady=10)
        
        # Scrollbar
        scrollbar = tk.Scrollbar(self.log_display)
        scrollbar.pack(side="right", fill="y")
        
        self.log_display.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.log_display.yview)
        
        # Refresh button
        refresh_button = tk.Button(log_frame, text="Refresh Log", 
                                  font=("Arial", 12), bg="#4a7abc", fg="white",
                                  command=self.refresh_log)
        refresh_button.pack(pady=10)
    
    def select_user(self):
        selection = self.user_listbox.curselection()
        if not selection:
            messagebox.showinfo("Selection Required", "Please select a user to communicate with")
            return
        
        selected_item = self.user_listbox.get(selection[0])
        # Extract username from format "Name (username)"
        username = selected_item.split("(")[1].strip(")")
        self.selected_recipient = username
        
        # Update authentication tab
        self.auth_status_label.config(text=f"Selected User: {self.users[username]['name']}")
        self.auth_button.config(state="normal")
        
        # Update query tab
        self.query_status_label.config(text=f"Selected User: {self.users[username]['name']}\nStatus: Not Queried")
        self.query_button.config(state="normal")
        
        # Reset encryption/decryption tabs
        self.message_text.delete("1.0", tk.END)
        self.encrypted_result.config(state="normal")
        self.encrypted_result.delete("1.0", tk.END)
        self.encrypted_result.config(state="disabled")
        
        self.received_text.config(state="normal")
        self.received_text.delete("1.0", tk.END)
        self.received_text.config(state="disabled")
        
        self.decrypted_result.config(state="normal")
        self.decrypted_result.delete("1.0", tk.END)
        self.decrypted_result.config(state="disabled")
        
        # Reset signature status
        self.signature_status.config(text="")
        
        # Enable encryption button
        self.encrypt_button.config(state="normal")
        
        # Add to log
        self.add_to_log(f"Selected user {self.users[username]['name']} for communication")
    
    def authenticate_connection(self):
        if not self.selected_recipient:
            return
        
        # Simulate authentication process
        self.auth_status_label.config(text="Authenticating...")
        self.root.update()
        self.root.after(1000)  # Simulate delay
        
        # Generate a digital signature for authentication
        if self.crypto_initialized:
            try:
                auth_message = f"AUTH:{self.current_user}:{self.selected_recipient}:{datetime.now().isoformat()}"
                signature = generate_signature(auth_message, self.private_key_rsa)
                auth_success = True
                auth_details = f"\nSecured with RSA digital signature"
            except Exception as e:
                print(f"Authentication error: {e}")
                auth_success = False
                auth_details = "\nError in cryptographic authentication"
        else:
            auth_success = True
            auth_details = "\nSimulated authentication (crypto not initialized)"
        
        # Authentication success
        if auth_success:
            self.auth_status_label.config(
                text=f"Authentication Successful!\nSecure connection established with {self.users[self.selected_recipient]['name']}{auth_details}")
        else:
            self.auth_status_label.config(
                text=f"Authentication Failed!{auth_details}")
        
        # Add to log
        self.add_to_log(f"Authenticated connection with {self.users[self.selected_recipient]['name']}")
    
    def send_query(self):
        if not self.selected_recipient:
            return
        
        # Simulate query process
        self.query_status_label.config(text="Querying user status...")
        self.root.update()
        self.root.after(1000)  # Simulate delay
        
        # Random status
        status_options = ["Online", "Available", "Busy", "Away"]
        status = random.choice(status_options)
        
        # Update status
        self.query_status_label.config(
            text=f"Selected User: {self.users[self.selected_recipient]['name']}\nStatus: {status}")
        
        # Add to log
        self.add_to_log(f"Queried {self.users[self.selected_recipient]['name']} - Status: {status}")
    
    def encrypt_and_send(self):
        if not self.selected_recipient:
            return
        
        message = self.message_text.get("1.0", "end-1c")
        if not message:
            messagebox.showwarning("Input Required", "Please enter a message to encrypt")
            return
        
        encryption_method = self.method_var.get()
        
        if encryption_method == "Simple":
            # Simple Caesar cipher
            level = int(self.level_var.get())
            encrypted = self.caesar_cipher(message, level)
            encrypted_display = encrypted
            
            # Store encryption info for decryption
            self.last_encryption = {
                "method": "Simple",
                "level": level,
                "data": encrypted,
                "original": message
            }
            
            encryption_details = f"Simple encryption (Caesar cipher, level {level})"
        else:
            # Advanced multi-layer encryption
            if self.crypto_initialized:
                try:
                    # Generate digital signature
                    signature = generate_signature(message, self.private_key_rsa)
                    
                    # Encrypt the message
                    ivs, encrypted_data, tags = encrypt_data(
                        message, self.methods, self.key_aes, self.key_des, 
                        self.key_tdes, self.public_key_rsa, self.public_key_ecc
                    )
                    
                    # Store encryption info for decryption
                    self.last_encryption = {
                        "method": "Advanced",
                        "ivs": ivs,
                        "data": encrypted_data,
                        "tags": tags,
                        "signature": signature,
                        "original": message
                    }
                    
                    # For display, show a truncated version
                    if len(encrypted_data) > 100:
                        encrypted_display = encrypted_data[:100] + "..."
                    else:
                        encrypted_display = encrypted_data
                    
                    encryption_details = f"Advanced encryption ({len(self.methods)} layers: {' → '.join(self.methods)})"
                except Exception as e:
                    print(f"Encryption error: {e}")
                    messagebox.showerror("Encryption Error", f"Failed to encrypt message: {str(e)}")
                    return
            else:
                messagebox.showwarning("Crypto Not Initialized", 
                                     "Advanced encryption is not available. Using simple encryption instead.")
                # Fall back to simple encryption
                level = int(self.level_var.get())
                encrypted = self.caesar_cipher(message, level)
                encrypted_display = encrypted
                
                # Store encryption info for decryption
                self.last_encryption = {
                    "method": "Simple",
                    "level": level,
                    "data": encrypted,
                    "original": message
                }
                
                encryption_details = f"Simple encryption (Caesar cipher, level {level})"
        
        # Display encrypted message
        self.encrypted_result.config(state="normal")
        self.encrypted_result.delete("1.0", tk.END)
        self.encrypted_result.insert("1.0", encrypted_display)
        self.encrypted_result.config(state="disabled")
        
        # Simulate sending
        messagebox.showinfo("Message Sent", 
                          f"Encrypted message sent to {self.users[self.selected_recipient]['name']}\n\n{encryption_details}")
        
        # Add to log
        self.add_to_log(f"Sent encrypted message to {self.users[self.selected_recipient]['name']} using {encryption_details}")
        
        # Simulate receiving on decryption tab
        self.received_text.config(state="normal")
        self.received_text.delete("1.0", tk.END)
        self.received_text.insert("1.0", encrypted_display)
        self.received_text.config(state="disabled")
        
        # Enable decrypt button
        self.decrypt_button.config(state="normal")
        
        # Set the same method for decryption
        self.decrypt_method_var.set(encryption_method)
        if encryption_method == "Simple":
            self.decrypt_level_var.set(str(self.level_var.get()))
    
    def decrypt_message(self):
        if not hasattr(self, 'last_encryption'):
            messagebox.showwarning("No Message", "No encrypted message to decrypt")
            return
        
        decryption_method = self.decrypt_method_var.get()
        
        if decryption_method == "Simple":
            # Simple Caesar cipher decryption
            level = int(self.decrypt_level_var.get())
            
            if self.last_encryption["method"] == "Simple":
                encrypted = self.last_encryption["data"]
                decrypted = self.caesar_decipher(encrypted, level)
                
                # Check if decryption was successful
                if decrypted == self.last_encryption["original"]:
                    verification_status = "Decryption successful!"
                    verification_color = "green"
                else:
                    verification_status = "Warning: Decryption may be incorrect (wrong level?)"
                    verification_color = "orange"
            else:
                # Trying to decrypt advanced encryption with simple method
                decrypted = "ERROR: Cannot decrypt advanced encryption with simple method"
                verification_status = "Decryption failed: Method mismatch"
                verification_color = "red"
        else:
            # Advanced multi-layer decryption
            if self.crypto_initialized and self.last_encryption["method"] == "Advanced":
                try:
                    # Decrypt the message
                    decrypted = decrypt_data(
                        self.last_encryption["ivs"], 
                        self.last_encryption["data"], 
                        self.last_encryption["tags"], 
                        self.methods, 
                        self.key_aes, self.key_des, self.key_tdes, 
                        self.private_key_rsa, self.private_key_ecc
                    )
                    
                    # Verify digital signature
                    is_valid = verify_signature(
                        decrypted, 
                        self.last_encryption["signature"], 
                        self.public_key_rsa
                    )
                    
                    if is_valid:
                        verification_status = "Digital signature verified: Message integrity confirmed"
                        verification_color = "green"
                    else:
                        verification_status = "WARNING: Digital signature verification failed!"
                        verification_color = "red"
                except Exception as e:
                    print(f"Decryption error: {e}")
                    decrypted = f"ERROR: Failed to decrypt message: {str(e)}"
                    verification_status = "Decryption failed due to an error"
                    verification_color = "red"
            elif self.last_encryption["method"] == "Simple":
                # Trying to decrypt simple encryption with advanced method
                decrypted = "ERROR: Cannot decrypt simple encryption with advanced method"
                verification_status = "Decryption failed: Method mismatch"
                verification_color = "red"
            else:
                decrypted = "ERROR: Cryptography not initialized"
                verification_status = "Decryption failed: Crypto not initialized"
                verification_color = "red"
        
        # Display decrypted message
        self.decrypted_result.config(state="normal")
        self.decrypted_result.delete("1.0", tk.END)
        self.decrypted_result.insert("1.0", decrypted)
        self.decrypted_result.config(state="disabled")
        
        # Update signature verification status
        self.signature_status.config(text=verification_status, fg=verification_color)
        
        # Add to log
        self.add_to_log(f"Decrypted message from {self.users[self.selected_recipient]['name']} using {decryption_method} method")
    
    def caesar_cipher(self, text, shift):
        """Simple Caesar cipher for demonstration"""
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = ord('a') if char.islower() else ord('A')
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return result
    
    def caesar_decipher(self, text, shift):
        """Reverse Caesar cipher"""
        return self.caesar_cipher(text, 26 - shift)
    
    def add_to_log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.communication_log.append(log_entry)
        
        # Update log display
        self.refresh_log()
    
    def refresh_log(self):
        self.log_display.config(state="normal")
        self.log_display.delete("1.0", tk.END)
        for entry in self.communication_log:
            self.log_display.insert(tk.END, entry)
        self.log_display.config(state="disabled")
        
        # Auto-scroll to bottom
        self.log_display.see(tk.END)
    
    def logout(self):
        # Remove from online users
        if self.current_user in self.online_users:
            self.online_users.remove(self.current_user)
        
        self.current_user = None
        self.selected_recipient = None
        
        # Return to login screen
        self.show_login_screen()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureCommunicationSystem(root)
    root.mainloop()