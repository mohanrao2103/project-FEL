import csv
import hashlib
from tkinter import messagebox
import tkinter as tk
from server4a import CommanderGUI  # Import the TankClientGUI class

CSV_FILE = 'server_credentials.csv'

class SystemAuthGUI:
    def __init__(self, root, on_login_success):
        self.root = root
        self.on_login_success = on_login_success
        self.root.title("Commander Authentication")
        self.root.geometry("800x600")
        self.show_login_screen()

    def show_login_screen(self) -> None:
        for widget in self.root.winfo_children():
            widget.destroy()
        
        login_frame = tk.Frame(self.root, bg="#f0f0f0")
        login_frame.place(relx=0.5, rely=0.5, anchor="center")

        login_box = tk.Frame(login_frame, bg="#ffffff", bd=2, relief="raised", padx=30, pady=30)
        login_box.pack(padx=20, pady=20)

        login_button = tk.Button(login_box, text="LOGIN", font=("Arial", 12, "bold"), bg="#2196F3", fg="white", width=15, height=2, command=self.show_login_window)
        login_button.grid(row=0, column=0, pady=10, padx=5)

        signup_button = tk.Button(login_box, text="SIGNUP", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", width=15, height=2, command=self.show_signup_window)
        signup_button.grid(row=0, column=1, pady=10, padx=5)

    def show_login_window(self) -> None:
        for widget in self.root.winfo_children():
            widget.destroy()

        frame = tk.Frame(self.root, padx=20, pady=10)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(frame, text="Username:", font=('Arial', 10, 'bold')).pack(pady=5)
        username_entry = tk.Entry(frame)
        username_entry.pack(pady=5)

        tk.Label(frame, text="Password:", font=('Arial', 10, 'bold')).pack(pady=5)
        password_entry = tk.Entry(frame, show="*")
        password_entry.pack(pady=5)

        def login():
            username = username_entry.get()
            password = password_entry.get()
            if self.verify_login(username, password):
                self.on_login_success("tank", username)  # Call the callback
            else:
                messagebox.showerror("Login Failed", "Invalid username or password.")

        tk.Button(frame, text="Login", command=login, bg="#2196F3", fg="white", font=("Arial", 10, "bold")).pack(pady=10)

    def show_signup_window(self) -> None:
        for widget in self.root.winfo_children():
            widget.destroy()

        frame = tk.Frame(self.root, padx=20, pady=10)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(frame, text="Username:", font=('Arial', 10, 'bold')).pack(pady=5)
        username_entry = tk.Entry(frame)
        username_entry.pack(pady=5)

        tk.Label(frame, text="Password:", font=('Arial', 10, 'bold')).pack(pady=5)
        password_entry = tk.Entry(frame, show="*")
        password_entry.pack(pady=5)

        def signup():
            username = username_entry.get()
            password = password_entry.get()
            if self.username_exists(username):
                messagebox.showerror("Signup Failed", "Username already exists.")
            else:
                self.store_credentials(username, password)
                messagebox.showinfo("Signup Successful", "Account created successfully!")
                self.show_login_screen()

        tk.Button(frame, text="Signup", command=signup, bg="#4CAF50", fg="white", font=("Arial", 10, "bold")).pack(pady=10)

    def username_exists(self, username: str) -> bool:
        try:
            with open(CSV_FILE, 'r') as file:
                reader = csv.reader(file)
                for row in reader:
                    if row[0] == username:
                        return True
        except FileNotFoundError:
            pass
        return False

    def store_credentials(self, username: str, password: str) -> None:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        with open(CSV_FILE, 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([username, hashed_password])

    def verify_login(self, username: str, password: str) -> bool:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        try:
            with open(CSV_FILE, 'r') as file:
                reader = csv.reader(file)
                for row in reader:
                    if row[0] == username and row[1] == hashed_password:
                        return True
        except FileNotFoundError:
            pass
        return False


if __name__ == "__main__":
    def on_login_success(user_type, username):
        root.destroy()  # Close the login window
        tank_root = tk.Tk()
        CommanderGUI(tank_root)  # Launch the CommanderGUI
        tank_root.mainloop()

    root = tk.Tk()
    app = SystemAuthGUI(root, on_login_success)
    root.mainloop()