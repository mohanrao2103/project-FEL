import tkinter as tk
from tkinter import scrolledtext
import threading  # Added for timer functionality
import time  # Added for timer functionality
from commandar import Commander

class CommanderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Commander Control Panel")
        self.commander = Commander()

        # Send Challenges Button
        tk.Button(root, text="Send Challenges", command=self.send_challenges).grid(row=0, column=0, columnspan=2, pady=5)

        # Verification Section
        tk.Label(root, text="Tank ID (Verify):").grid(row=1, column=0)
        self.verify_entry = tk.Entry(root)
        self.verify_entry.grid(row=1, column=1)

        tk.Label(root, text="Response:").grid(row=2, column=0)
        self.response_entry = tk.Entry(root)
        self.response_entry.grid(row=2, column=1)

        tk.Button(root, text="Verify Response", command=self.verify_response).grid(row=3, column=0, columnspan=2, pady=5)

        # Output Area
        self.text_area = scrolledtext.ScrolledText(root, width=60, height=20)
        self.text_area.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

        # Tank Status Sidebar
        self.tank_status = {}
        tk.Label(root, text="Tanks:").grid(row=0, column=2, padx=10)
        for i in range(1, 6):
            self.tank_status[i] = tk.Label(root, text=f"Tank {i}", bg="white", width=15)
            self.tank_status[i].grid(row=i, column=2, padx=10, pady=2)

        # Timer Configuration
        tk.Label(root, text="Set Timer (s):").grid(row=5, column=0)
        self.timer_entry = tk.Entry(root)
        self.timer_entry.insert(0, "10")  # Default timer value
        self.timer_entry.grid(row=5, column=1)

        # Timer Display
        self.timer_label = tk.Label(root, text="Timer: --s")
        self.timer_label.grid(row=6, column=0, columnspan=2)

    def log(self, message):
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.see(tk.END)

    def send_challenges(self):
        timer_value = int(self.timer_entry.get())
        self.commander.response_time = timer_value

        messages = self.commander.send_challenges()
        for msg in messages:
            self.log(msg)
        for i in range(1, 6):
            self.tank_status[i].config(bg="white")

        # Start the countdown
        threading.Thread(target=self.countdown, args=(timer_value,), daemon=True).start()

    def countdown(self, time_limit):
        for i in range(time_limit, 0, -1):
            self.timer_label.config(text=f"Timer: {i}s")
            time.sleep(1)
        self.timer_label.config(text="⏳ Timer expired!")

        # Log unresponsive tanks
        self.log("⌛ Time's up! Final responses:")

        # Check if 'responses' attribute exists in Commander
        if hasattr(self.commander, 'responses'):
            self.log(str(self.commander.responses))
            # Mark unresponsive tanks as yellow
            for tank_id in self.tank_status:
                if tank_id not in self.commander.responses or not self.commander.responses[tank_id]:
                    self.tank_status[tank_id].config(bg="yellow")
        else:
            self.log("⚠️ No responses attribute found in Commander.")

    def verify_response(self):
        tank_id = int(self.verify_entry.get())
        response = self.response_entry.get()
        success, message = self.commander.verify_response(tank_id, response)
        self.log(message)
        self.tank_status[tank_id].config(bg="green" if success else "red")

if __name__ == "__main__":
    root = tk.Tk()
    gui = CommanderGUI(root)
    root.mainloop()