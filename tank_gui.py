import tkinter as tk
from tkinter import scrolledtext
from tank import Tank

class TankGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Tank Control Panel")

        tk.Label(root, text="Tank ID:").grid(row=0, column=0)
        self.tank_entry = tk.Entry(root)
        self.tank_entry.grid(row=0, column=1)

        tk.Label(root, text="Challenge Number:").grid(row=1, column=0)
        self.challenge_entry = tk.Entry(root)
        self.challenge_entry.grid(row=1, column=1)

        tk.Button(root, text="Respond to Challenge", command=self.respond).grid(row=2, column=0, columnspan=2, pady=5)

        self.text_area = scrolledtext.ScrolledText(root, width=60, height=20)
        self.text_area.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    def respond(self):
        tank_id = int(self.tank_entry.get())
        challenge = int(self.challenge_entry.get())
        tank = Tank(tank_id)
        response = tank.respond_to_challenge(challenge)
        self.text_area.insert(tk.END, f"🚀 Tank {tank_id} responded: {response}\n")

if __name__ == "__main__":
    root = tk.Tk()
    gui = TankGUI(root)
    root.mainloop()
