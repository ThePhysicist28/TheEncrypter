import numpy as np
from scipy.integrate import solve_ivp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import Menu, Text, Scrollbar
import base64
import json

# Constants
G = 1  # Simplified gravitational constant

# Differential equation for the 3-body problem
def three_body_equations(t, y, masses):
    positions = y[:6].reshape(3, 2)
    velocities = y[6:].reshape(3, 2)
    dydt = np.zeros_like(y)
    dydt[:6] = velocities.flatten()
    for i in range(3):
        force = np.zeros(2)
        for j in range(3):
            if i != j:
                r = positions[j] - positions[i]
                distance = np.linalg.norm(r)
                force += G * masses[j] * r / distance**3
        dydt[6 + 2 * i:8 + 2 * i] = force
    return dydt

# Simulate the 3-body problem with given initial conditions
def simulate_3_body_problem(timesteps, dt, positions, velocities, masses):
    y0 = np.hstack((positions.flatten(), velocities.flatten()))
    t_span = (0, timesteps * dt)
    t_eval = np.linspace(*t_span, timesteps)
    
    sol = solve_ivp(three_body_equations, t_span, y0, t_eval=t_eval, args=(masses,), method='RK45')
    
    return sol.y[:6].reshape(3, 2, -1), sol.t

# Generate a key from simulation data
def generate_key(positions, velocities, masses, timesteps, dt):
    simulation_data, _ = simulate_3_body_problem(timesteps, dt, positions, velocities, masses)
    key_material = ''.join([f"{int(coord * 1000):03d}" for pos in simulation_data[:, :, -1] for coord in pos])
    key = key_material[:16].encode('utf-8')  # Ensure the key is 16 bytes
    return key

# Encrypt and decrypt messages
def encrypt_message(positions, velocities, masses, timesteps, dt, message):
    key = generate_key(positions, velocities, masses, timesteps, dt)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_message = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    encrypted_message_b64 = base64.b64encode(encrypted_message).decode('utf-8')
    initial_conditions = {
        'positions': positions.tolist(),
        'velocities': velocities.tolist(),
        'masses': masses.tolist(),
        'timesteps': timesteps,
        'dt': dt
    }
    result = json.dumps({
        'encrypted_message': encrypted_message_b64,
        'initial_conditions': initial_conditions
    })
    return result

def decrypt_message(encrypted_data):
    data = json.loads(encrypted_data)
    encrypted_message = base64.b64decode(data['encrypted_message'])
    initial_conditions = data['initial_conditions']
    positions = np.array(initial_conditions['positions'])
    velocities = np.array(initial_conditions['velocities'])
    masses = np.array(initial_conditions['masses'])
    timesteps = initial_conditions['timesteps']
    dt = initial_conditions['dt']

    key = generate_key(positions, velocities, masses, timesteps, dt)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)
    return decrypted_message.decode('utf-8')

# GUI Application
class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("TheEncrypter")
        
        self.create_widgets()
        self.create_menu()
        
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

    def create_widgets(self):
        self.message_label = tk.Label(self.root, text="Message:")
        self.message_label.grid(row=0, column=0, sticky='nw')
        
        self.message_text = Text(self.root, wrap='word', height=5)
        self.message_text.grid(row=0, column=1, sticky='nsew')
        self.message_scroll = Scrollbar(self.root, command=self.message_text.yview)
        self.message_scroll.grid(row=0, column=2, sticky='nse')
        self.message_text.config(yscrollcommand=self.message_scroll.set)

        self.encrypt_button = tk.Button(self.root, text="Encrypt", command=self.encrypt_message)
        self.encrypt_button.grid(row=1, column=0, pady=5)
        
        self.decrypt_button = tk.Button(self.root, text="Decrypt", command=self.decrypt_message)
        self.decrypt_button.grid(row=1, column=1, pady=5)

        self.result_label = tk.Label(self.root, text="Result:")
        self.result_label.grid(row=2, column=0, sticky='nw')
        
        self.result_text = Text(self.root, wrap='word', height=10)
        self.result_text.grid(row=2, column=1, sticky='nsew')
        self.result_scroll = Scrollbar(self.root, command=self.result_text.yview)
        self.result_scroll.grid(row=2, column=2, sticky='nse')
        self.result_text.config(yscrollcommand=self.result_scroll.set)
        
    def create_menu(self):
        self.menu = Menu(self.root)
        self.root.config(menu=self.menu)
        
        self.edit_menu = Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Edit", menu=self.edit_menu)
        self.edit_menu.add_command(label="Cut", command=lambda: self.cut_text())
        self.edit_menu.add_command(label="Copy", command=lambda: self.copy_text())
        self.edit_menu.add_command(label="Paste", command=lambda: self.paste_text())

    def cut_text(self):
        try:
            selected_text = self.get_selected_text()
            if selected_text:
                self.root.clipboard_clear()
                self.root.clipboard_append(selected_text)
                self.delete_selected_text()
        except tk.TclError:
            pass

    def copy_text(self):
        try:
            selected_text = self.get_selected_text()
            if selected_text:
                self.root.clipboard_clear()
                self.root.clipboard_append(selected_text)
        except tk.TclError:
            pass

    def paste_text(self):
        try:
            cursor_position = self.message_text.index(tk.INSERT)
            clipboard_text = self.root.clipboard_get()
            self.message_text.insert(cursor_position, clipboard_text)
        except tk.TclError:
            pass

    def get_selected_text(self):
        try:
            if self.message_text.tag_ranges(tk.SEL):
                return self.message_text.get(tk.SEL_FIRST, tk.SEL_LAST)
            if self.result_text.tag_ranges(tk.SEL):
                return self.result_text.get(tk.SEL_FIRST, tk.SEL_LAST)
        except tk.TclError:
            return None

    def delete_selected_text(self):
        try:
            if self.message_text.tag_ranges(tk.SEL):
                self.message_text.delete(tk.SEL_FIRST, tk.SEL_LAST)
            if self.result_text.tag_ranges(tk.SEL):
                self.result_text.delete(tk.SEL_FIRST, tk.SEL_LAST)
        except tk.TclError:
            pass

    def encrypt_message(self):
        message = self.message_text.get("1.0", tk.END).strip()
        timesteps = 1000
        dt = 0.01
        positions = np.random.rand(3, 2)
        velocities = np.random.rand(3, 2)
        masses = np.random.rand(3)
        encrypted_message = encrypt_message(positions, velocities, masses, timesteps, dt, message)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, encrypted_message)

    def decrypt_message(self):
        encrypted_data = self.result_text.get("1.0", tk.END).strip()
        decrypted_message = decrypt_message(encrypted_data)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, decrypted_message)

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
#Made BY SUPRIT AMBASTA
