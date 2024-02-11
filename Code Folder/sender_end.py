import socket
import hashlib
import os
import sys
from cryptography.fernet import Fernet
import time
import tkinter as tk
from tkinter import filedialog

# Provided encryption key
key = b'dtWMFIEe4S4l_5voF5SdwLfbT4RlRTMJ6yJz5LcQZUk='

# Step 1: Encrypt data
def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)
    return encrypted_data

# Step 3: Calculate hash
def calculate_hash(data):
    hash_obj = hashlib.blake2b(data)
    return hash_obj.hexdigest()

# Step 4: Calculate transmission time
def calculate_transmission_time(start_time, end_time):
    return end_time - start_time

# Function to send data or file
def send_data_or_file(choice, data_entry, file_path_var):
    if choice == "data":
        data_to_send = data_entry.get().encode('utf-8')
    elif choice == "file":
        file_path = file_path_var.get()
        with open(file_path, 'rb') as file:
            data_to_send = file.read()
    else:
        return None

    host = '192.168.79.1'
    port = 1234

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        encrypted_data = encrypt_data(data_to_send, key)
        s.send(encrypted_data)

        hash_value = calculate_hash(encrypted_data)
        start_time = time.time()

        end_time = time.time()
        transmission_time = calculate_transmission_time(start_time, end_time)

        return {
            "Original Data or File": data_entry.get() if choice == "data" else file_path_var.get(),
            "Encrypted Data": encrypted_data.decode('utf-8'),
            "Hash Value": hash_value,
            "Transmission Time": transmission_time
        }

# Create the main GUI window
window = tk.Tk()
window.title("Data/File Transfer")
window.geometry("400x250")

# Variable to store the user's choice
choice_var = tk.StringVar()

# Function to close the program
def close_program():
    window.destroy()

# Function to process the user's choice
def process_choice():
    choice = choice_var.get()
    if choice == "data_at_rest":
        create_data_at_rest_window()
        window.withdraw()  # Hide the main window
    elif choice == "data_in_transit":
        create_data_in_transit_window()
        window.withdraw()  # Hide the main window
    elif choice == "Nothing":
        result_label.config(text="Use me next time.")
        window.after(500, close_program)

# GUI elements for the main window
main_label = tk.Label(window, text="Choose an option:")
data_at_rest_radio = tk.Radiobutton(window, text="Data at Rest", variable=choice_var, value="data_at_rest")
data_in_transit_radio = tk.Radiobutton(window, text="Data in Transit", variable=choice_var, value="data_in_transit")
nothing_radio = tk.Radiobutton(window, text="Nothing", variable=choice_var, value="Nothing")
process_button = tk.Button(window, text="Choose", command=process_choice)
result_label = tk.Label(window, text="")

# Layout for the main window
main_label.grid(row=0, column=0, padx=10, pady=5)
data_at_rest_radio.grid(row=1, column=0, padx=10, pady=5, sticky='w')
data_in_transit_radio.grid(row=2, column=0, padx=10, pady=5, sticky='w')
nothing_radio.grid(row=3, column=0, padx=10, pady=5, sticky='w')
process_button.grid(row=4, column=0, padx=10, pady=10)
result_label.grid(row=5, column=0, padx=10, pady=5, sticky='w')

# Function to create the "Data in Transit" window
def create_data_in_transit_window():
    data_in_transit_window = tk.Toplevel(window)
    data_in_transit_window.title("Data in Transit")
    data_in_transit_window.geometry("800x400")

    # Variable to store the user's choice for data or file
    data_in_transit_choice_var = tk.StringVar()

    # Function to send the data or file
    def send_data_in_transit():
        choice = data_in_transit_choice_var.get()
        data_in_transit_result = send_data_or_file(choice, data_in_transit_data_entry, data_in_transit_file_path_var)

        if data_in_transit_result:
            display_result(data_in_transit_result)

    def display_result(result):
        result_window = tk.Toplevel(data_in_transit_window)
        result_window.title("Result")
        
        # Maximize the result window based on the platform
        if sys.platform == 'win32':
            result_window.state('zoomed')
        elif sys.platform == 'darwin':
            result_window.attributes('-zoomed', 1)
        else:
            result_window.attributes('-zoomed', True)
        
        result_text = tk.Text(result_window, wrap=tk.WORD, height=30, width=100)
        result_text.insert(tk.END, f"Original Data or File: {result['Original Data or File']}\n\n")
        result_text.insert(tk.END, f"Encrypted Data: {result['Encrypted Data']}\n")
        result_text.insert(tk.END, f"Hash Value: {result['Hash Value']}\n")
        result_text.insert(tk.END, f"Transmission Time: {result['Transmission Time']} seconds\n")
        result_text.pack(fill=tk.BOTH, expand=True)

        back_button = tk.Button(result_window, text="Back", command=lambda: back_to_data_in_transit_window(result_window))
        back_button.pack()

        result_window.mainloop()  # Start the result window's main loop

    def back_to_data_in_transit_window(result_window):
        result_window.destroy()  # Close the result window
        data_in_transit_window.deiconify()  # Show the "Data in Transit" window again

    back_button = tk.Button(data_in_transit_window, text="Back", command=lambda: back_to_main_window(data_in_transit_window))
    back_button.grid(row=8, column=0, padx=10, pady=10)

    # GUI elements for the "Data in Transit" window
    data_in_transit_label = tk.Label(data_in_transit_window, text="Choose an option for Data in Transit:")
    data_in_transit_data_radio = tk.Radiobutton(data_in_transit_window, text="Data", variable=data_in_transit_choice_var, value="data")
    data_in_transit_file_radio = tk.Radiobutton(data_in_transit_window, text="File", variable=data_in_transit_choice_var, value="file")
    data_in_transit_data_label = tk.Label(data_in_transit_window, text="Enter Data:")
    data_in_transit_data_entry = tk.Entry(data_in_transit_window, width=30)
    data_in_transit_file_label = tk.Label(data_in_transit_window, text="Select File:")
    data_in_transit_file_path_var = tk.StringVar()
    data_in_transit_file_path_entry = tk.Entry(data_in_transit_window, textvariable=data_in_transit_file_path_var, width=30)
    data_in_transit_file_path_entry.insert(0, "")

    data_in_transit_browse_button = tk.Button(data_in_transit_window, text="Browse", command=lambda: data_in_transit_file_path_var.set(filedialog.askopenfilename()))
    data_in_transit_send_button = tk.Button(data_in_transit_window, text="Send", command=send_data_in_transit)

    # Layout for the "Data in Transit" window
    data_in_transit_label.grid(row=0, column=0, padx=10, pady=5)
    data_in_transit_data_radio.grid(row=1, column=0, padx=10, pady=5, sticky='w')
    data_in_transit_file_radio.grid(row=2, column=0, padx=10, pady=5, sticky='w')
    data_in_transit_data_label.grid(row=3, column=0, padx=10, pady=5, sticky='w')
    data_in_transit_data_entry.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky='w')
    data_in_transit_file_label.grid(row=5, column=0, padx=10, pady=5, sticky='w')
    data_in_transit_file_path_entry.grid(row=6, column=0, padx=10, pady=5, sticky='w')
    data_in_transit_browse_button.grid(row=6, column=1, padx=10, pady=5, sticky='w')
    data_in_transit_send_button.grid(row=7, column=0, columnspan=2, padx=10, pady=5)

    def back_to_main_window(data_in_transit_window):
        data_in_transit_window.destroy()  # Close the "Data in Transit" window
        window.deiconify()  # Show the main window

# Function to create the "Data at Rest" window
def create_data_at_rest_window():
    data_at_rest_choice_var = tk.StringVar()  
    data_at_rest_window = tk.Toplevel(window)
    data_at_rest_window.title("Data at Rest")
    data_at_rest_window.geometry("800x400")

    def encrypt_data():
        data = data_at_rest_data_entry.get()
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data.encode('utf-8'))
        display_result("Encrypted Data", encrypted_data)

    def encrypt_file():
        file_path = data_at_rest_file_path_var.get()
        if not os.path.exists(file_path):
            display_result("Error", "File does not exist.")
        else:
            with open(file_path, 'rb') as file:
                data = file.read()
                fernet = Fernet(key)
                encrypted_data = fernet.encrypt(data)
                
                # Save the encrypted data to a file
                encrypted_file_path = save_encrypted_file(encrypted_data)
                
                result_text = f"Encrypted Data:\n\n{encrypted_data.decode('utf-8')}\n\nSaved to: {encrypted_file_path}"
                display_result("Encrypted File", result_text)

    def decrypt_data():
        encrypted_data = data_at_rest_data_entry.get()
        fernet = Fernet(key)
        try:
            decrypted_data = fernet.decrypt(encrypted_data.encode('utf-8'))
            display_result("Decrypted Data", decrypted_data.decode('utf-8'))
        except Exception as e:
            display_result("Error", "Decryption failed. Ensure you have the correct key.")

    def decrypt_file():
        file_path = data_at_rest_file_path_var.get()
        if not os.path.exists(file_path):
            display_result("Error", "File does not exist.")
        else:
            with open(file_path, 'rb') as file:
                data = file.read()
                fernet = Fernet(key)
                try:
                    decrypted_data = fernet.decrypt(data)
                    display_result("Decrypted Data", decrypted_data.decode('utf-8'))
                except Exception as e:
                    display_result("Error", "Decryption failed. Ensure you have the correct key.")

    def display_result(title, result):
        result_window = tk.Toplevel(data_at_rest_window)
        result_window.title(title)
        
        result_text = tk.Text(result_window, wrap=tk.WORD)
        result_text.insert(tk.END, result)
        result_text.pack(fill=tk.BOTH, expand=True)
        
        back_button = tk.Button(result_window, text="Back", command=lambda: back_to_data_at_rest_window(result_window))
        back_button.pack()

    def save_encrypted_file(encrypted_data):
        save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])
        if save_path:
            with open(save_path, 'wb') as file:
                file.write(encrypted_data)
        return save_path

    data_at_rest_label = tk.Label(data_at_rest_window, text="Choose an option for Data at Rest:")
    data_at_rest_data_radio = tk.Radiobutton(data_at_rest_window, text="Data", variable=data_at_rest_choice_var, value="data")
    data_at_rest_file_radio = tk.Radiobutton(data_at_rest_window, text="File", variable=data_at_rest_choice_var, value="file")
    data_at_rest_data_label = tk.Label(data_at_rest_window, text="Enter Data:")
    data_at_rest_data_entry = tk.Entry(data_at_rest_window, width=30)
    data_at_rest_data_entry.insert(0, "")
    data_at_rest_file_label = tk.Label(data_at_rest_window, text="Select File:")
    data_at_rest_file_path_var = tk.StringVar()
    data_at_rest_file_path_entry = tk.Entry(data_at_rest_window, textvariable=data_at_rest_file_path_var, width=30)
    data_at_rest_file_path_entry.insert(0, "")
    data_at_rest_browse_button = tk.Button(data_at_rest_window, text="Browse", command=lambda: data_at_rest_file_path_var.set(filedialog.askopenfilename()))
    encrypt_data_button = tk.Button(data_at_rest_window, text="Encrypt Data", command=encrypt_data, width=30)
    encrypt_file_button = tk.Button(data_at_rest_window, text="Encrypt File", command=encrypt_file, width=30)
    decrypt_data_button = tk.Button(data_at_rest_window, text="Decrypt Data", command=decrypt_data, width=30)
    decrypt_file_button = tk.Button(data_at_rest_window, text="Decrypt File", command=decrypt_file, width=30)

    data_at_rest_label.grid(row=0, column=0, padx=10, pady=5)
    data_at_rest_data_radio.grid(row=1, column=0, padx=10, pady=5, sticky='w')
    data_at_rest_file_radio.grid(row=2, column=0, padx=10, pady=5, sticky='w')
    data_at_rest_data_label.grid(row=3, column=0, padx=10, pady=5)
    data_at_rest_data_entry.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky='w')
    data_at_rest_file_label.grid(row=5, column=0, padx=10, pady=5)
    data_at_rest_file_path_entry.grid(row=6, column=0, padx=10, pady=5)
    data_at_rest_browse_button.grid(row=6, column=1, padx=10, pady=5, sticky='w')
    encrypt_data_button.grid(row=7, column=0, padx=10, pady=5)
    encrypt_file_button.grid(row=7, column=1, padx=10, pady=5)
    decrypt_data_button.grid(row=8, column=0, padx=10, pady=5)
    decrypt_file_button.grid(row=8, column=1, padx=10, pady=5)

    def back_to_data_at_rest_window(result_window):
        result_window.destroy()  # Close the result window
        data_at_rest_window.deiconify()  # Show the "Data at Rest" window again

    back_button = tk.Button(data_at_rest_window, text="Back", command=lambda: back_to_main_window(data_at_rest_window))
    back_button.grid(row=9, column=0, padx=10, pady=10)

    def back_to_main_window(data_at_rest_window):
        data_at_rest_window.destroy()  # Close the "Data at Rest" window
        window.deiconify()  # Show the main window

# Main loop for the main GUI window
window.mainloop()
