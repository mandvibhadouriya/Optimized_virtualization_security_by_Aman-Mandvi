import socket
from cryptography.fernet import Fernet
import hashlib
import time
import tkinter as tk
from tkinter import filedialog

# Provided encryption key
key = b'dtWMFIEe4S4l_5voF5SdwLfbT4RlRTMJ6yJz5LcQZUk='

# Function to save data to a file
def save_data_to_file(data, filename):
    with open(filename, 'wb') as file:
        file.write(data)

# Step 3: Calculate hash
def calculate_hash(data):
    hash_obj = hashlib.blake2b(data)
    return hash_obj.hexdigest()

# Create a socket connection
def receive_data():
    global result_window
    host = '192.168.79.1'  # Use 'localhost' or '127.0.0.1' for local testing
    port = 1234

    start_time = time.time()  # Start time for calculating total time

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        conn, addr = s.accept()

        print(f"Connection from {addr}")
        encrypted_data = conn.recv(4096)
        
        # Save encrypted data to a file
        encrypted_filename = "encrypted_data.txt"
        save_data_to_file(encrypted_data, encrypted_filename)

        # Step 2: Decrypt and print the data
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # Save decrypted data to a file
        decrypted_filename = "decrypted_data.txt"
        save_data_to_file(decrypted_data, decrypted_filename)

        # Step 3: Calculate hash
        hash_value = calculate_hash(encrypted_data)

        end_time = time.time()  # End time for calculating total time
        total_time = end_time - start_time

        # Open a new result window
        result_window = tk.Toplevel(window)
        result_window.title("Data Received")
        result_window.geometry("600x400")  # Maximize the result window

        result_text = tk.Label(result_window, text=f"Encrypted Data:\n{encrypted_data.decode('utf-8')}\n\n"
                                                f"Decrypted Data:\n{decrypted_data.decode('utf-8')}\n\n"
                                                f"Hash Value: {hash_value}\n\n"
                                                f"Encrypted data saved as '{encrypted_filename}'\n"
                                                f"Decrypted data saved as '{decrypted_filename}'\n\n"
                                                f"Total Time: {total_time:.2f} seconds")
        result_text.pack(padx=20, pady=20)

        # Add a Quit button in the result window
        quit_button = tk.Button(result_window, text="Quit", command=quit_program)
        quit_button.pack(pady=10)

# Function to quit the program
def quit_program():
    window.quit()
    window.destroy()

# Create a GUI
window = tk.Tk()
window.title("Data Receiver")
window.geometry("400x300")

receive_button = tk.Button(window, text="Receive Data", command=receive_data)
receive_button.pack(pady=10)

window.mainloop()