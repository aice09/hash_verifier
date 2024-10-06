import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

# Function to calculate the hash of the file
def calculate_hash(file_path, hash_type):
    hash_function = getattr(hashlib, hash_type)()  # Get the hash function from hashlib (md5, sha1, sha256)
    
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):  # Read file in chunks to handle large files
                hash_function.update(chunk)
        return hash_function.hexdigest()  # Return the computed hash in hexadecimal
    except FileNotFoundError:
        messagebox.showerror("Error", "File not found")
        return None

# Function to verify the hash
def verify_hash():
    file_path = file_entry.get()
    expected_hash = expected_hash_entry.get().strip()
    hash_type = hash_type_var.get()

    # Compute the file's hash
    computed_hash = calculate_hash(file_path, hash_type)
    
    # Compare with the expected hash
    if computed_hash:
        if computed_hash.lower() == expected_hash.lower():
            messagebox.showinfo("Success", "Hashes match! File is verified.")
        else:
            messagebox.showwarning("Mismatch", "Hashes do NOT match! The file may be corrupted or tampered with.")

# Function to browse and select a file
def browse_file():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)

# Create the main window
window = tk.Tk()
window.title("File Hash Verifier")
window.geometry("400x200")

# Create widgets
hash_type_var = tk.StringVar(value="sha256")  # Default hash type

tk.Label(window, text="Select Hash Type:").pack(pady=5)
tk.OptionMenu(window, hash_type_var, "md5", "sha1", "sha256").pack()

tk.Label(window, text="File Location:").pack(pady=5)
file_entry = tk.Entry(window, width=50)
file_entry.pack()
tk.Button(window, text="Browse", command=browse_file).pack(pady=5)

tk.Label(window, text="Expected Hash:").pack(pady=5)
expected_hash_entry = tk.Entry(window, width=50)
expected_hash_entry.pack()

tk.Button(window, text="Verify", command=verify_hash).pack(pady=10)

# Run the GUI event loop
window.mainloop()
