import tkinter as tk
from tkinter import messagebox
import threading
from server import server  # Import your server function here

def start_server_ui(log_text):
    try:
        log_text.insert(tk.END, "Starting server...\n")
        log_text.see(tk.END)
        server()  # Call the server function to handle incoming connections
        log_text.insert(tk.END, "Server stopped.\n")
    except Exception as e:
        messagebox.showerror("Error", f"Server error: {e}")

# Create Receiver GUI
def receiver_gui():
    root = tk.Tk()
    root.title("Receiver - Audio Decryption")

    # Set the background color to grayish tone
    root.configure(bg="#2f2f2f")

    # Title label
    tk.Label(root, text="Audio File Receiver", font=("Arial", 16, "bold"), fg="white", bg="#2f2f2f").pack(pady=10)

    # Log display text box
    log_text = tk.Text(root, width=50, height=20, state="normal", bg="#2f2f2f", fg="white", font=("Arial", 12))
    log_text.pack(pady=10)

    # Function to run the server in a separate thread
    def start_server_thread():
        threading.Thread(target=start_server_ui, args=(log_text,), daemon=True).start()

    # Start button
    start_button = tk.Button(root, text="Start Server", command=start_server_thread, width=25, height=2,
                             bg="#2e8b57", fg="white", font=("Arial", 12, "bold"), relief="solid", borderwidth=2)
    start_button.pack(pady=20)

    root.mainloop()

if __name__ == "__main__":
    receiver_gui()
