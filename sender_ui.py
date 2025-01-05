import tkinter as tk
from tkinter import filedialog, messagebox
from client import client  # Import your client function here

# Function to send the file to the server
def send_file():
    file_path = filedialog.askopenfilename(filetypes=[("Audio Files", "*.mp3")])
    if not file_path:
        return
    try:
        client(file_path)
        messagebox.showinfo("Success", "File sent successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send file: {e}")

# Create Sender GUI with customized UI style
def sender_gui():
    root = tk.Tk()
    root.title("Sender - Audio Encryption & Transfer")
    
    # Set the background color to a grayish tone
    root.configure(bg="#2f2f2f")

    # Title Label
    title_label = tk.Label(root, text="Audio File Sender", font=("Arial", 16, "bold"), fg="white", bg="#2f2f2f")
    title_label.pack(pady=10)

    # Button to select and send the audio file
    send_button = tk.Button(root, text="Select and Send File", command=send_file, width=25, height=2,
                             bg="#2e8b57", fg="white", font=("Arial", 12, "bold"), relief="solid", borderwidth=2)
    send_button.pack(pady=20)

    # Start the GUI event loop
    root.mainloop()

if __name__ == "__main__":
    sender_gui()
