import socket
import json
import time
import threading
import base64
import pyDes
from datetime import datetime
from hashlib import sha256
import random

# --- Global Variables ---
BROADCAST_IP = '192.168.1.255'
UDP_PORT = 6000
TCP_PORT = 6001
TIMEOUT = 900
ONLINE_TIMEOUT = 10
# [2.1.0-A] Prompt for username and store it locally
USERNAME = input("Enter your username: ")
peers = {}
shared_keys = {}
RUNNING = True
DH_P = 19
DH_G = 2

# --- Logging Function ---
def log_message(direction, username, message, secure=False):
    with open("chat_log.txt", "a") as log:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tag = "SECURE" if secure else "PLAIN"
        log.write(f"{timestamp} [{direction}] ({tag}) {username}: {message}\n")

# --- Key Derivation Function for 3DES ---
def derive_des_key(key_str):
    return sha256(key_str.encode()).digest()[:24]

# --- Encryption Helpers ---
def encrypt_message(message, key_str):
    des_key = derive_des_key(key_str)
    cipher = pyDes.triple_des(des_key)
    encrypted = cipher.encrypt(message, padmode=2)
    return base64.b64encode(encrypted).decode()

def decrypt_message(b64_encrypted, key_str):
    des_key = derive_des_key(key_str)
    cipher = pyDes.triple_des(des_key)
    encrypted_bytes = base64.b64decode(b64_encrypted.encode())
    return cipher.decrypt(encrypted_bytes, padmode=2).decode()

# --- Service Broadcaster ---
def service_announcer():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
# [2.1.0-C] Format broadcast message as JSON with "username" key
    msg = json.dumps({"username": USERNAME})
    while RUNNING:
# [2.1.0-B] Broadcast presence every 8 seconds using UDP
        sock.sendto(msg.encode(), (BROADCAST_IP, UDP_PORT))
        time.sleep(8)
    sock.close()

# --- Peer Discovery Listener ---
def peer_discovery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# [2.2.0-A] Listen for UDP broadcasts on port 6000
    sock.bind(('', UDP_PORT))
# [2.4.0-E] Continue listening after each session ends
    sock.settimeout(1)
    while RUNNING:
        try:
            data, addr = sock.recvfrom(1024)
# [2.2.0-B] Parse incoming UDP message as JSON
            payload = json.loads(data.decode())
            ip = addr[0]
            username = payload["username"]

            if ip not in peers:
# [2.2.0-D] Display new peer detected on console
                print(f"{username} is online")

# [2.2.0-C] Add or update peer with timestamp
            peers[ip] = (username, time.time())

        except socket.timeout:
            continue
        except Exception as e:
            print(f"[ERROR] Failed to parse message: {e}")
    sock.close()

# --- TCP Server to Handle Incoming Messages ---
def tcp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', TCP_PORT))
# [2.4.0-A] Listen for TCP connections on port 6001
    sock.listen()
# [2.4.0-E] Continue listening after each session ends
    sock.settimeout(1)
    while RUNNING:
        try:
# [2.4.0-B] Accept incoming TCP connection
            conn, addr = sock.accept()
            with conn:
                ip = addr[0]
                while True:
                    data = conn.recv(2048)
                    if not data:
                        break
# [2.2.0-B] Parse incoming UDP message as JSON
                    payload = json.loads(data.decode())
                    sender = peers.get(ip, ("Unknown",))[0]

# [2.4.0-C] Handle key exchange and respond
                    if "key" in payload:
                        their_key = int(payload["key"])
                        my_private = random.randint(2, DH_P - 2)
                        my_public = pow(DH_G, my_private, DH_P)
                        shared_key = str(pow(their_key, my_private, DH_P))
                        shared_keys[ip] = shared_key
                        conn.send(json.dumps({"key": str(my_public)}).encode())
                        print(f"\n[KEY] Shared key established with {sender}.")

# [2.4.0-C] Handle incoming encrypted message
                    elif "encrypted_message" in payload:
                        key = shared_keys.get(ip)
                        if not key:
                            print(f"[ERROR] No shared key for {ip}.")
                            continue
                        encrypted = payload["encrypted_message"]
                        decrypted = decrypt_message(encrypted, key)
                        print(f"[DEBUG] Encrypted received: {encrypted}")
                        print(f"[Secure] {sender} ({ip}): {decrypted}")
# [2.4.0-D] Log received message with timestamp and username
                        log_message("RECEIVED", sender, decrypted, secure=True)

# [2.4.0-C] Handle incoming plain message
                    elif "unencrypted_message" in payload:
                        msg = payload['unencrypted_message']
                        print(f"\n[Plain] {sender} ({ip}): {msg}")
# [2.4.0-D] Log received message with timestamp and username
                        log_message("RECEIVED", sender, msg, secure=False)

        except socket.timeout:
            continue
        except Exception as e:
            print(f"[TCP ERROR] {e}")
    sock.close()

# --- Main Command-Line Interface ---
def chat_interface():
    global RUNNING
    while True:
# [2.3.0-A] Prompt user for command (Users, Chat, History)
        command = input("\nCommand (Users / Chat / History / Exit): ").strip().lower()

        if command == "users":
            now = time.time()
            for ip, (username, timestamp) in peers.items():
# [2.3.0-B] Display Online/Away status based on last timestamp
                status = "Online" if now - timestamp < ONLINE_TIMEOUT else "Away"
                print(f"{username} ({ip}) - {status}")

        elif command == "chat":
            users_by_name = {name.lower(): ip for ip, (name, _) in peers.items()}
            print("Available users:")
            for name, ip in users_by_name.items():
                print(f"- {name} ({ip})")
            target = input("Chat with (username): ").strip().lower()
            target_ip = users_by_name.get(target)

            if not target_ip:
                print("User not found or offline.")
                continue

            if target_ip == socket.gethostbyname(socket.gethostname()):
                print("You cannot chat with yourself.")
                continue

            secure = input("Secure chat? (yes/no): ").strip().lower()

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((target_ip, TCP_PORT))

# [2.3.0-C] Secure chat: perform DH key exchange and send encrypted message
                if secure == "yes":
                    my_private = random.randint(2, DH_P - 2)
                    my_public = pow(DH_G, my_private, DH_P)
# [2.3.0-C] Send key as JSON
                    sock.send(json.dumps({"key": str(my_public)}).encode())
                    response = sock.recv(1024)
                    their_key = int(json.loads(response.decode())["key"])
                    shared = str(pow(their_key, my_private, DH_P))
                    shared_keys[target_ip] = shared

                    msg = input("Message: ")
                    encrypted = encrypt_message(msg, shared)
# [2.3.0-C] Send encrypted message in JSON
                    sock.send(json.dumps({"encrypted_message": encrypted}).encode())
                    print(f"\n[DEBUG] Encrypted raw: {encrypted}")
                    print(f"[SENT] Encrypted: {msg}")
# [2.3.0-E] Log sent message with timestamp and username
                    log_message("SENT", target, msg, secure=True)

                else:
                    msg = input("Message: ")
                    sock.send(json.dumps({"unencrypted_message": msg}).encode())
                    print(f"\n[SENT] Plain: {msg}")
# [2.3.0-E] Log sent message with timestamp and username
                    log_message("SENT", target, msg, secure=False)

                sock.close()

            except Exception as e:
                print(f"[TCP ERROR] {e}")

# [2.3.0-G] Display message log history
        elif command == "history":
            try:
                with open("chat_log.txt", "r") as f:
                    print("\n--- Chat History ---")
                    print(f.read())
            except FileNotFoundError:
                print("No history found.")

        elif command in ("exit", "quit"):
            print("[EXIT] Shutting down...")
            RUNNING = False
            break

# --- Thread Initialization ---
broadcast_thread = threading.Thread(target=service_announcer)
discovery_thread = threading.Thread(target=peer_discovery)
listener_thread = threading.Thread(target=tcp_listener)

broadcast_thread.start()
discovery_thread.start()
listener_thread.start()

time.sleep(8)
chat_interface()

broadcast_thread.join()
discovery_thread.join()
listener_thread.join()