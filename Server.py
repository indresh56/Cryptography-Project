import socket
import threading
import os
import json
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import base64
from merkle_tree import MerkleTree, merkle_tree_to_ascii, merkle_tree_visualize
import hashlib
from twilio.rest import Client
import random

# Constants
HOST = '127.0.0.1'
PORT = 12345
UPLOAD_DIR = "server_uploads"
CHUNK_SIZE = 4096  # Optimized chunk size
USER_FILE = "users.json"

# Twilio configuration
TWILIO_ACCOUNT_SID = 'AC6583397d4fdd51654990862b588fd721'
TWILIO_AUTH_TOKEN = '30fa701c0f323389dff0377228e680b7'
TWILIO_PHONE_NUMBER = '+15817018010'

os.makedirs(UPLOAD_DIR, exist_ok=True)

# Generate RSA key pair for secure communication
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

if not os.path.exists(USER_FILE):
    with open(USER_FILE, "w") as f:
        json.dump({}, f)

def send_otp(phone_number):
    """Send OTP via Twilio SMS."""
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    otp = str(random.randint(100000, 999999))
    
    message = client.messages.create(
        body=f"Your OTP code is {otp}",
        from_=TWILIO_PHONE_NUMBER,
        to=phone_number
    )

    print(f"OTP sent to {phone_number}: {otp}")
    return otp

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    with open(USER_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f)

def create_user_folder(username):
    """Creates a folder for the user if it doesn't exist."""
    user_dir = os.path.join(UPLOAD_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    os.makedirs(os.path.join(user_dir, "merkle_trees"), exist_ok=True)

def get_user_folder(username):
    """Returns the user's folder path."""
    return os.path.join(UPLOAD_DIR, username)


def send_with_size(sock, data):
    """Send data prefixed with its size for reliable transmission."""
    size = len(data).to_bytes(8, byteorder='big')
    sock.sendall(size + data)

def recv_with_size(sock):
    """Receive data with size prefix for reliable transmission."""
    size_bytes = sock.recv(8)
    if not size_bytes:
        return None
    size = int.from_bytes(size_bytes, byteorder='big')
    
    data = b''
    remaining = size
    while remaining > 0:
        chunk = sock.recv(min(CHUNK_SIZE, remaining))
        if not chunk:
            return None
        data += chunk
        remaining -= len(chunk)
    
    return data

def encrypt_data(data, aes_key):
    """Encrypt data using AES in CBC mode."""
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = cipher.iv
    return base64.b64encode(iv + ct_bytes)

def decrypt_data(encrypted_data, aes_key):
    """Decrypt data using AES in CBC mode."""
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

def compare_otps(server_otp, client_otp):
    # Extract the actual OTP from the server (remove size prefix)
    client_otp = client_otp[-6:]  # Keep only the last 6 digits

    # Normalize both OTPs
    server_otp = str(server_otp).strip().replace("\r", "").replace("\n", "")
    client_otp = str(client_otp).strip().replace("\r", "").replace("\n", "")

    # Debug info
    print(f"Server OTP: {repr(server_otp)} (Length: {len(server_otp)})")
    print(f"Client OTP: {repr(client_otp)} (Length: {len(client_otp)})")

    # Compare the cleaned OTPs
    return server_otp == client_otp

def handle_client(client_socket, addr):
    """Handle client connection and process commands."""
    print(f"Connected: {addr}")
    try:
        # Exchange encryption keys
        client_socket.sendall(public_key.export_key())
        encrypted_aes_key = client_socket.recv(256)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        print(f"AES Key received and decrypted: {aes_key.hex()}")

        authenticated = False
        username = ""  
        while True:
            # Receive command with size prefix
            command_data = recv_with_size(client_socket)
            if not command_data:
                break
                
            command = command_data.decode()
            print(f"Received command: {command}")

            if command.startswith("SIGNUP"):
                _, uname, pwd, phone = command.split()
                users = load_users()

                if uname in users:
                    client_socket.sendall(b"USER_EXISTS")
                else:
                    users[uname] = {
                        "password": pwd,
                        "phone": phone
                    }
                    save_users(users)
                    create_user_folder(uname)
                    client_socket.sendall(b"SIGNUP_SUCCESS")

            elif command.startswith("LOGIN"):
                _, uname, pwd = command.split()
                users = load_users()

                if uname in users and users[uname]["password"] == pwd:
                    phone_number = users[uname]["phone"]

                    # Send OTP
                    server_otp = send_otp(phone_number)
                    client_socket.sendall(b"OTP_SENT")

                    # Receive OTP from client
                    client_otp = client_socket.recv(1024).decode()
                    print("Received OTP "+client_otp)

                    if compare_otps(server_otp,client_otp):
                        authenticated = True
                        username = uname
                        client_socket.sendall(b"LOGIN_SUCCESS")
                    else:
                        client_socket.sendall(b"INVALID_OTP")
                else:
                    client_socket.sendall(b"LOGIN_FAILED")

            if not authenticated:
                continue

            user_folder = get_user_folder(username)
            merkle_folder = os.path.join(user_folder, "merkle_trees")

            if command.startswith("UPLOAD"):
                handle_upload(client_socket, command, aes_key, user_folder, merkle_folder)
            elif command.startswith("DOWNLOAD"):
                handle_download(client_socket, command, aes_key, user_folder, merkle_folder)
            elif command.startswith("UPDATE"):
                handle_update(client_socket, command, aes_key, user_folder, merkle_folder)
            elif command == "LIST_FILES":
                handle_list_files(client_socket, aes_key, user_folder)
            elif command.startswith("DELETE"):
                handle_delete_file(client_socket, command, aes_key, user_folder, merkle_folder)

    except Exception as e:
        print(f"Error with client {addr}: {e}")
    finally:
        client_socket.close()
        print(f"Connection closed: {addr}")

def handle_list_files(client_socket, aes_key, user_folder):
    try:
        files = os.listdir(user_folder)
        file_list = "\n".join(files).encode()
        encrypted_file_list = encrypt_data(file_list, aes_key)
        send_with_size(client_socket, encrypted_file_list)
    except Exception as e:
        print(f"Error sending file list: {e}")

def handle_delete_file(client_socket, command, aes_key, user_folder, merkle_folder):
    try:
        _, filename = command.split()
        file_path = os.path.join(user_folder, filename)
        merkle_path = os.path.join(merkle_folder, f"{filename}.json")
        
        response = ""
        if os.path.exists(file_path):
            os.remove(file_path)
            os.remove(merkle_path)
            response = "DELETE_SUCCESS"
        else:
            response = "FILE_NOT_FOUND"

        send_with_size(client_socket, response.encode())
    except Exception as e:
        print(f"Error deleting file: {e}")
        client_socket.sendall(b"DELETE_FAILED")

def handle_upload(client_socket, command, aes_key, user_folder, merkle_folder):
    """Handle file upload from client."""
    try:
        filename = command.split(" ", 1)[1]
        filepath = os.path.join(user_folder, filename)
        
        # Receive file data
        file_data = recv_with_size(client_socket)
        if file_data:
            decrypted_data = decrypt_data(file_data, aes_key)
            
            with open(filepath, "wb") as f:
                f.write(decrypted_data)
            
            print(f"File '{filename}' uploaded successfully.")
            
            # Receive and save Merkle Tree
            merkle_data = recv_with_size(client_socket)
            if merkle_data:
                merkle_tree_data = decrypt_data(merkle_data, aes_key).decode()
                merkle_tree_path = os.path.join(merkle_folder, f"{filename}.json")
                
                with open(merkle_tree_path, "w") as merkle_file:
                    merkle_file.write(merkle_tree_data)
                
                # Verify integrity
                received_tree = json.loads(merkle_tree_data)
                server_merkle_tree = MerkleTree(filepath)
                
                if server_merkle_tree.tree == received_tree:
                    print("Integrity Check Passed.")
                    # Display Merkle Tree
                    print("\nServer-side Merkle Tree for uploaded file:")
                    print(merkle_tree_to_ascii(server_merkle_tree.tree))
                    merkle_tree_visualize(server_merkle_tree.tree, merkle_tree_path)
                    
                    response = "UPLOAD_SUCCESS"
                else:
                    print("Integrity Check Failed!")
                    response = "INTEGRITY_FAILED"
            else:
                response = "MERKLE_TREE_MISSING"
        else:
            response = "UPLOAD_FAILED"
        
        # Send response
        send_with_size(client_socket, response.encode())
        
    except Exception as e:
        print(f"Upload error: {e}")
        send_with_size(client_socket, f"ERROR: {str(e)}".encode())

def handle_download(client_socket, command, aes_key, user_folder, merkle_folder):
    """Handle file download request from client."""
    try:
        filename = command.split(" ", 1)[1]
        filepath = os.path.join(user_folder, filename)
        merkle_path = os.path.join(merkle_folder, f"{filename}.json")
        
        if os.path.exists(filepath) and os.path.exists(merkle_path):
            # Send ready signal
            send_with_size(client_socket, b"READY")
            
            # Send file data
            with open(filepath, "rb") as f:
                file_data = f.read()
            
            encrypted_data = encrypt_data(file_data, aes_key)
            send_with_size(client_socket, encrypted_data)
            
            # Send Merkle Tree
            with open(merkle_path, "r") as merkle_file:
                merkle_data = merkle_file.read()
            
            encrypted_merkle = encrypt_data(merkle_data.encode(), aes_key)
            send_with_size(client_socket, encrypted_merkle)
            
            print(f"File '{filename}' and its Merkle tree sent to client.")
        else:
            send_with_size(client_socket, b"FILE_NOT_FOUND")
            
    except Exception as e:
        print(f"Download error: {e}")
        send_with_size(client_socket, f"ERROR: {str(e)}".encode())

def handle_update(client_socket, command, aes_key, user_folder, merkle_folder):
    """Handle file update request using efficient delta updates."""
    try:
        filename = command.split(" ", 1)[1]
        filepath = os.path.join(user_folder, filename)
        merkle_path = os.path.join(merkle_folder, f"{filename}.json")
        
        if not os.path.exists(filepath) or not os.path.exists(merkle_path):
            send_with_size(client_socket, b"FILE_NOT_FOUND")
            return
            
        # Send current server-side Merkle tree to client
        with open(merkle_path, "r") as merkle_file:
            server_merkle_data = merkle_file.read()
        
        # Display the old Merkle tree before update
        print("\nServer-side Merkle Tree before update:")
        server_tree = json.loads(server_merkle_data)
        print(merkle_tree_to_ascii(server_tree))
        
        # Send the server's merkle tree to client
        encrypted_merkle = encrypt_data(server_merkle_data.encode(), aes_key)
        send_with_size(client_socket, encrypted_merkle)
        
        # Receive changed chunks information
        changed_chunks_data = recv_with_size(client_socket)
        if not changed_chunks_data:
            send_with_size(client_socket, b"UPDATE_FAILED")
            return
            
        changed_chunks_info = json.loads(decrypt_data(changed_chunks_data, aes_key).decode())
        
        # Get original file data
        with open(filepath, "rb") as f:
            original_data = f.read()
        
        # Process each changed chunk
        chunk_size = changed_chunks_info["chunk_size"]
        updated_data = bytearray(original_data)
        
        # Receive and apply each changed chunk
        for chunk_idx in changed_chunks_info["changed_indices"]:
            # Receive the new chunk
            chunk_data = recv_with_size(client_socket)
            if not chunk_data:
                send_with_size(client_socket, b"UPDATE_FAILED")
                return
                
            new_chunk = decrypt_data(chunk_data, aes_key)
            
            # Calculate the start and end position for this chunk
            start_pos = chunk_idx * chunk_size
            end_pos = min(start_pos + chunk_size, len(updated_data))
            
            # If the new chunk extends the file
            if start_pos >= len(updated_data):
                updated_data.extend(new_chunk)
            elif end_pos - start_pos < len(new_chunk):
                # Replace the existing chunk and extend if needed
                updated_data[start_pos:end_pos] = new_chunk[:end_pos-start_pos]
                updated_data.extend(new_chunk[end_pos-start_pos:])
            else:
                # Simple replacement
                updated_data[start_pos:start_pos + len(new_chunk)] = new_chunk
        
        # Write the updated file
        with open(filepath, "wb") as f:
            f.write(updated_data)
        
        # Receive and save the new Merkle Tree
        new_merkle_data = recv_with_size(client_socket)
        if not new_merkle_data:
            send_with_size(client_socket, b"MERKLE_UPDATE_FAILED")
            return
            
        new_merkle_tree_data = decrypt_data(new_merkle_data, aes_key).decode()
        
        with open(merkle_path, "w") as merkle_file:
            merkle_file.write(new_merkle_tree_data)
        
        # Verify integrity with new Merkle tree
        received_tree = json.loads(new_merkle_tree_data)
        server_merkle_tree = MerkleTree(filepath)
        
        if server_merkle_tree.tree == received_tree:
            print("Update Integrity Check Passed.")
            print("\nServer-side Merkle Tree after update:")
            print(merkle_tree_to_ascii(server_merkle_tree.tree))
            merkle_tree_visualize(server_merkle_tree.tree, merkle_path)

            send_with_size(client_socket, b"UPDATE_SUCCESS")
        else:
            print("Update Integrity Check Failed!")
            send_with_size(client_socket, b"UPDATE_INTEGRITY_FAILED")
            
    except Exception as e:
        print(f"Update error: {e}")
        send_with_size(client_socket, f"ERROR: {str(e)}".encode())

def start_server():
    """Start the server and listen for connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"Server listening on {HOST}:{PORT}")
        
        while True:
            client_socket, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_socket, addr)).start()
    except KeyboardInterrupt:
        print("Server shutting down...")
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()