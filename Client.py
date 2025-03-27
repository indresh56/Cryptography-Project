import socket
import os
import json
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from merkle_tree import MerkleTree, merkle_tree_to_ascii
import hashlib

# Constants
HOST = '127.0.0.1'
PORT = 12345
CHUNK_SIZE = 4096  # Optimized chunk size

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

class SecureClient:
    def __init__(self):
        """Initialize the client and establish a secure connection to the server."""
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((HOST, PORT))
        
        # Receive server's public key
        public_key_data = self.client_socket.recv(2048)
        self.public_key = RSA.import_key(public_key_data)
        
        # Generate and send AES key securely
        self.aes_key = get_random_bytes(16)  # 128-bit AES key
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        encrypted_aes_key = cipher_rsa.encrypt(self.aes_key)
        self.client_socket.sendall(encrypted_aes_key)
        
        print(f"AES Key generated and sent: {self.aes_key.hex()}")

    def send_with_size(self, data):
        """Send data prefixed with its size for reliable transmission."""
        size = len(data).to_bytes(8, byteorder='big')
        self.client_socket.sendall(size + data)
    
    def recv_with_size(self):
        """Receive data with size prefix for reliable transmission."""
        size_bytes = self.client_socket.recv(8)
        if not size_bytes:
            return None
        size = int.from_bytes(size_bytes, byteorder='big')
        
        data = b''
        remaining = size
        while remaining > 0:
            chunk = self.client_socket.recv(min(CHUNK_SIZE, remaining))
            if not chunk:
                return None
            data += chunk
            remaining -= len(chunk)
        
        return data
    
    def encrypt_data(self, data):
        """Encrypt data using AES in CBC mode."""
        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        iv = cipher.iv
        return base64.b64encode(iv + ct_bytes)
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data using AES in CBC mode."""
        encrypted_data = base64.b64decode(encrypted_data)
        iv = encrypted_data[:16]
        ct = encrypted_data[16:]
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size)
    
    def authenticate(self):
        while True:
            print("\n1. Sign up")
            print("2. Log in")
            choice = input("Enter choice: ")

            if choice == "1":
                username = input("Enter username: ")
                password = input("Enter password: ")
                phone = input("Enter phone number (e.g., +1234567890): ")

                #self.client_socket.sendall(f"SIGNUP {username} {password}".encode())
                password = hash_password(password)
                command = f"SIGNUP {username} {password} {phone}"
                self.send_with_size(command.encode())

                response = self.client_socket.recv(1024).decode()
                if response == "SIGNUP_SUCCESS":
                    print("Signup successful!")
                else:
                    print("Username already exists!")

            elif choice == "2":
                username = input("Enter username: ")
                password = input("Enter password: ")
                #self.client_socket.sendall(f"LOGIN {username} {password}".encode())
                password = hash_password(password)
                
                command = f"LOGIN {username} {password}"
                self.send_with_size(command.encode())

                response = self.client_socket.recv(1024).decode()

                if response == "OTP_SENT":
                    otp = input("Enter the OTP sent to your phone: ")

                    self.send_with_size(otp.encode())

                    final_response = self.client_socket.recv(1024).decode()

                    if final_response == "LOGIN_SUCCESS":
                        print("Login successful with 2FA!")
                        return
                    else:
                        print("Invalid OTP.")
                else:
                    print("Login failed. Invalid credentials.")
            else:
                print("Invalid choice!")

    def request_file_list(self):
        self.send_with_size(b"LIST_FILES")
        encrypted_file_list = self.recv_with_size()
        if not encrypted_file_list:
            print("Failed to receive file list.")
            return
        
        file_list = self.decrypt_data(encrypted_file_list).decode()
        print("Files in your directory:")
        print(file_list)
    
    def delete_file(self, filename):
        command = f"DELETE {filename}".encode()
        self.send_with_size(command)
        
        response = self.recv_with_size()
        if response:
            print(response.decode())
        else:
            print("No response from server.")

    def upload_file(self, filename):
        """Upload a file to the server with integrity verification."""
        if not os.path.exists(filename):
            print("File not found!")
            return
        
        try:
            # Send UPLOAD command
            command = f"UPLOAD {os.path.basename(filename)}"
            self.send_with_size(command.encode())
            
            # Read and send file data
            with open(filename, "rb") as f:
                file_data = f.read()
            
            encrypted_data = self.encrypt_data(file_data)
            self.send_with_size(encrypted_data)
            
            # Generate and send Merkle Tree
            merkle_tree = MerkleTree(filename)
            merkle_tree_data = json.dumps(merkle_tree.tree)
            
            encrypted_merkle = self.encrypt_data(merkle_tree_data.encode())
            self.send_with_size(encrypted_merkle)
            
            # Display Merkle Tree
            print("\nClient-side Merkle Tree for uploaded file:")
            print(merkle_tree_to_ascii(merkle_tree.tree))
            
            # Receive response
            response = self.recv_with_size()
            if response:
                print(f"Server: {response.decode()}")
            else:
                print("No response from server.")
                
        except Exception as e:
            print(f"Upload error: {e}")
    
    def download_file(self, filename):
        """Download a file from the server with integrity verification."""
        try:
            # Send DOWNLOAD command
            command = f"DOWNLOAD {filename}"
            self.send_with_size(command.encode())
            
            # Receive response
            response = self.recv_with_size()
            if not response:
                print("No response from server.")
                return
                
            if response == b"READY":
                # Receive file data
                encrypted_file = self.recv_with_size()
                if not encrypted_file:
                    print("Failed to receive file data.")
                    return
                    
                file_data = self.decrypt_data(encrypted_file)
                
                # Save the downloaded file
                output_filename = f"downloaded_{filename}"
                with open(output_filename, "wb") as f:
                    f.write(file_data)
                
                # Receive Merkle Tree
                encrypted_merkle = self.recv_with_size()
                if not encrypted_merkle:
                    print("Failed to receive Merkle tree data.")
                    return
                    
                merkle_data = self.decrypt_data(encrypted_merkle).decode()
                received_merkle_tree = json.loads(merkle_data)
                
                # Verify file integrity
                downloaded_merkle_tree = MerkleTree(output_filename)
                
                if downloaded_merkle_tree.tree == received_merkle_tree:
                    print(f"File '{filename}' downloaded successfully and integrity verified.")
                else:
                    print("Warning: File integrity check failed! The downloaded file may be corrupted.")
                    
            elif response == b"FILE_NOT_FOUND":
                print("File not found on server.")
            else:
                print(f"Server response: {response.decode()}")
                
        except Exception as e:
            print(f"Download error: {e}")
    
    def update_file(self, filename):
        """Update a file on the server with efficient delta transmission."""
        if not os.path.exists(filename):
            print("Local file not found!")
            return
        
        try:
            # Send UPDATE command
            command = f"UPDATE {os.path.basename(filename)}"
            self.send_with_size(command.encode())
            
            # Receive server's version of the Merkle tree
            server_merkle_encrypted = self.recv_with_size()
            if not server_merkle_encrypted:
                print("Failed to receive server's Merkle tree.")
                return
                
            if server_merkle_encrypted == b"FILE_NOT_FOUND":
                print("File not found on server. Please upload it first.")
                return
                
            server_merkle_data = self.decrypt_data(server_merkle_encrypted).decode()
            server_tree = json.loads(server_merkle_data)
            
            # Generate local Merkle tree
            local_merkle_tree = MerkleTree(filename)
            
            # Compare trees to find differences
            changed_chunks = []
            local_leaves = local_merkle_tree.tree[0]
            server_leaves = server_tree[0]
            
            # Identify changed chunks
            for i in range(max(len(local_leaves), len(server_leaves))):
                if i >= len(server_leaves) or (i < len(local_leaves) and local_leaves[i] != server_leaves[i]):
                    changed_chunks.append(i)
            
            if not changed_chunks:
                print("File is already up to date on server.")
                # Need to read the response from server
                self.send_with_size(b"NO_CHANGES")
                response = self.recv_with_size()
                if response:
                    print(f"Server: {response.decode()}")
                return
            
            print(f"Found {len(changed_chunks)} changed chunks out of {len(local_leaves)} total chunks.")
            
            # Read local file
            with open(filename, "rb") as f:
                file_data = f.read()
            
            # Send changed chunks information
            chunk_info = {
                "chunk_size": local_merkle_tree.chunk_size,
                "changed_indices": changed_chunks
            }
            
            info_json = json.dumps(chunk_info)
            encrypted_info = self.encrypt_data(info_json.encode())
            self.send_with_size(encrypted_info)
            
            # Send only the changed chunks
            for chunk_idx in changed_chunks:
                start_pos = chunk_idx * local_merkle_tree.chunk_size
                end_pos = min(start_pos + local_merkle_tree.chunk_size, len(file_data))
                
                if start_pos < len(file_data):
                    chunk_data = file_data[start_pos:end_pos]
                    encrypted_chunk = self.encrypt_data(chunk_data)
                    self.send_with_size(encrypted_chunk)
            
            # Send the updated Merkle tree
            merkle_tree_data = json.dumps(local_merkle_tree.tree)
            encrypted_merkle = self.encrypt_data(merkle_tree_data.encode())
            self.send_with_size(encrypted_merkle)
            
            # Display the updated Merkle tree
            print("\nClient-side Merkle Tree after update:")
            print(merkle_tree_to_ascii(local_merkle_tree.tree))
            
            # Receive response
            response = self.recv_with_size()
            if response:
                print(f"Server: {response.decode()}")
            else:
                print("No response from server.")
                
        except Exception as e:
            print(f"Update error: {e}")
    
    def close(self):
        """Close the client socket connection."""
        self.client_socket.close()
        print("Connection closed.")

def main():
    """Main client function with user menu."""
    try:
        client = SecureClient()
        print("Connected to server successfully.")
        
        client.authenticate()
        client.request_file_list()
        while True:
            print("\nOptions:")
            print("1. List Uploads")
            print("2. Upload a file")
            print("3. Download a file")
            print("4. Update a file")
            print("5. Delete a file")
            print("6. Exit")
            
            choice = input("Enter choice: ")
            
            if choice == "1":
                client.request_file_list()
            elif choice == "2":
                filename = input("Enter file path to upload: ")
                client.upload_file(filename)
            elif choice == "3":
                filename = input("Enter filename to download: ")
                client.download_file(filename)
            elif choice == "4":
                filename = input("Enter file path to update: ")
                client.update_file(filename)
            elif choice == "5":
                filename = input("Enter file path to delete: ")
                client.delete_file(filename)
            elif choice == "6":
                break
            else:
                print("Invalid choice!")
        
        client.close()
        
    except ConnectionRefusedError:
        print("Connection to server failed. Make sure the server is running.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()