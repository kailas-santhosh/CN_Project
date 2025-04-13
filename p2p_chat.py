import socket
import threading
import time
import os
import hashlib
import json
from datetime import datetime
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import sys
import select
import netifaces  # Added for better IP detection

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('p2p_chat.log')
    ]
)

class P2PChatNode:
    def __init__(self, username, port=None):
        self.backend = default_backend()
        self.username = username
        self.private_key, self.public_key = self.generate_keys()
        self.peers = {}
        self.active_peer = None
        self.peer_socket = None
        self.listening_socket = None
        # self.listening_port = self.find_available_port()
        self.listening_port = port if port else self.find_available_port()
        self.running = False
        self.udp_broadcast_interval = 10
        self.connection_established = False
        self.message_lock = threading.Lock()
        self.connection_lock = threading.Lock()
        
        print(f"Starting node with IP: {self.get_local_ip()}, Port: {self.listening_port}")
        
        if not self.setup_listening_socket():
            raise Exception("Failed to setup listening socket")

    def get_local_ip(self):
        """Get the actual LAN IP address with multiple fallback methods"""
        try:
            ips = []
            
            # Method 1: UDP connection to Google DNS
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ips.append(s.getsockname()[0])
                s.close()
            except:
                pass
            
            # Method 2: Network interfaces
            try:
                for interface in netifaces.interfaces():
                    for link in netifaces.ifaddresses(interface).get(netifaces.AF_INET, []):
                        if 'addr' in link and not link['addr'].startswith('127.'):
                            ips.append(link['addr'])
            except:
                pass
            
            # Method 3: Hostname lookup
            try:
                ips.append(socket.gethostbyname(socket.gethostname()))
            except:
                pass
            
            # Return the first valid IP we found
            for ip in ips:
                if ip and not ip.startswith('127.'):
                    return ip
                    
            return '127.0.0.1'
        except Exception as e:
            logging.error(f"Could not determine LAN IP: {e}")
            return '127.0.0.1'

    def find_available_port(self):
        """Find an available port starting from 5000"""
        for port in range(5000, 6000):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('0.0.0.0', port))
                sock.close()
                return port
            except:
                continue
        raise Exception("No available ports found")

    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def setup_listening_socket(self):
        try:
            self.listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                self.listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            self.listening_socket.bind(('0.0.0.0', self.listening_port))
            self.listening_socket.listen(5)
            logging.info(f"Listening on port {self.listening_port}")
            return True
        except Exception as e:
            logging.error(f"Failed to setup listening socket: {str(e)}")
            return False

    def initialize_network(self):
        """Start all network components"""
        self.running = True
        # Start UDP components first
        self.start_udp_broadcast()
        self.start_udp_listener()
        # Then start TCP listener
        threading.Thread(target=self.listen_for_connections, daemon=True).start()
            
    def start_udp_broadcast(self):
        """Broadcast our presence to the local network"""
        def broadcast_loop():
            while self.running:
                udp_socket = None
                try:
                    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    
                    pub_key_pem = self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode('utf-8')
                    
                    broadcast_msg = json.dumps({
                        'username': self.username,
                        'ip': '127.0.0.1',  # Force localhost for testing
                        'port': self.listening_port,
                        'public_key': pub_key_pem
                    })
                    
                    # Send to both broadcast and localhost
                    udp_socket.sendto(broadcast_msg.encode('utf-8'), ('255.255.255.255', 37020))
                    udp_socket.sendto(broadcast_msg.encode('utf-8'), ('127.0.0.1', 37020))
                    time.sleep(self.udp_broadcast_interval)
                    
                except Exception as e:
                    logging.error(f"Broadcast error: {str(e)}")
                    time.sleep(1)
                finally:
                    if udp_socket:
                        udp_socket.close()

        threading.Thread(target=broadcast_loop, daemon=True).start()

    def start_udp_listener(self):
        def listener_loop():
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            try:
                udp_socket.bind(('0.0.0.0', 37020))
                
                while self.running:
                    try:
                        data, addr = udp_socket.recvfrom(1024)
                        peer_info = json.loads(data.decode('utf-8'))
                        
                        if peer_info['username'] != self.username:
                            public_key = serialization.load_pem_public_key(
                                peer_info['public_key'].encode('utf-8'),
                                backend=self.backend
                            )
                            self.peers[peer_info['username']] = {
                                'ip': peer_info['ip'],
                                'port': peer_info['port'],
                                'public_key': public_key
                            }
                            logging.info(f"Discovered peer: {peer_info['username']} at {peer_info['ip']}:{peer_info['port']}")
                    except Exception as e:
                        logging.error(f"UDP listener error: {str(e)}")
            finally:
                udp_socket.close()

        threading.Thread(target=listener_loop, daemon=True).start()

    def connect_to_peer(self, peer_username):
        if peer_username not in self.peers:
            print(f"Peer {peer_username} not found in network")
            return False
        
        if self.connection_established:
            print(f"Already connected to {self.active_peer}. Disconnect first.")
            return False
            
        peer_info = self.peers[peer_username]
        
        try:
            with self.connection_lock:
                print(f"Attempting to connect to {peer_username} at {peer_info['ip']}:{peer_info['port']}...")
                self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.peer_socket.settimeout(10)  # Increased timeout
                
                # Set socket options for better connectivity
                self.peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, 'SO_REUSEPORT'):
                    self.peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                
                try:
                    self.peer_socket.connect((peer_info['ip'], peer_info['port']))
                    print("TCP connection established, starting handshake...")
                except socket.timeout:
                    print("Connection timed out. Possible issues:")
                    print(f"1. Is {peer_username} running and listening on port {peer_info['port']}?")
                    print(f"2. Is there a firewall blocking port {peer_info['port']}?")
                    print(f"3. Is the IP address correct? (Tried connecting to {peer_info['ip']})")
                    return False
                except ConnectionRefusedError:
                    print(f"Connection refused. Is {peer_username} running and accepting connections?")
                    return False
                
                # Exchange public keys
                self.peer_socket.send(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
                peer_public_key = serialization.load_pem_public_key(
                    self.peer_socket.recv(1024),
                    backend=self.backend
                )

                stored_key = self.peers[peer_username]['public_key'].public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                received_key = peer_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                # Verify the public key matches
                if stored_key != received_key:
                    print("Security alert: Public key mismatch!")
                    self.peer_socket.close()
                    return False
                
                self.active_peer = peer_username
                self.connection_established = True
                
                threading.Thread(
                    target=self.handle_incoming_messages,
                    daemon=True
                ).start()
                
                print(f"Connected to {peer_username}. Start chatting!")
                return True
                
        except ConnectionResetError:
            print(f"{peer_username} rejected the connection. Are they already connected?")
            return False
        except Exception as e:
            print(f"Failed to connect to {peer_username}: {str(e)}")
            if self.peer_socket:
                self.peer_socket.close()
            return False

    def listen_for_connections(self):
        while self.running:
            try:
                conn, addr = self.listening_socket.accept()
                print(f"\nIncoming connection from {addr[0]}:{addr[1]}")
                
                # Only accept one connection at a time
                if self.connection_established:
                    print("Already connected to another peer, rejecting")
                    conn.close()
                    continue
                    
                # Exchange public keys first
                peer_public_key = serialization.load_pem_public_key(
                    conn.recv(1024),
                    backend=self.backend
                )
                conn.send(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

                # Identify peer by public key
                peer_username = None
                for username, info in self.peers.items():
                    if info['public_key'].public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ) == peer_public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ):
                        peer_username = username
                        break

                if peer_username:
                    with self.message_lock:
                        self.active_peer = peer_username
                        self.peer_socket = conn
                        self.connection_established = True
                    
                    print(f"\n[System] {peer_username} connected to you!")
                    print(f"You ({self.username}) > ", end="", flush=True)
                    
                    threading.Thread(
                        target=self.handle_incoming_messages,
                        daemon=True
                    ).start()
                else:
                    print("\n[System] Unknown peer connection rejected")
                    conn.close()

            except Exception as e:
                if self.running:
                    logging.error(f"Listener error: {str(e)}")

    def handle_incoming_messages(self):
        try:
            while self.running and self.peer_socket:
                try:
                    # First get the message type (1 byte)
                    msg_type = self.peer_socket.recv(1)
                    if not msg_type:
                        break

                    if msg_type == b'M':  # Regular message
                        # Then get message length (4 bytes)
                        msg_length_bytes = self.peer_socket.recv(4)
                        if not msg_length_bytes or len(msg_length_bytes) != 4:
                            break
                        
                        msg_length = int.from_bytes(msg_length_bytes, byteorder='big')
                        encrypted_msg = b''
                        remaining = msg_length
                    
                        while remaining > 0:
                            try:
                                chunk = self.peer_socket.recv(min(4096, remaining))
                                if not chunk:
                                    break
                                encrypted_msg += chunk
                                remaining -= len(chunk)
                            except socket.timeout:
                                continue
                            except ConnectionResetError:
                                break

                        if remaining > 0:  # Didn't receive full message
                            break

                        try:
                            message = self.decrypt_message(encrypted_msg, self.private_key)
                            timestamp = datetime.now().strftime('%H:%M')
                        
                            # Clear current line and print message above prompt
                            sys.stdout.write(f"\r\033[K")  # Clear line
                            sys.stdout.write(f"[{timestamp}] {self.active_peer}: {message}\n")
                            sys.stdout.write(f"You ({self.username}) > ")
                            sys.stdout.flush()
                            
                        except Exception as e:
                            logging.error(f"Message decryption failed: {str(e)}")
                            continue

                    elif msg_type == b'F':  # File transfer
                        self.handle_file_transfer()

                except socket.timeout:
                    continue
                except ConnectionResetError:
                    break
                except Exception as e:
                    logging.error(f"Unexpected error: {str(e)}")
                    break
                
        except Exception as e:
            logging.error(f"Message handler crashed: {str(e)}")
        finally:
            self.cleanup_connection()

    def handle_file_transfer(self):
        try:
            # Receive file metadata (encrypted)
            metadata_length_bytes = self.peer_socket.recv(4)
            if not metadata_length_bytes or len(metadata_length_bytes) != 4:
                return
            
            metadata_length = int.from_bytes(metadata_length_bytes, byteorder='big')
            encrypted_metadata = self.peer_socket.recv(metadata_length)
            
            metadata = json.loads(self.decrypt_message(encrypted_metadata, self.private_key))
            filename = metadata['filename']
            filesize = metadata['filesize']
            filehash = metadata['filehash']
            
            print(f"\n[File Transfer] Receiving {filename} ({filesize/1024:.2f} KB)")
            print(f"You ({self.username}) > ", end="", flush=True)
            
            # Create downloads directory if it doesn't exist
            os.makedirs('downloads', exist_ok=True)
            filepath = os.path.join('downloads', filename)
            
            # Receive file content in chunks
            hasher = hashlib.sha256()
            received = 0
            with open(filepath, 'wb') as f:
                while received < filesize:
                    chunk = self.peer_socket.recv(min(4096, filesize - received))
                    if not chunk:
                        break
                    f.write(chunk)
                    hasher.update(chunk)
                    received += len(chunk)
            
            # Verify file hash
            if hasher.hexdigest() == filehash:
                print(f"\n[File Transfer] Successfully received {filename}")
            else:
                print(f"\n[File Transfer] Warning: File hash mismatch for {filename}")
                os.remove(filepath)
            
            print(f"You ({self.username}) > ", end="", flush=True)
            
        except Exception as e:
            print(f"\n[File Transfer] Error receiving file: {str(e)}")
            print(f"You ({self.username}) > ", end="", flush=True)

    def send_file(self, filepath):
        if not self.connection_established or not self.peer_socket:
            print("\n[System] Not connected to any peer")
            print(f"You ({self.username}) > ", end="", flush=True)
            return False
        
        try:
            if not os.path.exists(filepath):
                print(f"\n[File Transfer] File not found: {filepath}")
                print(f"You ({self.username}) > ", end="", flush=True)
                return False
            
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)
            
            # Calculate file hash
            hasher = hashlib.sha256()
            with open(filepath, 'rb') as f:
                while chunk := f.read(4096):
                    hasher.update(chunk)
            filehash = hasher.hexdigest()
            
            # Prepare metadata
            metadata = {
                'filename': filename,
                'filesize': filesize,
                'filehash': filehash
            }
            
            # Encrypt and send metadata
            encrypted_metadata = self.encrypt_message(json.dumps(metadata), 
                                                    self.peers[self.active_peer]['public_key'])
            
            # Send file transfer indicator
            self.peer_socket.send(b'F')
            
            # Send metadata length
            self.peer_socket.send(len(encrypted_metadata).to_bytes(4, byteorder='big'))
            
            # Send metadata
            self.peer_socket.send(encrypted_metadata)
            
            print(f"\n[File Transfer] Sending {filename} ({filesize/1024:.2f} KB)...")
            print(f"You ({self.username}) > ", end="", flush=True)
            
            # Send file content
            with open(filepath, 'rb') as f:
                while chunk := f.read(4096):
                    self.peer_socket.send(chunk)
            
            print(f"\n[File Transfer] File sent successfully")
            print(f"You ({self.username}) > ", end="", flush=True)
            return True
            
        except Exception as e:
            print(f"\n[File Transfer] Error sending file: {str(e)}")
            self.cleanup_connection()
            return False

    def cleanup_connection(self):
        if self.peer_socket:
            self.peer_socket.close()
        if self.active_peer:
            print(f"\n[System] Connection with {self.active_peer} closed")
        self.active_peer = None
        self.peer_socket = None
        self.connection_established = False
        print(f"You ({self.username}) > ", end="", flush=True)

    def send_message(self, message):
        if not self.connection_established or not self.peer_socket:
            print("\n[System] Not connected to any peer")
            print(f"You ({self.username}) > ", end="", flush=True)
            return False
        
        try:
            # Send message type indicator
            self.peer_socket.send(b'M')
            
            encrypted_msg = self.encrypt_message(
                message,
                self.peers[self.active_peer]['public_key']
            )
            # Send message length first
            msg_length = len(encrypted_msg).to_bytes(4, byteorder='big')
            self.peer_socket.sendall(msg_length + encrypted_msg)
            
            timestamp = datetime.now().strftime('%H:%M')
            print(f"\r[{timestamp}] You -> {self.active_peer}: {message}")
            print(f"You ({self.username}) > ", end="", flush=True)
            return True
        except Exception as e:
            print(f"\n[System] Error sending message: {e}")
            self.cleanup_connection()
            return False    

    def encrypt_message(self, message, public_key):
        return public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt_message(self, encrypted_msg, private_key):
        return private_key.decrypt(
            encrypted_msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode('utf-8')

    def list_peers(self):
        if not self.peers:
            print("No peers discovered yet")
            return
        
        print("\nDiscovered peers:")
        for i, (username, info) in enumerate(self.peers.items(), 1):
            print(f"{i}. {username} ({info['ip']}:{info['port']})")

    def cleanup(self):
        self.running = False
        if self.peer_socket:
            self.peer_socket.close()
        if self.listening_socket:
            self.listening_socket.close()

    def display_help(self):
        print("\nAvailable commands:")
        print("/help - Show this help")
        print("/list - List discovered peers")
        print("/connect <username> - Connect to a peer")
        print("/msg <message> - Send message to connected peer")
        print("/sendfile <filepath> - Send file to connected peer")
        print("/disconnect - Disconnect from current peer")
        print("/exit - Quit the application")

    def start(self):
        print(f"\nInitializing network for {self.username}...")
        self.initialize_network()
        
        print(f"\nP2P Chat started as {self.username}")
        print("Type /help for commands")
        print(f"You ({self.username}) > ", end="", flush=True)
        
        while True:
            try:
                command = input().strip()
                
                if not command:
                    print(f"You ({self.username}) > ", end="", flush=True)
                    continue
                
                if command.lower() in ["/exit", "/quit"]:
                    self.cleanup()
                    print("Goodbye!")
                    break
                
                elif command.lower() == "/disconnect":
                    if self.peer_socket:
                        self.peer_socket.close()
                        print(f"Disconnected from {self.active_peer}")
                        self.active_peer = None
                        self.peer_socket = None
                        self.connection_established = False
                    else:
                        print("Not currently connected to any peer")
                    print(f"You ({self.username}) > ", end="", flush=True)
                
                elif command.lower() in ["/help", "/?"]:
                    self.display_help()
                    print(f"You ({self.username}) > ", end="", flush=True)
                
                elif command.lower() == "/list":
                    self.list_peers()
                    print(f"You ({self.username}) > ", end="", flush=True)
                
                elif command.startswith("/connect"):
                    parts = command.split(maxsplit=1)
                    if len(parts) < 2:
                        print("\nUsage: /connect <username>")
                        print(f"You ({self.username}) > ", end="", flush=True)
                        continue
                    self.connect_to_peer(parts[1])
                    print(f"You ({self.username}) > ", end="", flush=True)
                
                elif command.startswith("/msg"):
                    if not self.connection_established:
                        print("\n[System] Not connected to any peer")
                        print(f"You ({self.username}) > ", end="", flush=True)
                        continue
                    
                    parts = command.split(maxsplit=1)
                    if len(parts) < 2:
                        print("\nUsage: /msg <message>")
                        print(f"You ({self.username}) > ", end="", flush=True)
                        continue
                    
                    self.send_message(parts[1])
                
                elif command.startswith("/sendfile"):
                    if not self.connection_established:
                        print("\n[System] Not connected to any peer")
                        print(f"You ({self.username}) > ", end="", flush=True)
                        continue
                    
                    parts = command.split(maxsplit=1)
                    if len(parts) < 2:
                        print("\nUsage: /sendfile <filepath>")
                        print(f"You ({self.username}) > ", end="", flush=True)
                        continue
                    
                    self.send_file(parts[1])
                
                else:
                    print("\n[System] Unknown command. Type /help for help.")
                    print(f"You ({self.username}) > ", end="", flush=True)
            
            except KeyboardInterrupt:
                print("\nType /exit to quit")
                print(f"You ({self.username}) > ", end="", flush=True)
                continue
            except Exception as e:
                print(f"\n[System] Error: {e}")
                print(f"You ({self.username}) > ", end="", flush=True)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python p2p_chat.py <username>")
        sys.exit(1)
    
    username = sys.argv[1]
    try:
        node = P2PChatNode(username)
        node.start()
    except Exception as e:
        print(f"Fatal error: {e}")