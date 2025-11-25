# client.py
import socket
import json
import threading
import base64
import os
import sys
import time
from typing import Optional, Dict, Any, List

# I import these cryptographic libraries to handle RSA, AES, and digital signatures
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# I set the server address and port for connections
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9001

# I define where to store the cryptographic keys for each user
KEYS_DIR = 'keys'
RSA_PRIV_FILE = lambda u: os.path.join(KEYS_DIR, f"{u}_private.pem")
RSA_PUB_FILE = lambda u: os.path.join(KEYS_DIR, f"{u}_public.pem")


def ensure_keys_dir():
    # I create the keys directory if it doesn't exist yet
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)


def gen_rsa_keypair(username: str):
    # I generate an RSA key pair for a new user
    ensure_keys_dir()
    priv_path = RSA_PRIV_FILE(username)
    pub_path = RSA_PUB_FILE(username)
    
    # I check if this user already has keys to avoid overwriting them
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        print("Existing keys found.")
        return

    # I create a 2048-bit RSA key pair
    key = RSA.generate(2048)

    # I save the private key to a file securely
    priv_pem = key.export_key('PEM')
    with open(priv_path, 'wb') as f:
        f.write(priv_pem)

    # I save the public key to share with other users
    pub_pem = key.publickey().export_key('PEM')
    with open(pub_path, 'wb') as f:
        f.write(pub_pem)

    print("RSA key pair generated and saved.")


def load_private_key(username: str):
    # I load the user's private RSA key from the file
    path = RSA_PRIV_FILE(username)
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())


def load_public_pem(username: str) -> Optional[str]:
    # I load the user's public key from the file
    path = RSA_PUB_FILE(username)
    if not os.path.exists(path):
        return None
    with open(path, 'rb') as f:
        return f.read().decode()


def send_json(conn: socket.socket, obj: dict):
    # I send JSON data over the socket with a length prefix
    data = json.dumps(obj).encode()
    # I send the length first so the receiver knows how much data to expect
    conn.sendall(len(data).to_bytes(4, 'big') + data)


def recv_json(conn: socket.socket):
    # I receive JSON data by reading the length prefix first
    header = conn.recv(4)
    if not header:
        return None
    # I get the data length from the first 4 bytes
    length = int.from_bytes(header, 'big')
    data = b''
    # I keep receiving data until I have the complete message
    while len(data) < length:
        packet = conn.recv(length - len(data))
        if not packet:
            return None
        data += packet
    return json.loads(data.decode())

class Client:
    def __init__(self, username: str,
                 server_host=SERVER_HOST,
                 server_port=SERVER_PORT):
        self.username = username
        self.server_host = server_host
        self.server_port = server_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # I store the user's private RSA key here
        self.private_key = None
        # I store the user's public key in PEM format here  
        self.public_pem = None
        # I keep AES session keys for each contact I talk to
        self.session_keys: Dict[str, bytes] = {}
        # I cache other users' public keys so I don't have to ask the server every time
        self.public_keys_cache: Dict[str, str] = {}
        # I use this lock to protect shared data between threads
        self.lock = threading.Lock()
        # I track events for public key requests that are waiting for responses
        self.pubkey_events: Dict[str, threading.Event] = {}

        # I store message history organized by contact name
        self.history: Dict[str, List[Dict[str, Any]]] = {}

    def connect(self):
        # I connect to the server using TCP
        self.sock.connect((self.server_host, self.server_port))
        print("Connected to server.")
        # I start a background thread to listen for incoming messages
        threading.Thread(target=self._listener, daemon=True).start()

    def register(self):
        # I generate RSA key pair for this user
        gen_rsa_keypair(self.username)
        # I load the private key from file
        self.private_key = load_private_key(self.username)
        # I load the public key from file  
        self.public_pem = load_public_pem(self.username)
        # I send registration message to server with my public key
        send_json(self.sock, {
            'type': 'REGISTER',
            'username': self.username,
            'public_key_pem': self.public_pem
        })
        time.sleep(0.1)  # I wait a bit for server to process registration

    def request_public_key(self, target: str) -> Optional[str]:
        with self.lock:
            # I check if I already have this user's public key in cache
            if target in self.public_keys_cache:
                return self.public_keys_cache[target]

            # I create an event to wait for the public key response
            event = threading.Event()
            self.pubkey_events[target] = event

        # I ask the server for the target user's public key
        send_json(self.sock, {'type': 'GET_PUBLIC_KEY', 'target': target})

        # I wait up to 5 seconds for the public key to arrive
        if event.wait(timeout=5.0):
            with self.lock:
                return self.public_keys_cache.get(target)
        return None

    def send_session_key(self, target: str):
        # I generate a random 256-bit AES key for secure messaging
        key = get_random_bytes(32)

        # I get the recipient's public key from the server
        target_pub_pem = self.request_public_key(target)
        if not target_pub_pem:
            print("No public key for target.")
            return False

        # I import the recipient's public RSA key
        target_pub = RSA.import_key(target_pub_pem.encode())
        # I create RSA cipher with OAEP padding for encryption
        cipher_rsa = PKCS1_OAEP.new(target_pub)
        # I encrypt the AES session key with recipient's public key
        encrypted_key = cipher_rsa.encrypt(key)

        # I encode the encrypted key in base64 for JSON transmission
        b64 = base64.b64encode(encrypted_key).decode()
        
        # I send the encrypted session key to recipient through server
        send_json(self.sock, {
            'type': 'FORWARD',
            'from': self.username,
            'recipient': target,
            'payload': {
                'subtype': 'SESSION_KEY',
                'encrypted_key_b64': b64
            }
        })
        
        # I store the session key locally for encrypting future messages
        self.session_keys[target] = key
        print(f"Session key created and sent to {target}.")
        return True

    def _add_history(self, other: str, direction: str,
                     text: str, status: str):
        # I create a timestamp for this message entry
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = {
            'time': ts,
            'direction': direction,
            'text': text,
            'status': status
        }
        with self.lock:
            # I add this message to history for the specified contact
            self.history.setdefault(other, []).append(entry)

    def _update_last_outgoing_status(self, other: str, new_status: str):
        with self.lock:
            entries = self.history.get(other)
            if not entries:
                return
            # I find the most recent outgoing message and update its status
            for e in reversed(entries):
                if e.get('direction') == 'out':
                    e['status'] = new_status
                    break

    def get_history(self) -> Dict[str, List[Dict[str, Any]]]:
        with self.lock:
            # I return a thread-safe copy of the message history
            return {k: list(v) for k, v in self.history.items()}

    def list_users(self):
        # I ask server for list of all registered users
        send_json(self.sock, {'type': 'LIST_USERS'})

    def send_message(self, target: str, plaintext: str):
        # I check if I have a session key for this contact
        key = self.session_keys.get(target)
        if not key:
            print("No session key for target. Sending session key first.")
            ok = self.send_session_key(target)
            if not ok:
                return
            key = self.session_keys[target]
            time.sleep(0.5)

        # I use AES-GCM mode for encryption with built-in authentication
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(plaintext.encode())

        # I combine ciphertext and authentication tag for transmission
        ct_with_tag = ct + tag
        ct_b64 = base64.b64encode(ct_with_tag).decode()
        nonce_b64 = base64.b64encode(nonce).decode()

        # I create digital signature of the message using my private key
        h = SHA256.new(plaintext.encode())
        signature = pkcs1_15.new(self.private_key).sign(h)
        sig_b64 = base64.b64encode(signature).decode()

        payload = {
            'subtype': 'MESSAGE',
            'ciphertext_b64': ct_b64,
            'nonce_b64': nonce_b64,
            'signature_b64': sig_b64,
            'plaintext_len': len(plaintext)
        }
        send_json(self.sock, {
            'type': 'FORWARD',
            'from': self.username,
            'recipient': target,
            'payload': payload
        })
        print(f"Sent encrypted message to {target}.")

        # I record this outgoing message in history as 'sent'
        self._add_history(target, 'out', plaintext, 'sent')

    def _listener(self):
        # I run this loop continuously to handle incoming messages
        while True:
            try:
                msg = recv_json(self.sock)
                if msg is None:
                    print("Server disconnected.")
                    break
                typ = msg.get('type')
                if typ == 'FORWARDED':
                    # I handle a message forwarded from another user
                    sender = msg.get('from')
                    payload = msg.get('payload')
                    self._handle_payload(sender, payload)
                elif typ == 'DELIVERED':
                    # I handle delivery confirmation from server
                    to = msg.get('to')
                    print(f"Server: message delivered to {to}")
                    self._update_last_outgoing_status(to, 'delivered')
                    if hasattr(self, 'on_status') and callable(self.on_status):
                        self.on_status(f"Message to {to} delivered.")
                elif typ == 'STORED_OFFLINE':
                    # I handle notification that message was stored offline
                    to = msg.get('to')
                    print(f"Server stored message offline for {to}")
                    self._update_last_outgoing_status(to, 'offline_stored')
                    if hasattr(self, 'on_status') and callable(self.on_status):
                        self.on_status(f"Message to {to} stored offline.")
                elif typ == 'PUBLIC_KEY':
                    # I handle response with requested public key
                    target = msg.get('target')
                    pk = msg.get('public_key_pem')
                    with self.lock:
                        self.public_keys_cache[target] = pk
                        if target in self.pubkey_events:
                            self.pubkey_events[target].set()
                elif typ == 'REGISTERED':
                    print("Registered successfully with server.")
                elif typ == 'USERS':
                    # I handle response with list of all users
                    users = msg.get('users', [])
                    print("Users:")
                    for u in users:
                        print(f" - {u.get('username')} "
                              f"(online={u.get('online')})")
                    if hasattr(self, 'on_status') and callable(self.on_status):
                        if users:
                            online = [u['username']
                                      for u in users if u.get('online')]
                            offline = [u['username']
                                       for u in users if not u.get('online')]
                            msg_txt = "Contacts:\n"
                            if online:
                                msg_txt += "Online: " + ", ".join(online)
                            if offline:
                                if online:
                                    msg_txt += " | "
                                msg_txt += "Offline: " + ", ".join(offline)
                        else:
                            msg_txt = "No contacts registered yet."
                        self.on_status(msg_txt)
                else:
                    print("Server message:", msg)
            except Exception as e:
                print("Listener error:", e)
                break

    def _handle_payload(self, sender: str, payload: dict):
        st = payload.get('subtype')
        if st == 'SESSION_KEY':
            # I handle incoming encrypted session key
            enc_b64 = payload['encrypted_key_b64']
            enc = base64.b64decode(enc_b64)
            if not self.private_key:
                self.private_key = load_private_key(self.username)

            # I decrypt the session key using my private RSA key
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            key = cipher_rsa.decrypt(enc)

            self.session_keys[sender] = key
            print(
                f"\nReceived session key from {sender}. "
                f"Now you can receive encrypted messages."
            )

            # I request sender's public key for future signature verification
            if sender not in self.public_keys_cache:
                threading.Thread(
                    target=self.request_public_key,
                    args=(sender,),
                    daemon=True
                ).start()

        elif st == 'MESSAGE':
            # I handle an encrypted message from another user
            ct_with_tag = base64.b64decode(payload['ciphertext_b64'])
            nonce = base64.b64decode(payload['nonce_b64'])
            sig = base64.b64decode(payload['signature_b64'])

            key = self.session_keys.get(sender)
            if not key:
                print("\nNo session key for this sender. Can't decrypt.")
                return

            # I split ciphertext from authentication tag (last 16 bytes)
            ct = ct_with_tag[:-16]
            tag = ct_with_tag[-16:]

            # I decrypt and verify the message integrity
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            try:
                plaintext = cipher.decrypt_and_verify(ct, tag).decode()
            except Exception as e:
                print("\nDecryption failed:", e)
                return

            # I verify the digital signature to authenticate sender
            verified = False
            with self.lock:
                sender_pub_pem = self.public_keys_cache.get(sender)

            if not sender_pub_pem:
                # I try to fetch sender's public key if not cached
                sender_pub_pem = self.request_public_key(sender)

            if sender_pub_pem:
                try:
                    sender_pub = RSA.import_key(sender_pub_pem.encode())
                    h = SHA256.new(plaintext.encode())
                    pkcs1_15.new(sender_pub).verify(h, sig)
                    verified = True
                except (ValueError, TypeError):
                    verified = False
                except Exception as e:
                    print(f"\nSignature verification error: {e}")
                    verified = False

            print(f"\n=== New message from {sender} ===")
            print("Decrypted message:", plaintext)
            print("Signature verified:", verified)
            print("================================\n")

            # I add incoming message to history with verification status
            status = 'received_verified' if verified else 'received_unverified'
            self._add_history(sender, 'in', plaintext, status)
        else:
            print("\nUnknown forwarded subtype:", st)


def interactive_cli(username):
    # I create a client instance for the specified username
    c = Client(username)
    c.connect()
    c.register()
    time.sleep(0.3)
    print("\nCommands:")
    print("/pub <user>          - get public key of user")
    print("/sendkey <user>      - create & send session key to user")
    print("/msg <user> <text>   - send encrypted message")
    print("/users               - list contacts (basic)")
    print("/history <user>      - show history with user")
    print("/whoami              - check username on server")
    print("/exit\n")
    while True:
        try:
            line = input("> ").strip()
        except EOFError:
            break
        if not line:
            continue
        parts = line.split(' ', 2)
        cmd = parts[0]
        if cmd == '/pub' and len(parts) >= 2:
            target = parts[1]
            pk = c.request_public_key(target)
            print(f"Public key for {target}:")
            print(pk)
        elif cmd == '/sendkey' and len(parts) >= 2:
            target = parts[1]
            c.send_session_key(target)
        elif cmd == '/msg' and len(parts) >= 3:
            target = parts[1]
            text = parts[2]
            c.send_message(target, text)
        elif cmd == '/users':
            c.list_users()
        elif cmd == '/history' and len(parts) >= 2:
            target = parts[1]
            hist = c.get_history().get(target, [])
            if not hist:
                print(f"No history with {target}.")
            else:
                print(f"History with {target}:")
                for h in hist:
                    print(f"[{h['time']}] "
                          f"{h['direction']} "
                          f"({h['status']}): {h['text']}")
        elif cmd == '/whoami':
            send_json(c.sock, {'type': 'WHOAMI'})
            time.sleep(0.1)
        elif cmd == '/exit':
            print("bye")
            c.sock.close()
            break
        else:
            print("Unknown command.")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python client.py <username>")
        sys.exit(1)
    uname = sys.argv[1]
    interactive_cli(uname)
