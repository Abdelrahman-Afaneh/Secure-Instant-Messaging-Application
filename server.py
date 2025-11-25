# server.py
import socket
import threading
import json
import base64
from typing import Dict, List, Any

HOST = '0.0.0.0'
PORT = 9001


users_public_keys: Dict[str, str] = {}
connected_clients: Dict[str, socket.socket] = {}
offline_messages: Dict[str, List[Dict[str, Any]]] = {}

lock = threading.Lock()


def send_json(conn: socket.socket, obj: dict):
    # I send JSON data with length prefix for reliable transmission
    data = json.dumps(obj).encode()
    conn.sendall(len(data).to_bytes(4, 'big') + data)


def recv_json(conn: socket.socket):
    # I read the 4-byte length prefix first
    header = conn.recv(4)
    if not header:
        return None
    length = int.from_bytes(header, 'big')
    data = b''
    # I keep reading until I have the complete message
    while len(data) < length:
        packet = conn.recv(length - len(data))
        if not packet:
            return None
        data += packet
    return json.loads(data.decode())


def handle_client(conn: socket.socket, addr):
    username = None
    try:
        while True:
            msg = recv_json(conn)
            if msg is None:
                break
            typ = msg.get('type')
            if typ == 'REGISTER':
                # I handle user registration with their public key
                username = msg['username']
                pub_pem = msg['public_key_pem']
                with lock:
                    users_public_keys[username] = pub_pem
                    connected_clients[username] = conn
                    if username not in offline_messages:
                        offline_messages[username] = []
                print(f"[REGISTER] {username} from {addr}")
                send_json(conn, {'type': 'REGISTERED', 'status': 'ok'})
                # I deliver any pending offline messages for this user
                with lock:
                    pending = offline_messages.get(username, [])
                    for m in pending:
                        send_json(conn, {'type': 'FORWARDED', 'payload': m})
                    offline_messages[username] = []
            elif typ == 'GET_PUBLIC_KEY':
                # I handle requests for other users' public keys
                target = msg['target']
                with lock:
                    pk = users_public_keys.get(target)
                send_json(conn, {
                    'type': 'PUBLIC_KEY',
                    'target': target,
                    'public_key_pem': pk
                })
            elif typ == 'FORWARD':
                # I forward messages between users
                recipient = msg['recipient']
                payload = msg['payload']
                with lock:
                    dest = connected_clients.get(recipient)
                    if dest:
                        # I send message to online recipient
                        send_json(dest, {
                            'type': 'FORWARDED',
                            'from': msg.get('from'),
                            'payload': payload
                        })
                        send_json(conn, {
                            'type': 'DELIVERED',
                            'to': recipient
                        })
                    else:
                        # I store message for offline recipient
                        offline_messages.setdefault(recipient, []).append({
                            'from': msg.get('from'),
                            'payload': payload
                        })
                        send_json(conn, {
                            'type': 'STORED_OFFLINE',
                            'to': recipient
                        })
            elif typ == 'WHOAMI':
                # I tell client their username
                send_json(conn, {'type': 'WHOAMI', 'username': username})
            elif typ == 'LIST_USERS':
                # I return list of all users with online status
                with lock:
                    users_list = []
                    for uname in users_public_keys.keys():
                        users_list.append({
                            'username': uname,
                            'online': uname in connected_clients
                        })
                send_json(conn, {'type': 'USERS', 'users': users_list})
            else:
                send_json(conn, {
                    'type': 'ERROR',
                    'message': 'unknown message type'
                })
    except Exception as e:
        print("Client handler error:", e)
    finally:
        # I clean up when client disconnects
        with lock:
            if username and username in connected_clients:
                del connected_clients[username]
        conn.close()
        print(f"Connection {addr} closed.")


def main():
    # I start the main server loop
    print(f"Starting server on {HOST}:{PORT}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)
    try:
        while True:
            # I accept new client connections
            conn, addr = s.accept()
            print("Accepted connection from", addr)
            threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print("Shutting down server.")
    finally:
        s.close()


if __name__ == '__main__':
    main()
