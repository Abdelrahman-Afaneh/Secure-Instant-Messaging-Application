# client_gui.py
# Simple GUI wrapper around your existing encrypted Client class

import threading
import base64
import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

import tkinter as tk
from tkinter import scrolledtext, messagebox

# Import your existing Client + helpers from client.py
from client import Client, load_private_key


class GUIClient(Client):
    """
    Extends your existing Client class so that instead of printing messages
    to the terminal, it can pass them into the GUI via callbacks.
    """
    def __init__(self, username, on_message, on_status,
                 server_host='127.0.0.1', server_port=9001):
        super().__init__(username, server_host, server_port)
        self.on_message = on_message      # function(sender, text, verified)
        self.on_status = on_status        # function(text)

    def _handle_payload(self, sender: str, payload: dict):
        """
        Copied from your original _handle_payload, but instead of printing,
        it calls GUI callbacks.
        """
        st = payload.get('subtype')

        if st == 'SESSION_KEY':
            enc_b64 = payload['encrypted_key_b64']
            enc = base64.b64decode(enc_b64)

            if not self.private_key:
                self.private_key = load_private_key(self.username)

            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            key = cipher_rsa.decrypt(enc)

            self.session_keys[sender] = key

            # Notify GUI that session key arrived
            if self.on_status:
                self.on_status(
                    f"Session key received from {sender}. "
                    f"You can now receive encrypted messages."
                )

            # Preemptively request sender's public key
            if sender not in self.public_keys_cache:
                threading.Thread(
                    target=self.request_public_key,
                    args=(sender,),
                    daemon=True
                ).start()

        elif st == 'MESSAGE':
            ct_with_tag = base64.b64decode(payload['ciphertext_b64'])
            nonce = base64.b64decode(payload['nonce_b64'])
            sig = base64.b64decode(payload['signature_b64'])

            key = self.session_keys.get(sender)
            if not key:
                if self.on_status:
                    self.on_status(
                        f"No session key for {sender}, "
                        f"cannot decrypt message."
                    )
                return

            # Split ciphertext and GCM tag (last 16 bytes)
            ct = ct_with_tag[:-16]
            tag = ct_with_tag[-16:]

            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            try:
                plaintext = cipher.decrypt_and_verify(ct, tag).decode()
            except Exception as e:
                if self.on_status:
                    self.on_status(f"Decryption failed from {sender}: {e}")
                return

            # Verify signature
            verified = False
            sender_pub_pem = self.public_keys_cache.get(sender)
            if not sender_pub_pem:
                sender_pub_pem = self.request_public_key(sender)

            if sender_pub_pem:
                try:
                    sender_pub = RSA.import_key(sender_pub_pem.encode())
                    h = SHA256.new(plaintext.encode())
                    pkcs1_15.new(sender_pub).verify(h, sig)
                    verified = True
                except Exception:
                    verified = False

            # Send to GUI
            if self.on_message:
                self.on_message(sender, plaintext, verified)

        else:
            if self.on_status:
                self.on_status(f"Unknown payload subtype from {sender}: {st}")


def start_gui():
    root = tk.Tk()
    root.title("Secure Chat Client")

    # ---------- Top frame: username + connect ----------
    top_frame = tk.Frame(root)
    top_frame.pack(padx=10, pady=5, fill="x")

    tk.Label(top_frame, text="Username:").pack(side="left")
    username_entry = tk.Entry(top_frame, width=15)
    username_entry.pack(side="left", padx=5)

    connect_btn = tk.Button(top_frame, text="Connect")
    connect_btn.pack(side="left", padx=5)

    # NEW: Contacts + History buttons
    contacts_btn = tk.Button(top_frame, text="Contacts")
    contacts_btn.pack(side="left", padx=5)

    history_btn = tk.Button(top_frame, text="History")
    history_btn.pack(side="left", padx=5)

    status_label = tk.Label(root, text="Not connected", anchor="w")
    status_label.pack(fill="x", padx=10)

    # ---------- Middle frame: chat display ----------
    chat_box = scrolledtext.ScrolledText(
        root, wrap="word", height=20, state="disabled"
    )
    chat_box.pack(padx=10, pady=5, fill="both", expand=True)

    # ---------- Bottom frame: target + message + send ----------
    bottom_frame = tk.Frame(root)
    bottom_frame.pack(padx=10, pady=5, fill="x")

    tk.Label(bottom_frame, text="To:").grid(row=0, column=0, sticky="w")
    target_entry = tk.Entry(bottom_frame, width=15)
    target_entry.grid(row=0, column=1, padx=5, sticky="w")

    tk.Label(bottom_frame, text="Message:").grid(row=1, column=0, sticky="w")
    message_entry = tk.Entry(bottom_frame, width=50)
    message_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

    send_btn = tk.Button(bottom_frame, text="Send")
    send_btn.grid(row=1, column=2, padx=5)

    # Will hold the GUIClient instance once connected
    client_holder = {"client": None}

    # ---------- Helper functions ----------

    def append_chat(text: str):
        """Safely append text to the chat box from any thread."""
        def _append():
            chat_box.config(state="normal")
            chat_box.insert("end", text + "\n")
            chat_box.config(state="disabled")
            chat_box.see("end")
        root.after(0, _append)

    def timestamp():
        """Returns HH:MM:SS string."""
        return time.strftime("%H:%M:%S")

    def on_status(msg: str):
        """Callback from client to update status + chat."""
        ts = timestamp()
        def _update():
            status_label.config(text=msg)
            append_chat(f"[{ts}] [STATUS] {msg}")
        root.after(0, _update)

    def on_message(sender: str, text: str, verified: bool):
        """Callback from client when a message arrives."""
        ts = timestamp()
        ver_str = "✔" if verified else "✖"
        append_chat(f"[{ts}] [FROM {sender}][sig {ver_str}] {text}")

    def do_connect():
        if client_holder["client"] is not None:
            messagebox.showinfo("Info", "Already connected.")
            return

        username = username_entry.get().strip()
        if not username:
            messagebox.showerror("Error", "Please enter a username.")
            return

        c = GUIClient(username, on_message, on_status)

        try:
            c.connect()   # opens socket + starts listener thread
            c.register()  # generates keys (if needed) + REGISTER message
            client_holder["client"] = c
            on_status(f"Connected as {username}")
        except Exception as e:
            messagebox.showerror("Connection error", str(e))
            client_holder["client"] = None

    def do_send():
        c = client_holder["client"]
        if c is None:
            messagebox.showerror("Error", "You must connect first.")
            return

        target = target_entry.get().strip()
        msg = message_entry.get().strip()

        if not target:
            messagebox.showerror("Error",
                                 "Please enter the recipient username.")
            return

        if not msg:
            return

        ts = timestamp()

        # Send encrypted message
        c.send_message(target, msg)

        # Show our own message with timestamp
        append_chat(f"[{ts}] [TO {target}] {msg}")
        message_entry.delete(0, "end")

    # NEW: show contacts (basic)
    def do_show_contacts():
        c = client_holder["client"]
        if c is None:
            messagebox.showerror("Error", "You must connect first.")
            return
        on_status("Requesting contacts list from server...")
        c.list_users()

    # NEW: show history (basic)
    def do_show_history():
        c = client_holder["client"]
        if c is None:
            messagebox.showerror("Error", "You must connect first.")
            return

        hist = c.get_history()
        if not hist:
            append_chat(f"[{timestamp()}] [HISTORY] No messages yet.")
            return

        append_chat(f"[{timestamp()}] [HISTORY] -----")
        for other, entries in hist.items():
            append_chat(f"[{timestamp()}] [HISTORY] With {other}:")
            for h in entries:
                line = (f"  [{h['time']}] {h['direction']} "
                        f"({h['status']}): {h['text']}")
                append_chat(line)
        append_chat(f"[{timestamp()}] [HISTORY] -----")

    connect_btn.config(command=do_connect)
    send_btn.config(command=do_send)
    contacts_btn.config(command=do_show_contacts)
    history_btn.config(command=do_show_history)

    root.mainloop()


if __name__ == "__main__":
    start_gui()
