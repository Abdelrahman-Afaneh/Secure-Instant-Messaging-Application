Secure Encrypted Messaging System

This project is a secure multi-user messaging system built with Python.
It uses RSA for key exchange and digital signatures, and AES for message
encryption. A Tkinter GUI is included for sending and receiving
encrypted messages.

  ------------
  Main Files
  ------------

server.py - Handles multiple clients - Stores public keys for all
users - Forwards encrypted messages without decrypting - Saves offline
messages and sends them when the user reconnects - Stores message
history per user

client.py - Generates RSA keys automatically - Loads existing keys if
available - Creates and manages AES session keys - Encrypts outgoing
messages with AES - Signs messages with RSA - Verifies message
signatures - Communicates with the server using JSON

GUI.py - Tkinter interface for chat - Shows timestamps - Shows signature
verification status - Runs client logic in the background threads

  -------------------
  How Messages Work
  -------------------

1.  Client generates RSA keys if missing.
2.  Client sends its public key to the server.
3.  For each chat:
    -   A new AES session key is created.
    -   AES key is encrypted using the receiver’s RSA public key.
    -   Server forwards the encrypted session key.
4.  Messages are encrypted with AES and signed with RSA.
5.  Offline messages are stored by the server and delivered later.
6.  Client verifies all incoming signatures.

  ------------
  How to Run
  ------------

Install dependency: pip install pycryptodome

Start the server: python3 server.py

Start the GUI client: python3 GUI.py

Open multiple GUI windows to simulate multiple users.

  -------------------
  Security Features
  -------------------

-   RSA-2048 key pairs
-   AES-256 message encryption
-   RSA-encrypted AES session keys
-   Digital signatures
-   Offline message support
-   Message history
-   No plaintext transmitted
-   Per-user session keys
