import socket
import threading
import os
import time
import secrets
import datetime
import base64
from Crypto.Cipher import AES

# Server configuration
HOST = 'localhost'
PORT = 15000
KEY = b'mysecretpassword'  # Default encryption key

# Thread-safe lock for file operations
file_lock = threading.Lock()

# User management dictionaries
registered_users = {}      # Maps usernames to passwords
online_users = {}          # Maps usernames to socket connections
user_tokens = {}           # Maps usernames to session tokens
token_to_username = {}     # Maps tokens to usernames
socket_to_username = {}    # Maps socket connections to usernames
user_encryption_keys = {}  # Maps usernames to their encryption keys
hello_received = {}        # Tracks if client has sent HELLO command


def generate_random_key():
    """Generate a random 16-byte encryption key."""
    return os.urandom(16)


def encrypt(message, user_key=KEY):
    """
    Encrypt a message using AES-EAX mode.
    
    Args:
        message: The string message to encrypt
        user_key: The encryption key to use (defaults to server KEY)
        
    Returns:
        Base64 encoded encrypted message string
    """
    cipher = AES.new(user_key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(nonce + tag + ciphertext).decode()


def decrypt(encrypted_message, user_key=KEY):
    """
    Decrypt a message using AES-EAX mode.
    
    Args:
        encrypted_message: Base64 encoded encrypted message
        user_key: The encryption key to use (defaults to server KEY)
        
    Returns:
        Decrypted message as a string
    """
    data = base64.b64decode(encrypted_message)
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(user_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


def send_new_key_to_client(client_socket, username):
    """
    Generate and send a new encryption key to a client.
    
    Args:
        client_socket: The client's socket connection
        username: The username of the client
        
    Returns:
        The newly generated encryption key
    """
    key = generate_random_key()
    user_encryption_keys[username] = key
    encrypted_key = base64.b64encode(key).decode()
    client_socket.send(f"Key {encrypted_key}".encode())
    print(f"🔑 Sent new key to {username}: {key.hex()}")
    return key


def send_message(client_socket, message, username=None):
    """
    Encrypt and send a message to a client.
    
    Args:
        client_socket: The client's socket connection
        message: The message to send
        username: Optional username to use their specific encryption key
    """
    try:
        # Use user-specific key if available, otherwise use default key
        if username and username in user_encryption_keys:
            key = user_encryption_keys[username]
        else:
            key = KEY
            
        encrypted_message = encrypt(message, key)
        client_socket.send(encrypted_message.encode())
        time.sleep(0.1)  # Small delay to prevent message overlap
    except Exception as e:
        print(f"❌ Error sending message: {e}")


def validate_token(token):
    """
    Validate a session token.
    
    Args:
        token: The session token to validate
        
    Returns:
        Tuple of (username, is_valid_boolean)
    """
    print(f"🔍 Validating token: {token}")
    if token in token_to_username:
        username = token_to_username[token]
        return username, True
    return None, False


def initialize_history_file():
    """
    Initialize the chat history file if it doesn't exist.
    
    Returns:
        Boolean indicating success or failure
    """
    try:
        with file_lock:
            if not os.path.exists("chat_history.txt"):
                with open("chat_history.txt", "w", encoding="utf-8") as f:
                    f.write("--- Chat history initialized ---\n")
        return True
    except Exception as e:
        print(f"❌ Error initializing history file: {e}")
        return False


def save_message(message, message_type=None):
    """
    Save a message to the chat history file with timestamp.
    
    Args:
        message: The message to save
        message_type: Type of message ('PUBLIC' or 'PRIVATE')
        
    Returns:
        Boolean indicating success or failure
    """
    # Only save actual chat messages, not system messages
    if message_type in ['PUBLIC', 'PRIVATE']:
        with file_lock:
            try:
                timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
                with open("chat_history.txt", "a", encoding="utf-8") as f:
                    f.write(timestamp + message + "\n")
                print(f"✅ Saved to history: {message}")
                return True
            except Exception as e:
                print(f"❌ Error saving message: {e}")
                return False
    else:
        # Just print to console but don't save to history
        print(f"Not saved to history: {message}")
        return True


def handle_client(client_socket):
    """
    Handle communication with a connected client.
    
    Args:
        client_socket: The client's socket connection
    """
    username = None
    token = None
    hello_received[client_socket] = False
    
    # Initialize history file when a new client connects
    if not os.path.exists("chat_history.txt"):
        initialize_history_file()
        
    try:
        socket_to_username[client_socket] = None
        while True:
            encrypted_data = client_socket.recv(1024)
            if not encrypted_data:
                break
                
            try:
                data = decrypt(encrypted_data.decode())
                print(f"Received command from client: {data}")
            except Exception as e:
                print(f"❌ Decryption error: {e}")
                continue

            command = data.split()[0]

            # Check if HELLO has been received before proceeding with other commands
            if command not in ["REGISTER", "LOGIN"] and not hello_received[client_socket]:
                if command == "HELLO":
                    hello_received[client_socket] = True
                    send_message(client_socket, "✅ Welcome! You can now send messages.")
                else:
                    send_message(client_socket, "⚠️ Error: You must send 'HELLO' first!")
                    continue

            # Handle REGISTER command
            if data.startswith("REGISTER"):
                try:
                    _, username, password = data.split()
                    if username in registered_users:
                        send_message(client_socket, "Error: Username exists!")
                    else:
                        registered_users[username] = password
                        send_message(client_socket, "Registration successful!")
                        # System message - not saved to history
                        print(f"SYSTEM: User {username} registered")
                except ValueError:
                    send_message(client_socket, "Error: Invalid REGISTER format! Use: REGISTER <username> <password>")

            # Handle LOGIN command
            elif data.startswith("LOGIN"):
                try:
                    _, username, password = data.split()
                    
                    if username in registered_users and registered_users[username] == password:
                        # Prevent multiple logins from different sessions
                        if username in online_users:
                            send_message(client_socket, "❌ You are already logged in from another session! Please logout first.")
                            continue

                        # Generate and store session token
                        token = secrets.token_hex(16)
                        user_tokens[username] = token
                        token_to_username[token] = username
                        socket_to_username[client_socket] = username

                        send_message(client_socket, f"Login successful! Your token: {token}")
                        send_message(client_socket, "✅ Please send 'HELLO' to join the chat room.")

                        # System message - not saved to history
                        print(f"SYSTEM: User {username} logged in")
                    else:
                        send_message(client_socket, "❌ Error: Invalid credentials!")
                except ValueError:
                    send_message(client_socket, "❌ Error: Invalid LOGIN format! Use: LOGIN <username> <password>")

            # Handle HELLO command (join chat room)
            elif data.startswith("HELLO"):
                if data != "HELLO":
                    send_message(client_socket, "❌ Error: Use just 'HELLO' to join the chat")
                    return
                
                # Make sure username is set before using it
                username = socket_to_username.get(client_socket)
                if not username:
                    send_message(client_socket, "❌ Error: You must login first!")
                    continue
                    
                # Add user to online users and send welcome messages
                online_users[username] = client_socket
                send_message(client_socket, f"👋 Hi {username}, welcome to the chat room.")

                welcome_message = f"🔔 {username} has joined the chat!"
                # System message - not saved to history
                print(welcome_message)
                
                # Notify other users about the new user
                for user, sock in online_users.items():
                    if user != username:
                        send_message(sock, welcome_message)

                # Send list of online users
                online_list = ", ".join(online_users.keys()) if online_users else "No users online"
                send_message(client_socket, f"👥 Online users: {online_list}")

            # Handle PUBLIC message command
            elif data.startswith("PUBLIC"):
                print(f"📩 Received PUBLIC command: {data}")
                parts = data.split(" ", 2)
                if len(parts) < 3:
                    send_message(client_socket, "Error: Invalid PUBLIC format!")
                    continue
                
                token = parts[1]
                message = parts[2]
                
                # Validate user token
                token_username, is_valid = validate_token(token)
                if not is_valid:
                    send_message(client_socket, "Error: Invalid session! Please login again.")
                    continue
                
                # Confirm message sent to sender
                sender_message = f"PUBLIC MESSAGE, LENGTH = {len(message)} : {message}"
                send_message(client_socket, sender_message)
                
                # Format message for receivers and save to history
                receiver_message = f"PUBLIC MESSAGE FROM {token_username}, LENGTH = {len(message)} : {message}"
                save_message(receiver_message, 'PUBLIC')
                
                # Send message to all other online users
                for user, sock in online_users.items():
                    if user != token_username:
                        send_message(sock, receiver_message)

            # Handle PRIVATE message command
            elif data.startswith("PRIVATE "):
                try:
                    _, token, receivers_str, message = data.split(" ", 3)
                    
                    # Validate user token
                    token_username, is_valid = validate_token(token)
                    if not is_valid:
                        send_message(client_socket, "Error: Invalid session! Please login again.")
                        continue

                    # Parse and validate recipients
                    receivers = [r.strip() for r in receivers_str.split(",") if r.strip()]
                    valid_receivers = [r for r in receivers if r in online_users]

                    if not valid_receivers:
                        send_message(client_socket, "Error: None of the specified users are online!")
                        continue

                    message_length = len(message)
                    receivers_display = ", ".join(valid_receivers)
                    
                    # Confirm message sent to sender
                    sender_message = f"PRIVATE MESSAGE, LENGTH = {message_length} FROM {token_username} TO {receivers_display} : {message}"
                    send_message(client_socket, sender_message)
                    
                    # Format message for receivers and save to history
                    receiver_message = f"PRIVATE MESSAGE, LENGTH = {message_length} FROM {token_username} TO {receivers_display} : {message}"
                    save_message(receiver_message, 'PRIVATE')
                    
                    # Send message to all specified recipients
                    for receiver in valid_receivers:
                        if receiver in online_users:
                            send_message(online_users[receiver], receiver_message)

                except ValueError:
                    send_message(client_socket, "Error: Invalid PRIVATE format!")

            # Handle LOGOUT command
            elif data.startswith("LOGOUT"):
                parts = data.split(" ", 1)
                if len(parts) < 2:
                    send_message(client_socket, "Error: Invalid LOGOUT format!")
                    continue
                
                token = parts[1]
                token_username, is_valid = validate_token(token)
                
                if is_valid:
                    send_message(client_socket, "You have been logged out.")
                    
                    # Clean up user session data
                    if token_username in online_users:
                        del online_users[token_username]
                    
                    if token_username in user_tokens:
                        old_token = user_tokens[token_username]
                        if old_token in token_to_username:
                            del token_to_username[old_token]
                        del user_tokens[token_username]
                    
                    print(f"{token_username} logged out.")
                    
                    # System message - not saved to history
                    logout_message = f"🔔 {token_username} has logged out"
                    print(logout_message)
                    
                    username = token_username
                    socket_to_username[client_socket] = None
                    
                    # Notify other users
                    notification = f"🔔 {token_username} has left the chat!"
                    for _, sock in online_users.items():
                        send_message(sock, notification)
                else:
                    send_message(client_socket, "You are not logged in.")

            # Handle LIST USERS command
            elif data.startswith("LIST USERS"):
                online_list = ", ".join(online_users.keys()) if online_users else "No users online"
                print(f"Sending online users list: {online_list}")
                send_message(client_socket, f"Online users: {online_list}")

            # Handle HISTORY command
            elif data.startswith("HISTORY"):
                parts = data.split(" ", 1)
                if len(parts) < 2:
                    send_message(client_socket, "Error: Invalid HISTORY format!")
                    continue
                
                token = parts[1]
                token_username, is_valid = validate_token(token)
                
                if is_valid:
                    try:
                        with file_lock:  # Lock while reading history
                            if os.path.exists("chat_history.txt"):
                                with open("chat_history.txt", "r", encoding="utf-8") as f:
                                    history = f.read().strip()
                                if not history:
                                    send_message(client_socket, "No chat history available.")
                                else:
                                    send_message(client_socket, "Chat History:\n" + history)
                            else:
                                # Create the file if it doesn't exist
                                initialize_history_file()
                                send_message(client_socket, "No chat history available yet.")
                    except Exception as e:
                        print(f"❌ Error reading history: {e}")
                        send_message(client_socket, f"Error reading chat history: {str(e)}")
                else:
                    send_message(client_socket, "Error: Invalid session! Please login again.")

            # Handle WHOAMI command
            elif data.startswith("WHOAMI"):
                parts = data.split(" ", 1)
                if len(parts) < 2:
                    send_message(client_socket, "Error: Invalid WHOAMI format!")
                    continue
                
                token = parts[1]
                token_username, is_valid = validate_token(token)
                
                if is_valid:
                    send_message(client_socket, f"You are logged in as: {token_username}")
                else:
                    send_message(client_socket, "You are not logged in.")

            # Handle CLEAR HISTORY command
            elif data.startswith("CLEAR HISTORY"):
                parts = data.split(" ", 2)
                
                if len(parts) < 3:
                    send_message(client_socket, "Error: Invalid CLEAR HISTORY format! Use: CLEAR HISTORY <token>")
                    continue
                
                token = parts[2]
                
                token_username, is_valid = validate_token(token)
                
                if is_valid:
                    try:
                        with file_lock:
                            with open("chat_history.txt", "w", encoding="utf-8") as f:
                                f.write(f"--- Chat history cleared by {token_username} ---\n")
                        send_message(client_socket, "✅ Chat history cleared successfully!")
                        print(f"🗑️ Chat history cleared by {token_username}")
                        
                        # No longer saving system messages to history
                        print(f"SYSTEM: Chat history cleared by {token_username}")
                    except Exception as e:
                        send_message(client_socket, f"❌ Error clearing history: {str(e)}")
                        print(f"❌ Clear history error: {e}")
                else:
                    send_message(client_socket, "❌ Invalid token! Login again.")

            # Handle BYE command (disconnect)
            elif data == "BYE":
                try:
                    current_username = socket_to_username[client_socket]
                    if current_username and current_username in online_users:
                        # Clean up user session data
                        del online_users[current_username]
                        if current_username in user_tokens:
                            token = user_tokens[current_username]
                            if token in token_to_username:
                                del token_to_username[token]
                            del user_tokens[current_username]
                        
                        exit_message = f"🚪 {current_username} left the chat."
                        print(exit_message)
                        
                        # System message - not saved to history
                        print(exit_message)
                        
                        # Notify other users
                        for user, sock in online_users.items():
                            send_message(sock, exit_message)
                    
                    send_message(client_socket, "Goodbye! You have been disconnected.")
                except:
                    print("Error handling BYE command")
                
                break

            # Handle unknown commands
            else:
                send_message(client_socket, "Unknown command!")

    except ConnectionResetError:
        print("Client disconnected unexpectedly")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Clean up when client disconnects
        current_username = socket_to_username.get(client_socket)
        if current_username and current_username in online_users:
            del online_users[current_username]
            if current_username in user_tokens:
                token = user_tokens[current_username]
                if token in token_to_username:
                    del token_to_username[token]
                del user_tokens[current_username]
            
            # System message - not saved to history
            disconnect_message = f"🔔 {current_username} has disconnected!"
            print(disconnect_message)
            
            # Notify other users about disconnection
            for _, sock in online_users.items():
                try:
                    send_message(sock, disconnect_message)
                except:
                    pass
        
        if client_socket in socket_to_username:
            del socket_to_username[client_socket]
            
        try:
            client_socket.close()
        except:
            pass
            
        print(f"Connection closed for {current_username if current_username else 'unknown user'}")


# Main server execution
def main():
    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Server is listening on {HOST}:{PORT}...")

    # Initialize history file when server starts
    initialize_history_file()

    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"New connection from {addr}")
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        # Log server shutdown - not saved to history
        print("SYSTEM: Server shutting down...")
        server_socket.close()
        print("Server shut down.")
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()