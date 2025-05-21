import socket
import threading
import base64
import time
import sys
import tkinter as tk
from tkinter import ttk, scrolledtext,simpledialog, messagebox
from tkinter import font
from Crypto.Cipher import AES
import html
import re


# تنظیمات اتصال به سرور
HOST = 'localhost'
PORT = 15000
KEY = b'mysecretpassword'  # Default encryption key

# ثابت‌هایی برای اعمال فرمت روی پیام
FORMAT_BOLD = "BOLD"
FORMAT_COLOR = "COLOR"
FORMAT_LINK = "LINK"
FORMAT_CODE = "CODE"


class ChatClientGUI:
    """
    GUI client for a secure chat application with encryption capabilities
    """
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Client")
        self.root.geometry("800x600")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Client state variables
        self.client_socket = None
        self.running = False
        self.token = None
        self.current_username = None
        self.user_encryption_key = KEY
        self.socket_lock = threading.Lock()
        
        # Initialize GUI components
        self.setup_gui()

        # tag for text formatting in message display
        
        # Connect to server on startup
        self.connect_to_server()

    def setup_gui(self):
        """
        Initialize and configure all GUI elements
        """
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Top frame for connection status
        self._setup_status_frame(main_frame)
        
        # دوتا تب برای چت و کاربرا می‌سازه
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # بخش چت رو می‌سازه (نمایش و ارسال پیام)
        self._setup_chat_tab()
        
        # بخش نمایش لیست کاربرا رو می‌سازه
        self._setup_users_tab()

    def _setup_status_frame(self, parent_frame):
        """
        Set up the status bar at the top of the window
        """
        status_frame = ttk.Frame(parent_frame)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.status_label = ttk.Label(status_frame, text="Status: Disconnected", foreground="red")
        self.status_label.pack(side=tk.LEFT)
        
        self.user_label = ttk.Label(status_frame, text="Not logged in")
        self.user_label.pack(side=tk.RIGHT)

    def _setup_chat_tab(self):
        """
        Set up the main chat tab with message display and input areas
        """
        chat_frame = ttk.Frame(self.notebook)
        self.notebook.add(chat_frame, text="Chat")
        
        # Message display area
        self.message_display = scrolledtext.ScrolledText(chat_frame, wrap=tk.WORD, state="disabled")
        self.message_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Message input area
        input_frame = ttk.Frame(chat_frame)
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Message type selection (public/private)
        self._setup_message_type_frame(input_frame)
        
        # Recipient frame for private messages
        self._setup_recipient_frame(input_frame)
        
        # Message entry field and send button
        self._setup_message_entry_frame(input_frame)
        
        # Command buttons (login, register, etc.)
        self._setup_command_buttons(chat_frame)

    def _setup_message_type_frame(self, parent_frame):
        """
        Set up radio buttons for selecting message type (public/private)
        """
        type_frame = ttk.Frame(parent_frame)
        type_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 5))
        
        ttk.Label(type_frame, text="Message Type:").pack(side=tk.LEFT, padx=(0, 5))
        self.message_type = tk.StringVar(value="PUBLIC")
        ttk.Radiobutton(type_frame, text="Public", variable=self.message_type, value="PUBLIC").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(type_frame, text="Private", variable=self.message_type, value="PRIVATE").pack(side=tk.LEFT, padx=5)
        
        # Set up callback for message type changes
        self.message_type.trace("w", self.on_message_type_change)

    def _setup_recipient_frame(self, parent_frame):
        """
        Set up recipient entry field for private messages
        """
        recipient_frame = ttk.Frame(parent_frame)
        recipient_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 5))
        
        self.recipient_label = ttk.Label(recipient_frame, text="To:")
        self.recipient_label.pack(side=tk.LEFT, padx=(0, 5))
        self.recipient_label.pack_forget()  # Initially hidden
        
        self.recipient_entry = ttk.Entry(recipient_frame, width=30)
        self.recipient_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.recipient_entry.pack_forget()  # Initially hidden

    def _setup_message_entry_frame(self, parent_frame):
        """
        Set up message input field and send button
        """
        message_entry_frame = ttk.Frame(parent_frame)
        message_entry_frame.pack(side=tk.TOP, fill=tk.X)

                # Add formatting toolbar
        formatting_frame = ttk.Frame(message_entry_frame)
        formatting_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 5))
        
        # Bold button
        self.bold_button = ttk.Button(formatting_frame, text="B", width=3, 
                                      command=lambda: self.apply_formatting(FORMAT_BOLD))
        self.bold_button.pack(side=tk.LEFT, padx=2)
        
        # Color button with dropdown
        self.color_button = ttk.Button(formatting_frame, text="🎨", width=3,
                                      command=self.show_color_menu)
        self.color_button.pack(side=tk.LEFT, padx=2)
        
        # Link button
        self.link_button = ttk.Button(formatting_frame, text="🔗", width=3,
                                     command=lambda: self.apply_formatting(FORMAT_LINK))
        self.link_button.pack(side=tk.LEFT, padx=2)
        
        # Code button
        self.code_button = ttk.Button(formatting_frame, text="</>", width=3,
                                     command=lambda: self.apply_formatting(FORMAT_CODE))
        self.code_button.pack(side=tk.LEFT, padx=2)
        
        # Message input field and send button
        input_frame = ttk.Frame(message_entry_frame)
        input_frame.pack(side=tk.TOP, fill=tk.X)
        
        ttk.Label(message_entry_frame, text="Message:").pack(side=tk.LEFT, padx=(0, 5))
        self.message_entry = ttk.Entry(message_entry_frame)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_chat_message)
        
        send_button = ttk.Button(message_entry_frame, text="Send", command=self.send_chat_message)
        send_button.pack(side=tk.RIGHT)

    def _setup_command_buttons(self, parent_frame):
        """
        Set up command buttons for login, register, etc.
        """
        buttons_frame = ttk.Frame(parent_frame)
        buttons_frame.pack(fill=tk.X)
        
        button_frame_left = ttk.Frame(buttons_frame)
        button_frame_left.pack(side=tk.LEFT, fill=tk.X)
        
        button_frame_right = ttk.Frame(buttons_frame)
        button_frame_right.pack(side=tk.RIGHT, fill=tk.X)
        
        # Left side buttons (account management)
        self.login_button = ttk.Button(button_frame_left, text="Login", command=self.login_dialog)
        self.login_button.pack(side=tk.LEFT, padx=5)
        
        self.register_button = ttk.Button(button_frame_left, text="Register", command=self.register_dialog)
        self.register_button.pack(side=tk.LEFT, padx=5)
        
        self.logout_button = ttk.Button(button_frame_left, text="Logout", command=self.logout, state=tk.DISABLED)
        self.logout_button.pack(side=tk.LEFT, padx=5)
        
        self.hello_button = ttk.Button(button_frame_left, text="Hello", command=self.send_hello, state=tk.DISABLED)
        self.hello_button.pack(side=tk.LEFT, padx=5)
        
        # Right side buttons (history management)
        self.history_button = ttk.Button(button_frame_right, text="History", command=self.get_history, state=tk.DISABLED)
        self.history_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_history_button = ttk.Button(button_frame_right, text="Clear History", command=self.clear_history, state=tk.DISABLED)
        self.clear_history_button.pack(side=tk.LEFT, padx=5)
        
        # Add a disconnect button
        self.disconnect_button = ttk.Button(button_frame_right, text="Disconnect", command=self.disconnect)
        self.disconnect_button.pack(side=tk.LEFT, padx=5)

    def _setup_users_tab(self):
        """
        Set up the users tab for displaying online users
        """
        users_frame = ttk.Frame(self.notebook)
        self.notebook.add(users_frame, text="Users")
        
        self.users_display = scrolledtext.ScrolledText(users_frame, wrap=tk.WORD, state="disabled")
        self.users_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        users_buttons_frame = ttk.Frame(users_frame)
        users_buttons_frame.pack(fill=tk.X)
        
        refresh_users_button = ttk.Button(users_buttons_frame, text="Refresh Users List", command=self.list_users)
        refresh_users_button.pack(side=tk.LEFT, padx=5)
        
        whoami_button = ttk.Button(users_buttons_frame, text="Who Am I", command=self.whoami)
        whoami_button.pack(side=tk.LEFT, padx=5)

    def on_message_type_change(self, *args):
        """
        Show or hide recipient field based on message type selection
        """
        if self.message_type.get() == "PRIVATE":
            self.recipient_label.pack(side=tk.LEFT, padx=(0, 5))
            self.recipient_entry.pack(side=tk.LEFT, padx=(0, 5))
        else:
            self.recipient_label.pack_forget()
            self.recipient_entry.pack_forget()

    def update_status(self, status, color="black"):
        """
        Update the connection status label
        """
        self.status_label.config(text=f"Status: {status}", foreground=color)
        
    def update_user_label(self):
        """
        Update the user label to show current logged in user
        """
        self.user_label.config(text=f"Logged in as: {self.current_username}" if self.current_username else "Not logged in")

    def update_buttons_state(self):
        """
        Enable/disable buttons based on login state
        """
        if self.token:
            # User is logged in
            self.login_button.config(state=tk.DISABLED)
            self.register_button.config(state=tk.DISABLED)
            self.logout_button.config(state=tk.NORMAL)
            self.hello_button.config(state=tk.NORMAL)
            self.history_button.config(state=tk.NORMAL)
            self.clear_history_button.config(state=tk.NORMAL)
        else:
            # User is logged out
            self.login_button.config(state=tk.NORMAL)
            self.register_button.config(state=tk.NORMAL)
            self.logout_button.config(state=tk.DISABLED)
            self.hello_button.config(state=tk.DISABLED)
            self.history_button.config(state=tk.DISABLED)
            self.clear_history_button.config(state=tk.DISABLED)

    def show_color_menu(self):
        """
        Show a color selection menu
        """
        color_menu = tk.Menu(self.root, tearoff=0)
        
        # Common colors
        colors = [
            ("Red", "#FF0000"), 
            ("Green", "#00FF00"), 
            ("Blue", "#0000FF"),
            ("Yellow", "#FFFF00"),
            ("Cyan", "#00FFFF"),
            ("Magenta", "#FF00FF"),
            ("Black", "#000000"),
            ("Gray", "#808080"),
        ]
        
        for color_name, color_code in colors:
            if color_code:
                # For predefined colors
                color_menu.add_command(
                    label=color_name, 
                    background=color_code,
                    command=lambda code=color_code: self.apply_formatting(FORMAT_COLOR, code)
                )
            else:
                # For custom color option
                color_menu.add_command(
                    label=color_name,
                    command=self.custom_color_dialog
                )
        
        # Display the menu below the color button
        x = self.color_button.winfo_rootx()
        y = self.color_button.winfo_rooty() + self.color_button.winfo_height()
        color_menu.tk_popup(x, y)

    def custom_color_dialog(self):
        """
        Show dialog for custom color selection
        """
        color_code = simpledialog.askstring("Custom Color", "Enter color (hex format, e.g. #FF5500):")
        if color_code:
            # Validate format - simple check for hex color
            if re.match(r'^#[0-9A-Fa-f]{6}$', color_code):
                self.apply_formatting(FORMAT_COLOR, color_code)
            else:
                messagebox.showerror("Invalid Format", "Please use valid hex format (e.g. #FF5500)")

    def apply_formatting(self, format_type, format_value=None):
        """
        Apply selected formatting to the current text selection
        """
        try:
            # Get selected text positions
            selected_text = ""
            try:
                start_pos = self.message_entry.selection_from()
                end_pos = self.message_entry.selection_to()
                selected_text = self.message_entry.get()[start_pos:end_pos]
            except:
                # No selection, prompt user for text to format
                if format_type == FORMAT_LINK:
                    self.apply_link_format()
                    return
                selected_text = simpledialog.askstring(f"Apply {format_type}", 
                                                     f"Enter text to format as {format_type}:")
                if not selected_text:
                    return
                current_text = self.message_entry.get()
                cursor_pos = self.message_entry.index(tk.INSERT)
                new_text = current_text[:cursor_pos] + selected_text + current_text[cursor_pos:]
                self.message_entry.delete(0, tk.END)
                self.message_entry.insert(0, new_text)
                start_pos = cursor_pos
                end_pos = cursor_pos + len(selected_text)
            
            # Apply formatting based on type
            if format_type == FORMAT_BOLD:
                formatted_text = f"**{selected_text}**"
            elif format_type == FORMAT_COLOR:
                formatted_text = f"<color={format_value}>{selected_text}</color>"
            elif format_type == FORMAT_CODE:
                formatted_text = f"`{selected_text}`"
            else:
                # Default case or unsupported format
                return
                
            # Replace selected text with formatted text
            current_text = self.message_entry.get()
            new_text = current_text[:start_pos] + formatted_text + current_text[end_pos:]
            self.message_entry.delete(0, tk.END)
            self.message_entry.insert(0, new_text)
            
        except Exception as e:
            messagebox.showerror("Formatting Error", f"Error applying formatting: {str(e)}")

    def apply_link_format(self):
        """
        Special handling for link formatting
        """
        link_text = simpledialog.askstring("Link Text", "Enter display text:")
        if not link_text:
            return
            
        link_url = simpledialog.askstring("Link URL", "Enter URL:")
        if not link_url:
            return
            
        # Add http:// if missing
        if not link_url.startswith(("http://", "https://")):
            link_url = "http://" + link_url
            
        formatted_link = f"[{link_text}]({link_url})"
        
        # Insert at cursor position
        current_text = self.message_entry.get()
        cursor_pos = self.message_entry.index(tk.INSERT)
        new_text = current_text[:cursor_pos] + formatted_link + current_text[cursor_pos:]
        self.message_entry.delete(0, tk.END)
        self.message_entry.insert(0, new_text)

    def display_message(self, message):
        """
        Display a message in the chat area with proper formatting
        """
        self.message_display.config(state="normal")
        
        # Add timestamp to messages for better readability
        timestamp = time.strftime("%H:%M:%S")
        
        # Format messages differently based on type
        if "PUBLIC MESSAGE FROM" in message or ("PUBLIC MESSAGE" in message and ", LENGTH = " in message):
            parts = message.split(", LENGTH = ")
            if len(parts) > 1:
                sender_part = parts[0].replace("PUBLIC MESSAGE FROM ", "")
                rest = parts[1].split(" : ", 1)
                if len(rest) > 1:
                    # Don't count sender information in the message length
                    msg_content = rest[1]
                    # Process formatting in the message content
                    msg_content = self.process_formatting(msg_content)
                    formatted_message = f"[{timestamp}] 📢 {sender_part}: {msg_content}"
                    self.message_display.insert(tk.END, formatted_message + "\n")
                else:
                    self.message_display.insert(tk.END, f"[{timestamp}] {message}\n")
        elif "PRIVATE MESSAGE" in message and "FROM" in message and "TO" in message:
            try:
                # Try to parse and format private messages nicely
                sender = message.split("FROM ")[1].split(" TO ")[0].strip()
                recipients = message.split("TO ")[1].split(" : ")[0].strip()
                msg_content = message.split(" : ", 1)[1].strip() if " : " in message else ""
                
                # Process formatting in the message content
                msg_content = self.process_formatting(msg_content)
                
                if self.current_username == sender:
                    # Message sent by current user
                    formatted_message = f"[{timestamp}] 🔒 To {recipients}: {msg_content}"
                else:
                    # Message received from someone else
                    formatted_message = f"[{timestamp}] 🔒 From {sender}: {msg_content}"
                
                self.message_display.insert(tk.END, formatted_message + "\n")
            except:
                # Fall back to original message if parsing fails
                self.message_display.insert(tk.END, f"[{timestamp}] {message}\n")
        else:
            # Default formatting for system messages and others
            self.message_display.insert(tk.END, f"[{timestamp}] {message}\n")
            
        self.message_display.see(tk.END)
        self.message_display.config(state="disabled")

    def process_formatting(self, text):
        """
        Process formatting markers in text and convert them to appropriate display format
        """
        # Process bold formatting (**text**)
        text = re.sub(r'\*\*(.*?)\*\*', r'𝐁𝐨𝐥𝐝: \1', text)
        
        # Process color formatting (<color=#RRGGBB>text</color>)
        color_pattern = r'<color=(#[0-9A-Fa-f]{6})>(.*?)</color>'
        text = re.sub(color_pattern, lambda m: f"🎨 Color({m.group(1)}): {m.group(2)}", text)
        
        # Process link formatting ([text](url))
        link_pattern = r'\[(.*?)\]\((https?://.*?)\)'
        text = re.sub(link_pattern, lambda m: f"🔗 Link({m.group(2)}): {m.group(1)}", text)
        
        # Process code formatting (`text`)
        code_pattern = r'`(.*?)`'
        text = re.sub(code_pattern, r'💻 Code: \1', text)
        
        return text
    
    def create_formatting_tags(self):
        """
        Create text tags for formatting in the message display
        """
        # Configure the message display as a Text widget instead of ScrolledText
        # so we can apply tags for formatting
        main_frame = self.root.nametowidget(self.message_display.winfo_parent())
        self.message_display.destroy()
        
        # Create a Text widget with a scrollbar
        self.message_display = tk.Text(main_frame, wrap=tk.WORD)
        self.message_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(main_frame, command=self.message_display.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.message_display.config(yscrollcommand=scrollbar.set)
        
        # Create formatting tags
        bold_font = font.Font(self.message_display, self.message_display.cget("font"))
        bold_font.configure(weight="bold")
        self.message_display.tag_configure("bold", font=bold_font)
        
        # Tag for code formatting
        code_font = font.Font(family="Courier", size=10)
        self.message_display.tag_configure("code", font=code_font, background="#f0f0f0")
        
        # Initially disable editing in the display
        self.message_display.config(state="disabled")

    def display_users(self, users_message):
        """
        Display the list of online users in the users tab
        """
        self.users_display.config(state="normal")
        self.users_display.delete(1.0, tk.END)
        self.users_display.insert(tk.END, users_message + "\n")
        self.users_display.config(state="disabled")

    def encrypt(self, message):
        """
        Encrypt a message using AES encryption
        """
        cipher = AES.new(self.user_encryption_key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
        return base64.b64encode(nonce + tag + ciphertext).decode()

    def decrypt(self, encrypted_message):
        """
        Decrypt an AES encrypted message
        """
        data = base64.b64decode(encrypted_message)
        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        cipher = AES.new(self.user_encryption_key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()

    def connect_to_server(self):
        """
        Establish a connection to the chat server
        """
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST, PORT))
            self.running = True
            self.update_status("Connected", "green")
            
            # Start receiving thread
            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()
            
            return True
        except Exception as e:
            self.update_status(f"Connection failed: {e}", "red")
            messagebox.showerror("Connection Error", f"Failed to connect to server: {e}")
            return False

    def receive_messages(self):
        """
        Background thread for receiving and processing messages from the server
        """
        while self.running:
            try:
                with self.socket_lock:
                    if self.client_socket is None:
                        time.sleep(0.1)
                        continue
                        
                    self.client_socket.settimeout(0.5)
                    try:
                        data = self.client_socket.recv(1024)
                        self.client_socket.settimeout(None)
                        
                        if not data:
                            self.display_message("🔴 Disconnected from server.")
                            self.running = False
                            break
                        
                        message = data.decode()
                        
                        # Handle encryption key updates
                        if message.startswith("Key "):
                            key_base64 = message.split(" ", 1)[1]
                            self.user_encryption_key = base64.b64decode(key_base64)
                            self.display_message(f"🔑 Received new encryption key")
                            continue
                        
                        # Decrypt and process regular messages
                        decrypted_message = self.decrypt(message)

                        # Handle special server responses
                        if "Login successful! Your token:" in decrypted_message:
                            self.token = decrypted_message.split("Your token: ")[1].strip()
                            self.display_message(f"✅ Login successful!")
                            self.update_buttons_state()
                            self.update_user_label()
                        
                        elif "You have been logged out due to a new login." in decrypted_message:
                            self.display_message(f"\n⚠️ {decrypted_message}")
                            self.display_message("🔴 Disconnected from server.")
                            self.token = None
                            self.current_username = None
                            self.update_buttons_state()
                            self.update_user_label()
                            self.running = False
                            break
                        elif decrypted_message == "BYE" or "Goodbye! You have been disconnected." in decrypted_message:
                            self.display_message("\n🔴 Server has closed the connection.")
                            self.running = False
                            break
                        else:
                            # Handle regular messages
                            if "Online users:" in decrypted_message:
                                self.display_users(decrypted_message)
                            self.display_message(decrypted_message)
                        
                    except socket.timeout:
                        # This is expected behavior for the timeout we set
                        pass
                    except Exception as e:
                        if self.running:
                            self.display_message(f"❌ Error receiving message: {str(e)}")
                
            except Exception as e:
                if self.running:
                    self.display_message(f"❌ Connection error: {str(e)}")
            
            time.sleep(0.1)
        
        # Update UI when disconnected
        self.update_status("Disconnected", "red")

    def send_command(self, command):
        """
        Send an encrypted command to the server
        """
        try:
            with self.socket_lock:
                if self.client_socket and self.running:
                    encrypted_command = self.encrypt(command)
                    self.client_socket.send(encrypted_command.encode())
        except Exception as e:
            self.display_message(f"❌ Error sending command: {str(e)}")

    def login_dialog(self):
        """
        Show a dialog for user login
        """
        login_window = tk.Toplevel(self.root)
        login_window.title("Login")
        login_window.geometry("300x150")
        login_window.transient(self.root)
        login_window.grab_set()
        
        ttk.Label(login_window, text="Username:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        username_entry = ttk.Entry(login_window, width=20)
        username_entry.grid(row=0, column=1, padx=10, pady=10)
        
        ttk.Label(login_window, text="Password:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        password_entry = ttk.Entry(login_window, width=20, show="*")
        password_entry.grid(row=1, column=1, padx=10, pady=10)
        
        def login():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            
            if username and password:
                self.current_username = username
                self.send_command(f"LOGIN {username} {password}")
                login_window.destroy()
            else:
                messagebox.showerror("Error", "Please enter both username and password")
        
        ttk.Button(login_window, text="Login", command=login).grid(row=2, column=0, columnspan=2, pady=10)
        
        # Center the window
        login_window.update_idletasks()
        width = login_window.winfo_width()
        height = login_window.winfo_height()
        x = (login_window.winfo_screenwidth() // 2) - (width // 2)
        y = (login_window.winfo_screenheight() // 2) - (height // 2)
        login_window.geometry(f'+{x}+{y}')

    def register_dialog(self):
        """
        Show a dialog for user registration
        """
        register_window = tk.Toplevel(self.root)
        register_window.title("Register")
        register_window.geometry("300x150")
        register_window.transient(self.root)
        register_window.grab_set()
        
        ttk.Label(register_window, text="Username:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        username_entry = ttk.Entry(register_window, width=20)
        username_entry.grid(row=0, column=1, padx=10, pady=10)
        
        ttk.Label(register_window, text="Password:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        password_entry = ttk.Entry(register_window, width=20, show="*")
        password_entry.grid(row=1, column=1, padx=10, pady=10)
        
        def register():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            
            if username and password:
                self.send_command(f"REGISTER {username} {password}")
                register_window.destroy()
            else:
                messagebox.showerror("Error", "Please enter both username and password")
        
        ttk.Button(register_window, text="Register", command=register).grid(row=2, column=0, columnspan=2, pady=10)
        
        # Center the window
        register_window.update_idletasks()
        width = register_window.winfo_width()
        height = register_window.winfo_height()
        x = (register_window.winfo_screenwidth() // 2) - (width // 2)
        y = (register_window.winfo_screenheight() // 2) - (height // 2)
        register_window.geometry(f'+{x}+{y}')

    def logout(self):
        """
        Logout the current user
        """
        if self.token:
            self.send_command(f"LOGOUT {self.token}")
            self.token = None
            self.current_username = None
            self.update_buttons_state()
            self.update_user_label()

    def send_hello(self):
        """
        Send HELLO command to join the chat room
        """
        self.send_command("HELLO")

    def get_history(self):
        """
        Request chat history from the server
        """
        if self.token:
            self.send_command(f"HISTORY {self.token}")

    def clear_history(self):
        """
        Clear chat history on the server
        """
        if self.token:
            if messagebox.askyesno("Clear History", "Are you sure you want to clear chat history?"):
                self.send_command(f"CLEAR HISTORY {self.token}")

    def list_users(self):
        """
        Request list of online users from the server
        """
        self.send_command("LIST USERS")

    def whoami(self):
        """
        Request identity confirmation from the server
        """
        if self.token:
            self.send_command(f"WHOAMI {self.token}")
        else:
            self.display_message("❌ You are not logged in!")

    def send_chat_message(self, event=None):
        """
        Send a chat message to the server (public or private)
        """
        if not self.token:
            messagebox.showinfo("Not Logged In", "Please login first")
            return
            
        message = self.message_entry.get().strip()
        if not message:
            return
            
        message_type = self.message_type.get()
        
        if message_type == "PUBLIC":
            # Format: PUBLIC <token> <message>
            self.send_command(f"PUBLIC {self.token} {message}")
        elif message_type == "PRIVATE":
            recipients = self.recipient_entry.get().strip()
            if not recipients:
                messagebox.showinfo("No Recipients", "Please enter recipient usernames separated by commas")
                return
                
            # Format: PRIVATE <token> <recipients> <message>
            formatted_message = f"PRIVATE {self.token} {recipients} {message}"
            self.send_command(formatted_message)
            
        self.message_entry.delete(0, tk.END)

    def disconnect(self):
        """
        Disconnect from the server by sending BYE command
        """
        if self.running and self.client_socket:
            self.display_message("Disconnecting from server...")
            self.send_command("BYE")
            time.sleep(0.5)  # Give time for BYE to be processed
            self.running = False
            with self.socket_lock:
                if self.client_socket:
                    self.client_socket.close()
                    self.client_socket = None
            self.update_status("Disconnected", "red")

    def on_closing(self):
        """
        Handle application closure
        """
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.running = False
            if self.client_socket:
                try:
                    self.send_command("BYE")
                    time.sleep(0.5)  # Give time for BYE to be sent
                    self.client_socket.close()
                except:
                    pass
            self.root.destroy()
            sys.exit(0)


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientGUI(root)
    root.mainloop()