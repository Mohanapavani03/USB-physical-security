import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, Toplevel, Text
import webbrowser
import os
import random
import string
import smtplib
from email.message import EmailMessage
from datetime import datetime
import time
import cv2
import logging
import wmi
import threading
import winreg
import ctypes
import subprocess
import json
import hashlib
from PIL import Image, ImageTk

# --- Enhanced Logging setup ---
logging.basicConfig(
    filename="usb_security_system.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("USB_SECURITY")
logger.setLevel(logging.INFO)

# Create console handler for real-time monitoring
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

# === Email Configuration ===
EMAIL_ADDRESS = "mohanapavani03@gmail.com"
EMAIL_PASSWORD = "gbna zqnt qkzp gkes"  # Your app password
ADMIN_EMAIL = EMAIL_ADDRESS

# === HTML Report ===
html_report_path = "usb_security_report.html"
html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Project Information</title>
  <style>
    body { font-family: 'Segoe UI', sans-serif; background: #f4f8fb; margin: 0; padding: 30px; color: #333; }
    .container { max-width: 1000px; margin: auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.1);}
    h1, h2 { color: #003366; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th, td { padding: 12px 15px; border: 1px solid #ccc; text-align: left; }
    th { background-color: #003366; color: white; }
    .highlight { background-color: #e6f0ff; padding: 15px; border-left: 5px solid #003366; margin-bottom: 20px; }
    .footer { margin-top: 40px; text-align: center; font-size: 13px; color: #777; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Project Information</h1>
    <div class="highlight">
      This project was developed by <strong>Gousya Bi, Asha, Prasanna, Rafiya, Shahista, Pavani, Bhavani</strong> as part of a <strong>Cyber Security Internship</strong>. This project is designed to <strong>Secure the Organizations In Real World from Cyber Frauds performed by Hackers</strong>.
    </div>
    <h2>Project Details</h2>
    <table>
      <tr><th>Project Name</th><td>USB Physical Security</td></tr>
      <tr><th>Project Description</th><td>Implementing Physical Security Policy on USB Ports in Organization for Physical Security</td></tr>
      <tr><th>Project Start Date</th><td>21-May-2025</td></tr>
      <tr><th>Project End Date</th><td>09-August-2025</td></tr>
      <tr><th>Project Status</th><td><strong style="color: green;">Completed</strong></td></tr>
    </table>
    <h2>Developer Details</h2>
    <table>
      <tr><th>Name</th><th>Employee ID</th><th>Email</th></tr>
      <tr><td>G Prasanna</td><td>ST#IS#7720</td><td>prasannagorrepati793@gmail.com</td></tr>
      <tr><td>Dudekula Gousyabi</td><td>ST#IS#7718</td><td>dudekulagousyabi@gmail.com</td></tr>
      <tr><td>Shaik Shahista</td><td>ST#IS#7722</td><td>shaikshahista31@gmail.com</td></tr>
      <tr><td>Tadi MohanaPavani</td><td>ST#IS#7723</td><td>mohanapavani03@gmail.com</td></tr>
      <tr><td>Mirimpalli Asha Jyothi</td><td>ST#IS#7719</td><td>jyomirimpalli.123@gmail.com</td></tr>
      <tr><td>Singu Bhavani</td><td>ST#IS#7725</td><td>bbhavanisingu@gmail.com</td></tr>
      <tr><td>Rafiya Shaik</td><td>ST#IS#7721</td><td>rafiyashaikit@gmail.com</td></tr>
    </table>
    <h2>Company Details</h2>
    <table>
      <tr><th>Company Name</th><td>Supraja Technologies</td></tr>
      <tr><th>Email</th><td>contact@suprajatechnologies.com</td></tr>
    </table>
    <div class="footer">&copy; 2025 Supraja Technologies | Cyber Security Internship Project</div>
  </div>
</body>
</html>
"""

if not os.path.exists(html_report_path):
    with open(html_report_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    logger.info("Created project information HTML report")


# === Admin Check ===
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        logger.error(f"Admin check failed: {str(e)}")
        return False


# === USB Registry Control ===
def set_usb_registry(value):
    try:
        reg_path = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
        with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                reg_path,
                0,
                winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, value)
        logger.info(f"USB registry set to: {value}")
        return True
    except Exception as e:
        logger.error(f"Registry access failed: {str(e)}")
        return False


# === User Database Setup ===
USERS_FILE = "users.json"
LOGGED_ACTIONS_FILE = "security_actions.log"


def log_action(username, action, details=""):
    """Log security-relevant actions to file and system log"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] {username} - {action}"
    if details:
        log_entry += f" - {details}"

    # Write to security actions log
    with open(LOGGED_ACTIONS_FILE, "a") as f:
        f.write(log_entry + "\n")

    # Also log to system logger
    logger.info(log_entry)


def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                users = json.load(f)
                logger.info(f"Loaded {len(users)} users from database")
                return users
        except Exception as e:
            logger.error(f"Failed to load users: {str(e)}")
            return {"admin": {"email": ADMIN_EMAIL, "password": hash_password("admin123"), "approved": True,
                              "role": "admin"}}
    logger.info("No user database found, creating default admin")
    return {"admin": {"email": ADMIN_EMAIL, "password": hash_password("admin123"), "approved": True, "role": "admin"}}


def save_users(users):
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=4)
        logger.info(f"Saved {len(users)} users to database")
    except Exception as e:
        logger.error(f"Failed to save users: {str(e)}")


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# === Email Functions ===
def send_email(to_email, subject, body):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email
    msg.set_content(body)

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        logger.info(f"Email sent to {to_email} - Subject: {subject}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {str(e)}")
        return False


# === User Management Functions ===
def generate_temp_password():
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(8))


def register_user(email):
    users = load_users()

    # Check if email already exists
    for user_data in users.values():
        if user_data["email"] == email:
            logger.warning(f"Registration attempt with existing email: {email}")
            return False, "Email already registered"

    # Generate username based on email
    username = email.split("@")[0]
    base_username = username
    counter = 1
    while username in users:
        username = f"{base_username}{counter}"
        counter += 1

    temp_password = generate_temp_password()
    users[username] = {
        "email": email,
        "password": hash_password(temp_password),
        "approved": False,
        "role": "user"  # Default role
    }
    save_users(users)
    logger.info(f"New user registered: {username} ({email}) - Pending approval")

    # Send email with temp password to user
    user_email_body = f"""Hello,

Thank you for registering with the USB Control Panel.

Your temporary password is: {temp_password}

Please login using this password. Your account will be active after admin approval.

- USB Control System"""

    send_email(
        email,
        "Your USB Control Panel Access",
        user_email_body
    )

    # Send approval request to admin
    admin_email_body = f"""New user registration requires approval:

Username: {username}
Email: {email}
Role: User

Please approve or reject this registration in the admin panel.

- USB Control System"""

    send_email(
        ADMIN_EMAIL,
        "New User Registration Requires Approval",
        admin_email_body
    )

    return True, "Registration successful. Check your email for temporary password."


def approve_user(username):
    users = load_users()
    if username not in users:
        logger.warning(f"Approve user failed: User {username} not found")
        return False, "User not found"

    users[username]["approved"] = True
    save_users(users)
    logger.info(f"User approved: {username}")

    # Notify user
    user_email = users[username]["email"]
    send_email(
        user_email,
        "Account Approved",
        f"""Hello,

Your account has been approved by the administrator.

You can now fully access the USB Control Panel.

- USB Control System"""
    )

    return True, f"Approved {username}"


def reject_user(username):
    users = load_users()
    if username not in users:
        logger.warning(f"Reject user failed: User {username} not found")
        return False, "User not found"

    user_email = users[username]["email"]
    send_email(
        user_email,
        "Account Rejected",
        f"""Hello,

Your account registration has been rejected by the administrator.

Please contact support if you believe this is an error.

- USB Control System"""
    )

    # Remove user
    del users[username]
    save_users(users)
    logger.info(f"User rejected and removed: {username}")

    return True, f"Rejected {username}"


def promote_to_admin(username):
    users = load_users()
    if username not in users:
        logger.warning(f"Promote to admin failed: User {username} not found")
        return False, "User not found"

    users[username]["role"] = "admin"
    save_users(users)
    logger.info(f"User promoted to admin: {username}")

    # Notify user
    user_email = users[username]["email"]
    send_email(
        user_email,
        "Account Promoted to Administrator",
        f"""Hello,

Your account has been promoted to Administrator by the administrator.

You now have full administrative privileges.

- USB Control System"""
    )

    return True, f"Promoted {username} to admin"


# --- Webcam recording function ---
def capture_intruder_video(duration=5):
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"intruder_{timestamp}.avi"
        logger.warning(f"Intruder alert! Recording video: {filename}")

        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            logger.error("Failed to access webcam for intruder recording")
            return

        fourcc = cv2.VideoWriter_fourcc(*'XVID')
        out = cv2.VideoWriter(filename, fourcc, 20.0, (640, 480))

        start_time = time.time()
        while int(time.time() - start_time) < duration:
            ret, frame = cap.read()
            if ret:
                out.write(frame)
            else:
                break

        cap.release()
        out.release()
        logger.info(f"Intruder video recorded: {filename}")
        messagebox.showwarning("Intruder Detected", f"Security alert triggered!\nVideo recorded as {filename}")
        return filename
    except Exception as e:
        logger.error(f"Error recording intruder video: {str(e)}")
        return None


# --- USB status checker ---
def check_usb_status():
    logger.info("Checking USB device status")
    try:
        c = wmi.WMI()
        usb_drives = []

        for disk in c.Win32_DiskDrive():
            if 'USB' in disk.InterfaceType:
                usb_drives.append({
                    'DeviceID': disk.DeviceID,
                    'Model': disk.Model,
                    'Size (GB)': round(int(disk.Size) / (1024 ** 3), 2) if disk.Size else "Unknown"
                })

        # Create pop-up window
        status_window = Toplevel(root)
        status_window.title("USB Device Status")
        status_window.geometry("400x250")

        # Display USB info
        text_area = Text(status_window, wrap="word", font=("Arial", 10))
        text_area.pack(expand=True, fill="both", padx=10, pady=10)

        if usb_drives:
            text_area.insert("end", "[INFO] USB device(s) connected:\n\n")
            for drive in usb_drives:
                text_area.insert("end", f"• {drive['Model']} ({drive['DeviceID']}) — {drive['Size (GB)']} GB\n")
            logger.info(f"Found {len(usb_drives)} USB devices")
        else:
            text_area.insert("end", "[INFO] No USB storage devices connected.")
            logger.info("No USB storage devices found")

        text_area.config(state="disabled")
    except Exception as e:
        logger.error(f"Failed to check USB status: {str(e)}")
        messagebox.showerror("Error", f"Failed to check USB status: {str(e)}")


# --- Prompt for reboot ---
def prompt_reboot():
    if messagebox.askyesno("Reboot Required",
                           "Changes require a system restart to take effect.\n"
                           "Would you like to reboot now?"):
        logger.warning("System reboot initiated by user")
        os.system("shutdown /r /t 1")


# === GUI Application ===
class USBControlApp:
    def __init__(self, root):
        self.root = root
        self.root.title("USB Physical Security")
        self.root.geometry("600x600")
        self.root.resizable(False, False)
        self.root.configure(bg="#2c3e50")

        # Load and display logo
        try:
            self.logo_img = Image.open("C:\\Users\\HARIKA\\PyCharmMiscProject\\logo.jpg")
            self.logo_img = self.logo_img.resize((120, 120), Image.LANCZOS)
            self.logo = ImageTk.PhotoImage(self.logo_img)
            logger.info("Application logo loaded successfully")
        except Exception as e:
            logger.error(f"Logo not found: {str(e)}")
            self.logo = None

        # Initialize user database
        if not os.path.exists(USERS_FILE):
            save_users({"admin": {"email": ADMIN_EMAIL,
                                  "password": hash_password("admin123"),
                                  "approved": True,
                                  "role": "admin"}})
            logger.info("Created initial admin user")

        self.current_user = None
        self.setup_auth_ui()
        logger.info("USB Physical Security application started")

    def setup_auth_ui(self):
        # Clear existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()

        # Create header with logo and title
        header_frame = ttk.Frame(self.root, style="Header.TFrame")
        header_frame.pack(fill=tk.X, pady=(10, 20))

        if self.logo:
            logo_label = ttk.Label(header_frame, image=self.logo, style="Header.TLabel")
            logo_label.pack(side=tk.LEFT, padx=(20, 10))

        title_label = ttk.Label(header_frame,
                                text="USB Physical Security",
                                font=('Arial', 20, 'bold'),
                                style="Header.TLabel")
        title_label.pack(side=tk.LEFT, padx=10, pady=10)

        # Auth Frame
        auth_frame = ttk.Frame(self.root, style="Auth.TFrame", padding=20)
        auth_frame.pack(expand=True, fill=tk.BOTH, padx=50, pady=20)

        ttk.Label(auth_frame, text="Login to USB Control Panel",
                  font=('Arial', 12), style="AuthHeader.TLabel").pack(pady=(0, 15))

        # Login Widgets
        form_frame = ttk.Frame(auth_frame)
        form_frame.pack(fill=tk.X, pady=5)

        ttk.Label(form_frame, text="Email:", style="Form.TLabel").grid(row=0, column=0, sticky='e', padx=5, pady=5)
        self.email_entry = ttk.Entry(form_frame, width=30, font=('Arial', 10))
        self.email_entry.grid(row=0, column=1, pady=5, sticky='ew')
        self.email_entry.focus()

        ttk.Label(form_frame, text="Password:", style="Form.TLabel").grid(row=1, column=0, sticky='e', padx=5, pady=5)
        self.password_entry = ttk.Entry(form_frame, show="*", width=30, font=('Arial', 10))
        self.password_entry.grid(row=1, column=1, pady=5, sticky='ew')

        btn_frame = ttk.Frame(auth_frame)
        btn_frame.pack(pady=15)

        ttk.Button(btn_frame, text="Login", command=self.login, style="Accent.TButton").pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Register", command=self.show_register, style="Secondary.TButton").pack(side=tk.LEFT,
                                                                                                           padx=10)

        # Status label
        self.auth_status = ttk.Label(auth_frame, text="", style="Status.TLabel")
        self.auth_status.pack(pady=(10, 0))

        # Apply styles
        self.apply_styles()
        logger.debug("Authentication UI setup complete")

    def apply_styles(self):
        style = ttk.Style()

        # Configure theme
        style.theme_use('clam')

        # Header styles
        style.configure("Header.TFrame", background="#3498db")
        style.configure("Header.TLabel", background="#3498db", foreground="white")

        # Auth frame styles
        style.configure("Auth.TFrame", background="#ecf0f1", borderwidth=2, relief="groove")
        style.configure("AuthHeader.TLabel", background="#ecf0f1", font=('Arial', 12, 'bold'))

        # Form styles
        style.configure("Form.TLabel", background="#ecf0f1", font=('Arial', 10))

        # Button styles
        style.configure("Accent.TButton",
                        background="#2ecc71",
                        foreground="white",
                        font=('Arial', 10, 'bold'),
                        width=15,
                        borderwidth=1,
                        focusthickness=3,
                        focuscolor='none')
        style.map("Accent.TButton",
                  background=[('active', '#27ae60'), ('pressed', '#27ae60')])

        style.configure("Secondary.TButton",
                        background="#95a5a6",
                        foreground="white",
                        font=('Arial', 10),
                        width=15,
                        borderwidth=1)
        style.map("Secondary.TButton",
                  background=[('active', '#7f8c8d'), ('pressed', '#7f8c8d')])

        # Status label
        style.configure("Status.TLabel", background="#ecf0f1", foreground="#e74c3c", font=('Arial', 9))

    def show_register(self):
        logger.info("Registration window opened")
        register_window = tk.Toplevel(self.root)
        register_window.title("Register New User")
        register_window.geometry("350x150")
        register_window.resizable(False, False)
        register_window.grab_set()
        register_window.configure(bg="#ecf0f1")

        ttk.Label(register_window, text="Email:", background="#ecf0f1").pack(padx=10, pady=10)
        email_entry = ttk.Entry(register_window, width=30)
        email_entry.pack(padx=10, pady=5)
        email_entry.focus()

        def do_register():
            email = email_entry.get().strip()

            if not email or "@" not in email:
                messagebox.showerror("Error", "Please enter a valid email address")
                return

            success, message = register_user(email)
            messagebox.showinfo("Registration", message)
            if success:
                logger.info(f"New registration initiated for: {email}")
                register_window.destroy()

        btn_frame = ttk.Frame(register_window)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Register", command=do_register, style="Accent.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=register_window.destroy, style="Secondary.TButton").pack(
            side=tk.LEFT, padx=5)

    def login(self):
        email = self.email_entry.get().strip()
        password = self.password_entry.get().strip()
        users = load_users()

        if not email or not password:
            self.auth_status.config(text="Both fields are required")
            logger.warning("Login attempt with empty fields")
            return

        # Find user by email
        user_found = None
        for username, user_data in users.items():
            if user_data["email"] == email:
                user_found = username
                break

        if user_found is None:
            self.auth_status.config(text="Email not registered")
            logger.warning(f"Login attempt with unregistered email: {email}")
            threading.Thread(target=capture_intruder_video, daemon=True).start()
            log_action("INTRUDER", "Unauthorized login attempt", f"Email: {email}")
            return

        if not users[user_found]["approved"]:
            self.auth_status.config(text="Account pending admin approval")
            logger.warning(f"Login attempt to unapproved account: {user_found}")
            threading.Thread(target=capture_intruder_video, daemon=True).start()
            log_action("INTRUDER", "Attempt to access unapproved account", f"User: {user_found}")
            return

        if users[user_found]["password"] != hash_password(password):
            self.auth_status.config(text="Invalid password")
            logger.warning(f"Failed login attempt for user: {user_found}")
            threading.Thread(target=capture_intruder_video, daemon=True).start()
            log_action("INTRUDER", "Failed login attempt", f"User: {user_found}")
            return

        self.current_user = user_found
        self.current_role = users[user_found].get("role", "user")
        logger.info(f"User logged in: {user_found} ({self.current_role})")
        log_action(self.current_user, "User logged in")
        self.show_main_ui()

    def show_main_ui(self):
        # Clear existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()

        # Create header
        header_frame = ttk.Frame(self.root, style="Header.TFrame")
        header_frame.pack(fill=tk.X, pady=(10, 20))

        if self.logo:
            logo_label = ttk.Label(header_frame, image=self.logo, style="Header.TLabel")
            logo_label.pack(side=tk.LEFT, padx=(20, 10))

        title_label = ttk.Label(header_frame,
                                text="USB Physical Security",
                                font=('Arial', 20, 'bold'),
                                style="Header.TLabel")
        title_label.pack(side=tk.LEFT, padx=10, pady=10)

        # Main Frame
        main_frame = ttk.Frame(self.root, style="Main.TFrame", padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Welcome message
        welcome_text = f"Welcome, {self.current_user}!"
        if self.current_role == "admin":
            welcome_text += " (Administrator)"

        ttk.Label(main_frame, text=welcome_text,
                  font=('Arial', 12, 'bold'),
                  style="Main.TLabel").pack(pady=10)

        # USB Control Section
        control_frame = ttk.LabelFrame(main_frame, text="USB Port Control", style="Section.TLabelframe")
        control_frame.pack(fill=tk.X, pady=10, padx=10)

        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(pady=10, padx=10)

        ttk.Button(btn_frame, text="Enable USB", width=15,
                   command=self.enable_usb, style="Accent.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Disable USB", width=15,
                   command=self.disable_usb, style="Danger.TButton").pack(side=tk.LEFT, padx=5)

        # Status Section
        status_frame = ttk.LabelFrame(main_frame, text="System Status", style="Section.TLabelframe")
        status_frame.pack(fill=tk.X, pady=10, padx=10)

        btn_frame2 = ttk.Frame(status_frame)
        btn_frame2.pack(pady=10, padx=10)

        ttk.Button(btn_frame2, text="Check USB Status", width=15,
                   command=check_usb_status, style="Secondary.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame2, text="Project Info", width=15,
                   command=self.open_project_info, style="Secondary.TButton").pack(side=tk.LEFT, padx=5)

        # Admin features
        if self.current_role == "admin":
            admin_frame = ttk.LabelFrame(main_frame, text="Administration", style="AdminSection.TLabelframe")
            admin_frame.pack(fill=tk.X, pady=10, padx=10)

            btn_frame3 = ttk.Frame(admin_frame)
            btn_frame3.pack(pady=10, padx=10)

            ttk.Button(btn_frame3, text="Manage Users", width=15,
                       command=self.manage_users, style="Admin.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame3, text="View Security Log", width=15,
                       command=self.view_security_log, style="Admin.TButton").pack(side=tk.LEFT, padx=5)

        # Logout button
        ttk.Button(main_frame, text="Logout",
                   command=self.logout,
                   style="Logout.TButton").pack(pady=20)

        # Apply main styles
        self.apply_main_styles()
        logger.debug("Main UI setup complete")

    def apply_main_styles(self):
        style = ttk.Style()

        # Main frame
        style.configure("Main.TFrame", background="#ecf0f1")
        style.configure("Main.TLabel", background="#ecf0f1")

        # Section frames
        style.configure("Section.TLabelframe", background="#ecf0f1", font=('Arial', 10, 'bold'))
        style.configure("Section.TLabelframe.Label", background="#ecf0f1", foreground="#2c3e50")

        # Admin section
        style.configure("AdminSection.TLabelframe", background="#ecf0f1", font=('Arial', 10, 'bold'))
        style.configure("AdminSection.TLabelframe.Label", background="#ecf0f1", foreground="#c0392b")

        # Danger button
        style.configure("Danger.TButton",
                        background="#e74c3c",
                        foreground="white",
                        font=('Arial', 10, 'bold'),
                        width=15)
        style.map("Danger.TButton",
                  background=[('active', '#c0392b'), ('pressed', '#c0392b')])

        # Admin button
        style.configure("Admin.TButton",
                        background="#9b59b6",
                        foreground="white",
                        font=('Arial', 10, 'bold'),
                        width=15)
        style.map("Admin.TButton",
                  background=[('active', '#8e44ad'), ('pressed', '#8e44ad')])

        # Logout button
        style.configure("Logout.TButton",
                        background="#95a5a6",
                        foreground="white",
                        font=('Arial', 10),
                        width=10)
        style.map("Logout.TButton",
                  background=[('active', '#7f8c8d'), ('pressed', '#7f8c8d')])

    def manage_users(self):
        logger.info(f"Admin {self.current_user} opened user management")
        users = load_users()
        manage_window = tk.Toplevel(self.root)
        manage_window.title("User Management")
        manage_window.geometry("500x400")
        manage_window.resizable(False, False)
        manage_window.grab_set()

        # Treeview for users
        tree_frame = ttk.Frame(manage_window)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        columns = ('username', 'email', 'status', 'role')
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings')

        # Define columns
        tree.heading('username', text='Username')
        tree.heading('email', text='Email')
        tree.heading('status', text='Status')
        tree.heading('role', text='Role')

        tree.column('username', width=120, anchor='w')
        tree.column('email', width=180, anchor='w')
        tree.column('status', width=80, anchor='center')
        tree.column('role', width=80, anchor='center')

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Add data
        for username, data in users.items():
            if username == "admin":  # Skip admin account
                continue
            status = "Approved" if data["approved"] else "Pending"
            role = data.get("role", "user")
            tree.insert('', 'end', values=(username, data["email"], status, role))

        # Button frame
        btn_frame = ttk.Frame(manage_window)
        btn_frame.pack(fill=tk.X, pady=5, padx=10)

        def approve_selected():
            selected = tree.focus()
            if not selected:
                messagebox.showinfo("Info", "Please select a user")
                return

            username = tree.item(selected, 'values')[0]
            success, message = approve_user(username)
            messagebox.showinfo("Approval", message)
            if success:
                log_action(self.current_user, "Approved user", f"Username: {username}")
                manage_window.destroy()

        def reject_selected():
            selected = tree.focus()
            if not selected:
                messagebox.showinfo("Info", "Please select a user")
                return

            username = tree.item(selected, 'values')[0]
            success, message = reject_user(username)
            messagebox.showinfo("Rejection", message)
            if success:
                log_action(self.current_user, "Rejected user", f"Username: {username}")
                manage_window.destroy()

        def promote_selected():
            selected = tree.focus()
            if not selected:
                messagebox.showinfo("Info", "Please select a user")
                return

            username = tree.item(selected, 'values')[0]
            success, message = promote_to_admin(username)
            messagebox.showinfo("Promotion", message)
            if success:
                log_action(self.current_user, "Promoted user to admin", f"Username: {username}")
                manage_window.destroy()

        ttk.Button(btn_frame, text="Approve Selected",
                   command=approve_selected, style="Accent.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Reject Selected",
                   command=reject_selected, style="Danger.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Promote to Admin",
                   command=promote_selected, style="Admin.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close",
                   command=manage_window.destroy, style="Secondary.TButton").pack(side=tk.RIGHT, padx=5)

    def view_security_log(self):
        logger.info(f"Admin {self.current_user} viewing security log")
        log_window = tk.Toplevel(self.root)
        log_window.title("Security Actions Log")
        log_window.geometry("700x400")

        # Create text widget with scrollbar
        text_frame = ttk.Frame(log_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        text_area = Text(text_frame, wrap="word", font=("Consolas", 10))
        scrollbar = ttk.Scrollbar(text_frame, command=text_area.yview)
        text_area.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Load log content
        try:
            if os.path.exists(LOGGED_ACTIONS_FILE):
                with open(LOGGED_ACTIONS_FILE, "r") as f:
                    log_content = f.read()
                    text_area.insert("1.0", log_content)
            else:
                text_area.insert("1.0", "No security log entries found")
        except Exception as e:
            logger.error(f"Error loading security log: {str(e)}")
            text_area.insert("1.0", f"Error loading log: {str(e)}")

        text_area.config(state="disabled")

        # Add close button
        btn_frame = ttk.Frame(log_window)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Close", command=log_window.destroy).pack()

    def enable_usb(self):
        if not is_admin():
            messagebox.showerror("Admin Required", "Please run as administrator.")
            logger.error("Enable USB failed: Admin privileges required")
            return

        if set_usb_registry(3):  # 3 = Manual start
            log_action(self.current_user, "USB ports ENABLED", "Changes take effect after reboot")
            logger.info("USB ports enabled (pending reboot)")
            messagebox.showinfo("USB Enabled",
                                "USB ports will be ENABLED after system restart.\n"
                                "Please reboot your computer for changes to take effect.")
            prompt_reboot()
        else:
            logger.error("Failed to enable USB ports")
            messagebox.showerror("Failed", "Failed to enable USB ports.")

    def disable_usb(self):
        if not is_admin():
            messagebox.showerror("Admin Required", "Please run as administrator.")
            logger.error("Disable USB failed: Admin privileges required")
            return

        if set_usb_registry(4):  # 4 = Disabled
            log_action(self.current_user, "USB ports DISABLED", "Changes take effect after reboot")
            logger.warning("USB ports disabled (pending reboot)")
            messagebox.showwarning("USB Disabled",
                                   "USB ports will be DISABLED after system restart.\n"
                                   "Please reboot your computer for changes to take effect.")
            prompt_reboot()
        else:
            logger.error("Failed to disable USB ports")
            messagebox.showerror("Failed", "Failed to disable USB ports.")

    def open_project_info(self):
        webbrowser.open(f"file://{os.path.abspath(html_report_path)}")
        log_action(self.current_user, "Viewed project information")
        logger.info("Project information opened")

    def logout(self):
        logger.info(f"User logged out: {self.current_user}")
        log_action(self.current_user, "Logged out")
        self.current_user = None
        self.setup_auth_ui()


# === Main Application ===
if __name__ == "__main__":
    if not is_admin():
        logger.critical("Application started without admin privileges")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", "python", __file__, None, 1)
        exit()

    root = tk.Tk()
    app = USBControlApp(root)

    # Log application start
    logger.info("=" * 80)
    logger.info("USB Physical Security Application Started")
    logger.info(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Operating System: {os.name} {os.environ.get('OS', '')}")
    logger.info("=" * 80)

    root.mainloop()