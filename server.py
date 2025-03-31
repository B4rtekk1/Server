from flask import Flask, request, jsonify, send_from_directory
import os
import smtplib
from email.mime.text import MIMEText
import shutil
import signal
import logging
from datetime import datetime, timedelta, timezone
import json
import random
from dotenv import load_dotenv
from PIL import Image
import jwt
import bcrypt
from flask_sqlalchemy import SQLAlchemy

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

UPLOAD_FOLDER = "uploads"
API_KEY = os.getenv("API_KEY")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
KNOWN_DEVICE_IDS = os.getenv("KNOWN_DEVICE_IDS").split(",")
EMAIL_SENDER = "bartoszkasyna@gmail.com"
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECEIVER = "bartoszkasyna@gmail.com"
LOG_FILE = "ServerLogs/server_logs.txt"
SENT_ALERTS_FILE = "sent_alerts.json"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    verification_code = db.Column(db.String(6), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

log_messages = []
sent_alerts = {}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

def compress_image(image_path, quality=70):
    try:
        image = Image.open(image_path)
        if image.mode in ("RGBA", "P"):
            image = image.convert("RGB")
        image.save(image_path, quality=quality, optimize=True)
        return "Image compressed successfully"
    except Exception as e:
        return f"Error: {e}"

def load_logs_from_file():
    global log_messages
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            log_messages = f.readlines()
        logger.info(f"Loaded {len(log_messages)} log entries from {LOG_FILE}")
    else:
        logger.info(f"No log file found at {LOG_FILE}, starting with empty log list")

def load_sent_alerts():
    global sent_alerts
    if os.path.exists(SENT_ALERTS_FILE):
        with open(SENT_ALERTS_FILE, "r") as f:
            loaded = json.load(f)
            sent_alerts = {k: datetime.fromisoformat(v) for k, v in loaded.items()}
    else:
        sent_alerts = {}

def save_sent_alerts():
    with open(SENT_ALERTS_FILE, "w") as f:
        json.dump({k: v.isoformat() for k, v in sent_alerts.items()}, f)

def log_to_memory_and_file(level, message):
    global log_messages
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
    log_entry = f"{timestamp} - {level.upper()} - {message}"
    log_messages.append(log_entry + "\n")
    if level == "INFO":
        logger.info(message)
    elif level == "WARNING":
        logger.warning(message)
    elif level == "ERROR":
        logger.error(message)

def send_email(to_email, subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_SENDER
    msg["To"] = to_email
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        log_to_memory_and_file("INFO", f"Email sent to {to_email}")
    except Exception as e:
        log_to_memory_and_file("ERROR", f"Error sending email to {to_email}: {e}")
        raise

def send_alert(device_id, ip):
    device_id_cleaned = device_id.strip().replace("{", "").replace("}", "")
    current_time = datetime.now()
    
    last_alert_time = sent_alerts.get(device_id_cleaned)
    if last_alert_time and (current_time - last_alert_time) < timedelta(hours=1):
        return

    sent_alerts[device_id_cleaned] = current_time
    save_sent_alerts()

    subject = "New device detected"
    body = f"Someone tried to access your files with device ID: {device_id}"
    send_email(EMAIL_RECEIVER, subject, body)

def check_api_key_and_device():
    api_key = request.headers.get("X-Api-Key")
    device_id = request.headers.get("X-Device-ID")
    client_ip = request.remote_addr
    
    if api_key.strip() != API_KEY.strip():
        log_to_memory_and_file("WARNING", f"Unauthorized access attempt from device ID {device_id}")
        return jsonify({"error": "Unauthorized"}), 401
    
    if not device_id:
        return jsonify({"error": "Device ID required"}), 400
    
    device_id_cleaned = device_id.strip().replace("{", "").replace("}", "")
    known_ids_cleaned = [id.strip().replace("{", "").replace("}", "") for id in KNOWN_DEVICE_IDS]
    
    if device_id_cleaned not in known_ids_cleaned:
        send_alert(device_id, client_ip)
        log_to_memory_and_file("WARNING", f"Unknown device ID: {device_id}")
        return jsonify({"warning": f"Device {device_id} unknown"}), 403
    
    return None

def generate_token(username):
    payload = {
        "username": username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["username"]
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    def decorator(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Token is missing"}), 401
        if token.startswith("Bearer "):
            token = token[7:]
        username = verify_token(token)
        if not username:
            return jsonify({"error": "Invalid or expired token"}), 401
        return f(*args, **kwargs)
    decorator.__name__ = f.__name__
    return decorator

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    identifier = data.get("identifier")
    password = data.get("password")
    user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
    if user and user.check_password(password):
        if not user.is_verified:
            return jsonify({"error": "Email not verified"}), 403
        token = generate_token(user.username)
        log_to_memory_and_file("INFO", f"User {user.username} logged in")
        return jsonify({"token": token})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    
    if not email or not username or not password:
        return jsonify({"error": "All fields (username, password, email) are required"}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 400
    
    verification_code = str(random.randint(100000, 999999))
    
    new_user = User(username=username, email=email, verification_code=verification_code)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    
    send_email(email, "Verify Your Email", f"Your verification code is: {verification_code}")
    
    log_to_memory_and_file("INFO", f"User {username} registered, verification code sent to {email}")
    return jsonify({"message": f"User {username} registered successfully. Please verify your email."}), 201

@app.route("/verify-email", methods=["POST"])
def verify_email():
    data = request.json
    email = data.get("email")
    code = data.get("code")
    
    if not email or not code:
        return jsonify({"error": "Email and code are required"}), 400
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if user.is_verified:
        return jsonify({"message": "Email already verified"}), 200
    
    if user.verification_code == code:
        user.is_verified = True
        user.verification_code = None
        db.session.commit()
        log_to_memory_and_file("INFO", f"Email {email} verified for user {user.username}")
        return jsonify({"message": "Email verified successfully"}), 200
    else:
        return jsonify({"error": "Invalid verification code"}), 400

@app.route("/list", methods=["GET"])
@token_required
def list_files():
    auth_error = check_api_key_and_device()
    if auth_error:
        return auth_error
    folder_path = request.args.get("folder", "")
    base_upload_folder = os.path.abspath(UPLOAD_FOLDER)
    target_folder = os.path.abspath(os.path.join(base_upload_folder, folder_path))
    if not target_folder.startswith(base_upload_folder):
        log_to_memory_and_file("WARNING", f"Invalid folder path attempted: {folder_path}")
        return jsonify({"error": "Invalid folder path"}), 400
    
    if not os.path.exists(target_folder):
        log_to_memory_and_file("WARNING", f"Target folder not found: {target_folder}")
        return jsonify({"error": "Folder not found"}), 404
    
    items = []
    for root, dirs, files_in_dir in os.walk(target_folder):
        for dir_name in dirs:
            full_path = os.path.join(root, dir_name)
            if os.path.exists(full_path):
                try:
                    relative_path = os.path.relpath(full_path, base_upload_folder)
                    mod_time = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime('%Y-%m-%d %H:%M')
                    items.append({"path": relative_path + "/", "type": "directory", "modified": mod_time})
                except Exception as e:
                    log_to_memory_and_file("ERROR", f"Error processing directory {full_path}: {e}")
            else:
                log_to_memory_and_file("WARNING", f"Directory {full_path} not found, skipping")
        
        for file in files_in_dir:
            full_path = os.path.join(root, file)
            if os.path.exists(full_path):
                try:
                    relative_path = os.path.relpath(full_path, base_upload_folder)
                    mod_time = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime('%Y-%m-%d %H:%M')
                    items.append({"path": relative_path, "type": "file", "modified": mod_time})
                except Exception as e:
                    log_to_memory_and_file("ERROR", f"Error processing file {full_path}: {e}")
            else:
                log_to_memory_and_file("WARNING", f"File {full_path} not found, skipping")
        break
    
    log_to_memory_and_file("INFO", "User listed files")
    return jsonify({"files": items})

@app.route("/upload", methods=["POST"])
@token_required
def upload_file():
    auth_error = check_api_key_and_device()
    if auth_error:
        return auth_error
    file = request.files["file"]
    requested_folder = request.form.get("folder", "")
    base_upload_folder = os.path.abspath(UPLOAD_FOLDER)
    full_path = os.path.abspath(os.path.join(base_upload_folder, requested_folder))
    if not full_path.startswith(base_upload_folder):
        log_to_memory_and_file("WARNING", f"Invalid folder path attempted: {requested_folder}")
        return jsonify({"error": "Invalid folder path"}), 400
    os.makedirs(full_path, exist_ok=True)
    filename = os.path.basename(file.filename)
    file_path = os.path.join(full_path, filename)
    file.save(file_path)
    
    if filename.lower().endswith((".jpg", ".jpeg", ".png")):
        compress_result = compress_image(file_path)
        log_to_memory_and_file("INFO", f"Uploaded and compressed image: {filename} - {compress_result}")
    
    relative_path = os.path.relpath(file_path, base_upload_folder)
    log_to_memory_and_file("INFO", f"Uploaded file: {relative_path}")
    return jsonify({"message": f"File {relative_path} uploaded successfully"})

@app.route("/download/<path:filename>", methods=["GET"])
@token_required
def download_file(filename):
    auth_error = check_api_key_and_device()
    if auth_error:
        return auth_error
    base_upload_folder = os.path.abspath(UPLOAD_FOLDER)
    file_path = os.path.abspath(os.path.join(base_upload_folder, filename))
    if not file_path.startswith(base_upload_folder):
        log_to_memory_and_file("WARNING", f"Invalid file path attempted: {filename}")
        return jsonify({"error": "Invalid file path"}), 400
    if not os.path.exists(file_path):
        log_to_memory_and_file("WARNING", f"File not found: {filename}")
        return jsonify({"error": "File not found"}), 404
    log_to_memory_and_file("INFO", f"Downloaded file: {filename}")
    return send_from_directory(base_upload_folder, filename)

@app.route("/delete/<path:filename>", methods=["DELETE"])
@token_required
def delete_file(filename):
    auth_error = check_api_key_and_device()
    if auth_error:
        return auth_error
    base_upload_folder = os.path.abspath(UPLOAD_FOLDER)
    file_path = os.path.abspath(os.path.join(base_upload_folder, filename))
    if not file_path.startswith(base_upload_folder):
        log_to_memory_and_file("WARNING", f"Invalid file path attempted: {filename}")
        return jsonify({"error": "Invalid file path"}), 400
    if os.path.exists(file_path):
        os.remove(file_path)
        log_to_memory_and_file("INFO", f"Deleted file: {filename}")
        return jsonify({"message": f"File {filename} deleted"})
    log_to_memory_and_file("WARNING", f"File not found for deletion: {filename}")
    return jsonify({"error": "File not found"}), 404

@app.route("/move/<path:filename>", methods=["POST"])
@token_required
def move_file(filename):
    auth_error = check_api_key_and_device()
    if auth_error:
        return auth_error
    new_name = request.json.get("new_name")
    if not new_name:
        log_to_memory_and_file("WARNING", "New name not provided for move")
        return jsonify({"error": "New name not provided"}), 400
    base_upload_folder = os.path.abspath(UPLOAD_FOLDER)
    old_path = os.path.abspath(os.path.join(base_upload_folder, filename))
    new_path = os.path.abspath(os.path.join(base_upload_folder, new_name))
    if not old_path.startswith(base_upload_folder) or not new_path.startswith(base_upload_folder):
        log_to_memory_and_file("WARNING", f"Invalid path attempted: {filename} to {new_name}")
        return jsonify({"error": "Invalid path"}), 400
    if not os.path.exists(old_path):
        log_to_memory_and_file("WARNING", f"File not found for move: {filename}")
        return jsonify({"error": "File not found"}), 404
    new_dir = os.path.dirname(new_path)
    os.makedirs(new_dir, exist_ok=True)
    shutil.move(old_path, new_path)
    log_to_memory_and_file("INFO", f"Moved file from {filename} to {new_name}")
    return jsonify({"message": f"File moved to: {new_name}"})

server_variable = "Default Value"

@app.route("/update_variable", methods=["POST"])
@token_required
def update_variable():
    auth_error = check_api_key_and_device()
    if auth_error:
        return auth_error
    data = request.json
    new_value = data.get("new_value")
    if not new_value:
        log_to_memory_and_file("WARNING", "No new value provided")
        return jsonify({"error": "No new value provided"}), 400
    global server_variable
    server_variable = new_value
    log_to_memory_and_file("INFO", f"Server variable updated to: {server_variable}")
    return jsonify({"message": f"Server variable updated to: {server_variable}"})

@app.route("/get_variable", methods=["GET"])
@token_required
def get_variable():
    auth_error = check_api_key_and_device()
    if auth_error:
        return auth_error
    return jsonify({"server_variable": server_variable})

@app.route("/get_logs", methods=["GET"])
@token_required
def get_logs():
    auth_error = check_api_key_and_device()
    if auth_error:
        return auth_error
    return jsonify({"logs": "".join(log_messages)})

def shutdown_handler(signum, frame):
    log_to_memory_and_file("INFO", "Server is shutting down")
    app.logger.handlers.clear()
    print("Server stopped")
    exit(0)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@example.com')
            admin.set_password('admin123')
            admin.is_verified = True
            db.session.add(admin)
            db.session.commit()
    load_logs_from_file()
    load_sent_alerts()
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    print("Server starting on http://localhost:5000")
    log_to_memory_and_file("INFO", "Server started")
    app.run(host="0.0.0.0", port=5000, debug=True)