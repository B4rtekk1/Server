from flask import Flask, request, jsonify, send_from_directory
import os
import smtplib
from email.mime.text import MIMEText
import shutil
import signal
import logging
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
API_KEY = os.getenv("API_KEY")
KNOWN_DEVICE_IDS = os.getenv("KNOWN_DEVICE_IDS").split(",")
EMAIL_SENDER = "bartoszkasyna@gmail.com"
EMAIL_PASSWORD = "#############"
EMAIL_RECEIVER = "bartoszkasyna@gmail.com"
LOG_FILE = "ServerLogs/server_logs.txt"

log_messages = []

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

def load_logs_from_file():
    global log_messages
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            log_messages = f.readlines()
        logger.info(f"Loaded {len(log_messages)} log entries from {LOG_FILE}")
    else:
        logger.info(f"No log file found at {LOG_FILE}, starting with empty log list")

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

def send_alert(device_id, ip):
    subject = "New device detected"
    body = f"Someone tried to access your files with device ID: {device_id} from IP: {ip}"
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECEIVER
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        log_to_memory_and_file("ERROR", f"An error occurred {e}")
        print(f"An error occurred {e}")

def check_api_key_and_device():
    api_key = request.headers.get("X-Api-Key")
    device_id = request.headers.get("X-Device-ID")
    client_ip = request.remote_addr
    
    if api_key.strip() != API_KEY.strip():
        log_to_memory_and_file("WARNING", f"Unauthorized access attempt from IP {client_ip}, {api_key}, {API_KEY}")
        return jsonify({"error": "Unauthorized"}), 401
    
    if not device_id:
        log_to_memory_and_file("WARNING", f"No device ID provided from IP {client_ip}")
        return jsonify({"error": "Device ID required"}), 400
    
    device_id_cleaned = device_id.strip().replace("{", "").replace("}", "")
    known_ids_cleaned = [id.strip().replace("{", "").replace("}", "") for id in KNOWN_DEVICE_IDS]
    
    if device_id_cleaned not in known_ids_cleaned:
        send_alert(device_id, client_ip)
        log_to_memory_and_file("WARNING", f"Unknown device ID: {device_id} from IP {client_ip}")
        return jsonify({"warning": f"Device {device_id} unknown"}), 403
    
    return None

@app.route("/list", methods=["GET"])
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
    
    items = []
    for root, dirs, files_in_dir in os.walk(target_folder):
        for dir_name in dirs:
            relative_path = os.path.relpath(os.path.join(root, dir_name), base_upload_folder)
            full_path = os.path.join(root, dir_name)
            mod_time = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime('%Y-%m-%d %H:%M')
            items.append({"path": relative_path + "/", "type": "directory", "modified": mod_time})
        for file in files_in_dir:
            relative_path = os.path.relpath(os.path.join(root, file), base_upload_folder)
            full_path = os.path.join(root, file)
            mod_time = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime('%Y-%m-%d %H:%M')
            items.append({"path": relative_path, "type": "file", "modified": mod_time})
        break
        
    
    log_to_memory_and_file("INFO", "User listed files")
    return jsonify({"files": items})

@app.route("/upload", methods=["POST"])
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
    relative_path = os.path.relpath(file_path, base_upload_folder)
    log_to_memory_and_file("INFO", f"Uploaded file: {relative_path}")
    return jsonify({"message": f"File {relative_path} uploaded successfully"})

@app.route("/download/<path:filename>", methods=["GET"])
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
def get_variable():
    auth_error = check_api_key_and_device()
    if auth_error:
        return auth_error
    return jsonify({"server_variable": server_variable})

@app.route("/get_logs", methods=["GET"])
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
    load_logs_from_file()
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    print("Server starting on http://localhost:5000")
    log_to_memory_and_file("INFO", "Server started")
    app.run(host="0.0.0.0", port=5000)