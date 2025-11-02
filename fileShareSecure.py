import subprocess
import importlib
import sys
import threading
import time

required_modules = ['colorama', 'itsdangerous', 'click', 'blinker', 'flask', 'cryptography']

def install_missing_modules(modules):
    try:
        pip = 'pip'
        importlib.import_module(pip)
    except ImportError:
        print(f"{pip} is not installed. Installing...")
        subprocess.check_call([sys.executable, "-m", "ensurepip", "--upgrade"])
    for module in modules:
        try:
            importlib.import_module(module)
        except ImportError:
            print(f"{module} is not installed. Installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", module])

install_missing_modules(required_modules)

import os
import secrets
import json
import io
import hashlib
import datetime
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session
from flask import Flask, request, redirect, url_for, send_from_directory, render_template_string, flash, jsonify
from werkzeug.utils import secure_filename
from functools import wraps
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configuration
UPLOAD_FOLDER = './uploads'
BLOB_FOLDER = './blobs'
DATABASE_FILE = 'fileshare.db'
DEFAULT_MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
DEFAULT_USER_QUOTA = 100 * 1024 * 1024  # 100 MB
DEFAULT_ADMIN_QUOTA = 2 * 1024 * 1024 * 1024  # 2 GB
DEFAULT_SUPERUSER_QUOTA = 10 * 1024 * 1024 * 1024  # 10 GB
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'supersecretkey'  # Needed for flashing messages

# Master key used to wrap per-file encryption keys (derived from app secret)
MASTER_KEY = hashlib.sha256(app.secret_key.encode('utf-8')).digest()

# Create the upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(BLOB_FOLDER):
    os.makedirs(BLOB_FOLDER)

# --- Database Functions ---
def init_database():
    """Initialize the database with required tables."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            privilege_level INTEGER NOT NULL DEFAULT 0
        )
    ''')
    
    # Create banned_ips table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS banned_ips (
            ip_address TEXT PRIMARY KEY
        )
    ''')
    
    # Create user_quotas table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_quotas (
            username TEXT PRIMARY KEY,
            quota_bytes INTEGER NOT NULL,
            FOREIGN KEY (username) REFERENCES users (username)
        )
    ''')
    
    # Create user_upload_limits table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_upload_limits (
            username TEXT PRIMARY KEY,
            upload_limit_bytes INTEGER,
            FOREIGN KEY (username) REFERENCES users (username)
        )
    ''')
    
    # Create user_folder_passwords table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_folder_passwords (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            FOREIGN KEY (username) REFERENCES users (username)
        )
    ''')
    
    # Create max_upload_size table (single row)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS max_upload_size (
            id INTEGER PRIMARY KEY DEFAULT 1,
            max_size_bytes INTEGER NOT NULL,
            CHECK (id = 1)
        )
    ''')
    
    # MODIFIED: Add file_id as primary key (composite of uploader+filename)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_stats (
            file_id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            uploader TEXT NOT NULL,
            upload_time TEXT NOT NULL,
            size INTEGER NOT NULL,
            download_count INTEGER NOT NULL DEFAULT 0,
            expiry TEXT,
            temporary BOOLEAN NOT NULL DEFAULT 0,
            unlisted BOOLEAN NOT NULL DEFAULT 0,
            FOREIGN KEY (uploader) REFERENCES users (username)
        )
    ''')

    # MODIFIED: Use file_id instead of filename
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS download_tokens (
            file_id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            nonce BLOB NOT NULL,
            blob_path TEXT NOT NULL,
            wrapped_key BLOB,
            created TEXT NOT NULL,
            FOREIGN KEY (file_id) REFERENCES file_stats (file_id)
        )
    ''')

    # MODIFIED: Use file_id for reports
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            reporter_ip TEXT NOT NULL,
            reason TEXT NOT NULL,
            details TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            created TEXT NOT NULL,
            resolved_by TEXT,
            resolved_at TEXT
        )
    ''')
    
    # Insert default max upload size if not exists
    cursor.execute('SELECT COUNT(*) FROM max_upload_size')
    if cursor.fetchone()[0] == 0:
        cursor.execute('INSERT INTO max_upload_size (max_size_bytes) VALUES (?)', (DEFAULT_MAX_UPLOAD_SIZE,))
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Get a database connection."""
    return sqlite3.connect(DATABASE_FILE)

# Initialize database on startup
init_database()

# HTML template for the webpage
HTML = '''
<!doctype html>
<html>
  <head>
    <title>Local File Sharing</title>
    <style>
      body { font-family: Arial, sans-serif; text-align: center; margin: 20px; }
      .progress-container { width: 50%; margin: 20px auto; display: none; }
      .progress-bar { width: 100%; background-color: #f3f3f3; border: 1px solid #ccc; }
      .progress { height: 20px; width: 0%; background-color: #4caf50; text-align: center; color: white; line-height: 20px; }
    </style>
  </head>
  <body>
    <h1>Upload a File</h1>
    <form id="uploadForm">
      <input type="file" id="fileInput" name="file">
      <label><input type="checkbox" id="temporary" name="temporary"> Temporary</label>
      <label><input type="checkbox" id="unlisted" name="unlisted"> Unlisted</label>
      <input type="number" id="expiry_hours" name="expiry_hours" min="1" max="168" placeholder="Expiry (hours)">
      <button type="button" onclick="uploadFile()">Upload</button>
    </form>

    <div class="progress-container">
      <div class="progress-bar">
        <div id="progress" class="progress">0%</div>
      </div>
    </div>

    <h2>Available Files</h2>
    <form method="get" style="margin-bottom: 10px;">
      <input type="text" name="q" placeholder="Search files" value="{{ request.args.get('q', '') }}">
      <select name="sort">
        <option value="name" {% if sort == 'name' %}selected{% endif %}>Name</option>
        <option value="date" {% if sort == 'date' %}selected{% endif %}>Upload Date</option>
        <option value="size" {% if sort == 'size' %}selected{% endif %}>Size</option>
        <option value="downloads" {% if sort == 'downloads' %}selected{% endif %}>Downloads</option>
      </select>
      <select name="order">
        <option value="asc" {% if order == 'asc' %}selected{% endif %}>Ascending</option>
        <option value="desc" {% if order == 'desc' %}selected{% endif %}>Descending</option>
      </select>
      <button type="submit">Apply</button>
    </form>
    <ul>
      {% for file in files %}
        <li>
          <a href="{{ url_for('download_file', filename=file['name']) }}">{{ file['name'] }}</a>
          ({{ file['size']|default(0, true) // 1024 }} KB, {{ file['download_count']|default(0, true) }} downloads)
          {% if file['temporary'] %} [Temporary]{% endif %}
          {% if file['unlisted'] %} [Unlisted]{% endif %}
          {% if file['expiry'] %} [Expires: {{ file['expiry'][:16].replace('T', ' ') }}]{% endif %}
          {% if file['uploader'] == session['username'] or is_admin %}
            <form method="post" action="{{ url_for('delete_file', filename=file['name']) }}" style="display:inline;">
              <button type="submit">Delete</button>
            </form>
          {% endif %}
        </li>
      {% endfor %}
    </ul>

    <script>
      function uploadFile() {
          let fileInput = document.getElementById('fileInput');
          if (!fileInput.files.length) {
              alert("Please select a file.");
              return;
          }

          let file = fileInput.files[0];
          let formData = new FormData();
          formData.append("file", file);
          let temporary = document.getElementById('temporary').checked;
          let unlisted = document.getElementById('unlisted').checked;
          let expiry_hours = document.getElementById('expiry_hours').value;
          formData.append("temporary", temporary ? '1' : '0');
          formData.append("unlisted", unlisted ? '1' : '0');
          formData.append("expiry_hours", expiry_hours);

          let xhr = new XMLHttpRequest();
          xhr.open("POST", "/", true);

          // Show progress bar
          document.querySelector('.progress-container').style.display = "block";

          xhr.upload.onprogress = function(event) {
              if (event.lengthComputable) {
                  let percentComplete = (event.loaded / event.total) * 100;
                  let progressBar = document.getElementById('progress');
                  progressBar.style.width = percentComplete + "%";
                  progressBar.innerText = Math.round(percentComplete) + "%";
              }
          };

          xhr.onload = function() {
              if (xhr.status == 200) {
                  location.reload();  // Refresh to show new file
              } else {
                  alert("File upload failed.");
              }
          };

          xhr.send(formData);
      }
    </script>
  </body>
</html>
'''

# --- Helper function to generate file_id ---
def make_file_id(username, filename):
    """Generate unique file_id from username and filename."""
    return f"{username}:{filename}"

# --- User Management ---
PRIV_USER = 0
PRIV_ADMIN = 1
PRIV_SUPERUSER = 2
AUTH_LOG_FILE = None

def log_auth_event(event_type, username, ip, extra=None):
    return

def load_user_folder_passwords():
    """Load all user folder passwords from database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username, password_hash FROM user_folder_passwords')
    passwords = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()
    return passwords

def set_user_folder_password(username, password):
    """Set or remove user folder password."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if password:
        pw_hash = generate_password_hash(password)
        cursor.execute('''
            INSERT OR REPLACE INTO user_folder_passwords (username, password_hash)
            VALUES (?, ?)
        ''', (username, pw_hash))
    else:
        cursor.execute('DELETE FROM user_folder_passwords WHERE username = ?', (username,))
    
    conn.commit()
    conn.close()

def check_user_folder_password(username, password):
    """Check if the provided password matches the user's folder password."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM user_folder_passwords WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return True  # No password set
    return check_password_hash(result[0], password)

def load_banned_ips():
    """Load all banned IPs from database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT ip_address FROM banned_ips')
    banned_ips = {row[0] for row in cursor.fetchall()}
    conn.close()
    return banned_ips

def ban_ip(ip):
    """Ban an IP address."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT OR REPLACE INTO banned_ips (ip_address) VALUES (?)', (ip,))
    conn.commit()
    conn.close()

def unban_ip(ip):
    """Unban an IP address."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM banned_ips WHERE ip_address = ?', (ip,))
    conn.commit()
    conn.close()

def is_banned(ip):
    """Check if an IP is banned."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM banned_ips WHERE ip_address = ?', (ip,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def load_users():
    """Load all users from database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username, password_hash, privilege_level FROM users')
    users = {row[0]: (row[1], str(row[2])) for row in cursor.fetchall()}
    conn.close()
    return users

def save_user(username, password, priv=PRIV_USER):
    """Save a new user to the database."""
    pw_hash = generate_password_hash(password)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO users (username, password_hash, privilege_level)
        VALUES (?, ?, ?)
    ''', (username, pw_hash, priv))
    conn.commit()
    conn.close()

def is_superuser():
    users = load_users()
    if 'username' not in session:
        return False
    username = session['username']
    return username in users and int(users[username][1]) == PRIV_SUPERUSER

def is_admin():
    users = load_users()
    if 'username' not in session:
        return False
    username = session['username']
    return username in users and int(users[username][1]) in (PRIV_ADMIN, PRIV_SUPERUSER)

def check_session_password():
    if 'username' not in session or 'pw_hash' not in session:
        return False
    users = load_users()
    username = session['username']
    if username not in users:
        return False
    return session['pw_hash'] == users[username][0]

# --- Registration, Login, Logout Routes ---
registration_template = """
<!doctype html>
<title>Register</title>
<h2>Register a new account:</h2>
<form method="post" action="{{ url_for('register') }}">
  <input type="text" name="username" required placeholder="Username">
  <input type="password" name="password" required placeholder="Password">
  <input type="submit" value="Register">
</form>
<p>Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
"""

login_template = """
<!doctype html>
<title>Login</title>
<h2>Login to your account:</h2>
<form method="post" action="{{ url_for('login') }}">
  <input type="text" name="username" required placeholder="Username">
  <input type="password" name="password" required placeholder="Password">
  <input type="submit" value="Login">
</form>
<p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a> (Registering lets you upload whatever you want :D)</p>
<p><a href="{{url_for('info') }}">More Info</a></p>
"""

info_page = """
<!doctype html>
<title>Information</title>
<p>Users who register are automatically assigned a private folder with 100MB of space and a 10MB upload limit.</p>
<p>All files are encrypted, and can only be viewed by you and whoever you send them to.</p>
<p>When generating a link for a file, any previous link for that file will stop working, only the newest link will work.</p>
<p>Back to <a href="{{ url_for('login') }}">Login</a></p>
"""

# --- Per-user folder helpers ---
def get_user_folder(username):
    return os.path.join(UPLOAD_FOLDER, username)

def ensure_user_folder(username):
    folder = get_user_folder(username)
    if not os.path.exists(folder):
        os.makedirs(folder)

@app.before_request
def block_banned_ips():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if is_banned(ip):
        return "Your IP has been banned.", 403

@app.route('/info', methods=['GET'])
def info():
    return render_template_string(info_page)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if not username or not password:
            flash("Username and password cannot be empty.")
            return redirect(url_for('register'))

        if username.lower() == "anonymous":
            flash("The username 'Anonymous' is reserved and cannot be registered.")
            return redirect(url_for('register'))

        users = load_users()
        if username in users:
            flash("Username already exists. Please choose another.")
            return redirect(url_for('register'))

        priv = PRIV_SUPERUSER if username == "Ryder7223" else PRIV_USER
        save_user(username, password, priv=priv)
        ensure_user_folder(username)
        log_auth_event('register', username, ip)
        flash("Registration successful! Please log in.")
        return redirect(url_for('login'))

    return render_template_string(registration_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    users = load_users()
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            flash("Username and password cannot be empty.")
            return redirect(url_for('login'))
        if username not in users or not check_password_hash(users[username][0], password):
            flash("Invalid username or password.")
            return redirect(url_for('login'))
        session['username'] = username
        session['pw_hash'] = users[username][0]
        return redirect(url_for('main'))
    return render_template_string(login_template)

@app.route('/logout', methods=['GET'])
def logout():
    session.pop('username', None)
    session.pop('pw_hash', None)
    flash('Logged out successfully.')
    return redirect(url_for('login'))

# --- File Metadata and Quotas ---

FILE_EVENTS_LOG = None

def log_file_event(event_type, filename, user, ip, extra=None):
    return

def cleanup_expired_files():
    stats = load_file_stats()
    now = datetime.datetime.now()
    to_delete = []
    users = list(load_users().keys())
    for file_id, meta in stats.items():
        if meta.get('temporary') and meta.get('expiry'):
            try:
                expiry = datetime.datetime.fromisoformat(meta['expiry'])
                if now > expiry:
                    to_delete.append((file_id, meta.get('uploader'), meta.get('filename')))
            except Exception:
                continue
    for file_id, uploader, fname in to_delete:
        folder = get_user_folder(uploader) if uploader else UPLOAD_FOLDER
        try:
            os.remove(os.path.join(folder, fname))
        except Exception:
            pass
        remove_file_metadata(file_id)
        log_file_event('expired_delete', fname, 'system', 'localhost')

def with_expiry_cleanup(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        cleanup_expired_files()
        return f(*args, **kwargs)
    return decorated

def binary_filesize(value):
    # value is bytes
    units = ["bytes", "KiB", "MiB", "GiB", "TiB"]
    size = float(value)
    i = 0
    while size >= 1024 and i < len(units) - 1:
        size /= 1024.0
        i += 1
    return f"{size:.2f} {units[i]}"

app.jinja_env.filters['binary_filesize'] = binary_filesize

main_template = '''
<!doctype html>
<title>File Share</title>
<h1>Welcome</h1>
<p><a href="{{ url_for('user_folder', username=session['username']) }}">Go to My Files</a></p>
<p><a href="/logout">Logout</a>{% if is_admin %} | <a href="/admin">Admin</a>{% endif %}</p>
'''

@app.route('/')
@with_expiry_cleanup
def main():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template_string(main_template, is_admin=is_admin())

# User folder page: list files, allow upload/delete if owner
user_folder_template = '''
<!doctype html>
<title>Files for {{ username }}</title>
<h1>Files for {{ username }}</h1>
<script>
var MAX_UPLOAD_SIZE = {{ max_upload_size }};
var USER_QUOTA = {{ user_quota }};
var USER_USED = {{ user_used }};
</script>
<div style="width:60%;margin:10px auto 20px auto;">
  <div style="text-align:left;">Storage used: {{ user_used|binary_filesize }} / {{ user_quota|binary_filesize }} ({{ (100*user_used/user_quota)|round(1) }}%)</div>
  <div style="background:#eee;border:1px solid #aaa;height:22px;width:100%;border-radius:6px;overflow:hidden;">
    <div style="background:#4caf50;height:100%;width:{{ (100*user_used/user_quota)|round(1) }}%;color:white;text-align:center;line-height:22px;">{{ (100*user_used/user_quota)|round(1) }}%</div>
  </div>
</div>
{% if can_upload %}
<form id="uploadForm">
  <input type="file" id="fileInput" name="file">
  <label><input type="checkbox" id="temporary" name="temporary"> Temporary</label>
  <input type="number" id="expiry_seconds" name="expiry_seconds" min="0" placeholder="Seconds" style="width:70px;">
  <input type="number" id="expiry_minutes" name="expiry_minutes" min="0" placeholder="Minutes" style="width:70px;">
  <input type="number" id="expiry_hours" name="expiry_hours" min="0" placeholder="Hours" style="width:70px;">
  <input type="number" id="expiry_days" name="expiry_days" min="0" placeholder="Days" style="width:70px;">
  <input type="number" id="expiry_weeks" name="expiry_weeks" min="0" placeholder="Weeks" style="width:70px;">
  <input type="number" id="expiry_months" name="expiry_months" min="0" placeholder="Months" style="width:70px;">
  <input type="number" id="expiry_years" name="expiry_years" min="0" placeholder="Years" style="width:70px;">
  <button type="button" onclick="uploadFile()">Upload</button>
</form>
<div class="progress-container" style="width:50%;margin:20px auto;display:none;">
  <div class="progress-bar" style="width:100%;background-color:#f3f3f3;border:1px solid #ccc;">
    <div id="progress" class="progress" style="height:20px;width:0%;background-color:#4caf50;text-align:center;color:white;line-height:20px;">0%</div>
  </div>
</div>
{% endif %}
<h2>Files</h2>
<ul>
  {% for file in files %}
    <li>
      {{ file['name'] }}
      ({{ file['size']|default(0)|binary_filesize }}, {{ file['download_count']|default(0, true) }} downloads)
      {% if file['temporary'] %} [Temporary]{% endif %}
      {% if file['expiry'] %} [Expires: {{ file['expiry'][:16].replace('T', ' ') }}]{% endif %}
      <span id="status-{{ file['file_id']|replace(':', '_')|replace(' ', '_') }}"></span>
      {% if can_upload %}
      <button type="button" onclick="copyLink('{{ file['file_id'] }}', '{{ file['name'] }}')">Generate New Link</button>
      {% endif %}
      {% if can_delete %}
        <form method="post" action="{{ url_for('delete_from_user', username=username, file_id=file['file_id']) }}" style="display:inline;">
          <button type="submit">Delete</button>
        </form>
      {% endif %}
    </li>
  {% endfor %}
</ul>
<p><a href="/">Back to User Folders</a></p>
<script>
  function uploadFile() {
      let fileInput = document.getElementById('fileInput');
      if (!fileInput.files.length) {
          alert("Please select a file.");
          return;
      }
      let file = fileInput.files[0];
      if (file.size > MAX_UPLOAD_SIZE) {
          alert("File is too large. Maximum allowed size is " + (MAX_UPLOAD_SIZE/1024/1024).toFixed(2) + " MB.");
          return;
      }
      if (file.size + USER_USED > USER_QUOTA) {
          alert("Uploading this file would exceed your quota. You have " + ((USER_QUOTA-USER_USED)/1024/1024).toFixed(2) + " MB left.");
          return;
      }
      let formData = new FormData();
      formData.append("file", file);
      let temporary = document.getElementById('temporary').checked;
      formData.append("temporary", temporary ? '1' : '0');
      let fields = ["seconds","minutes","hours","days","weeks","months","years"];
      for (let f of fields) {
        let v = document.getElementById('expiry_' + f).value;
        formData.append('expiry_' + f, v);
      }
      let xhr = new XMLHttpRequest();
      xhr.open("POST", window.location.pathname + "/upload", true);
      document.querySelector('.progress-container').style.display = "block";
      xhr.upload.onprogress = function(event) {
          if (event.lengthComputable) {
              let percentComplete = (event.loaded / event.total) * 100;
              let progressBar = document.getElementById('progress');
              progressBar.style.width = percentComplete + "%";
              progressBar.innerText = Math.round(percentComplete) + "%";
          }
      };
      xhr.onload = function() {
          if (xhr.status == 200) {
              try {
                  const data = JSON.parse(xhr.responseText);
                  // We no longer display direct links here by design
              } catch (e) {}
              // No immediate reload; allow user to copy the link first
          } else {
              alert("File upload failed.");
          }
      };
      xhr.send(formData);
  }

  function copyLink(fileId, displayName) {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', window.location.pathname + '/link/' + encodeURIComponent(fileId), true);
      xhr.responseType = 'json';
      xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      xhr.onload = function() {
          if (xhr.status === 200) {
              const data = xhr.response;
              if (data && data.link) {
                  const statusId = fileId.replace(/:/g, '_').replace(/\s/g, '_');
                  const status = document.getElementById('status-' + statusId);
                  const setStatus = function(msg) {
                      if (status) { status.textContent = ' ' + msg; } else { alert(msg); }
                  };
                  const copyViaClipboardAPI = function(text) {
                      if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
                          return navigator.clipboard.writeText(text);
                      }
                      return Promise.reject(new Error('Clipboard API unavailable'));
                  };
                  const copyViaExecCommand = function(text) {
                      try {
                          const textarea = document.createElement('textarea');
                          textarea.value = text;
                          textarea.setAttribute('readonly', '');
                          textarea.style.position = 'absolute';
                          textarea.style.left = '-9999px';
                          document.body.appendChild(textarea);
                          textarea.select();
                          const ok = document.execCommand('copy');
                          document.body.removeChild(textarea);
                          if (!ok) throw new Error('execCommand copy failed');
                          return true;
                      } catch (e) {
                          return false;
                      }
                  };
                  copyViaClipboardAPI(data.link)
                    .then(function() { setStatus('(link copied)'); })
                    .catch(function() {
                        const ok = copyViaExecCommand(data.link);
                        if (ok) {
                            setStatus('(link copied)');
                        } else {
                            // Final fallback: show prompt for manual copy
                            const manual = prompt('Copy this link:', data.link);
                            if (manual !== null) {
                                setStatus('(link shown)');
                            }
                        }
                    });
              } else {
                  alert('Failed to get link');
              }
          } else if (xhr.status === 403) {
              alert('Unauthorized');
          } else {
              alert('Failed to generate link');
          }
      };
      xhr.send('x=1');
  }
</script>
'''

def load_user_upload_limits():
    """Load all user upload limits from database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username, upload_limit_bytes FROM user_upload_limits')
    limits = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()
    return limits

def save_user_upload_limits(limits):
    """Save user upload limits to database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    for username, limit in limits.items():
        cursor.execute('''
            INSERT OR REPLACE INTO user_upload_limits (username, upload_limit_bytes)
            VALUES (?, ?)
        ''', (username, limit))
    conn.commit()
    conn.close()

def get_user_upload_limit(username):
    """Get user upload limit from database or return global max."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT upload_limit_bytes FROM user_upload_limits WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result and result[0] is not None:
        return result[0]
    return get_max_upload_size()

def set_user_upload_limit(username, limit):
    """Set user upload limit in database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO user_upload_limits (username, upload_limit_bytes)
        VALUES (?, ?)
    ''', (username, limit))
    conn.commit()
    conn.close()

@app.route('/user/<username>/folder_password', methods=['POST'])
def set_folder_password(username):
    return redirect(url_for('user_folder', username=username))

@app.route('/user/<username>/verify_password', methods=['POST'])
def verify_folder_password(username):
    return jsonify({"success": False})

@app.route('/user/<username>')
@with_expiry_cleanup
def user_folder(username):
    if 'username' not in session:
        return redirect(url_for('login'))
    users = load_users()
    if username not in users:
        flash('User not found.')
        return redirect(url_for('main'))
    folder = get_user_folder(username)
    if not os.path.exists(folder):
        os.makedirs(folder)
    if session['username'] != username:
        flash('Access denied.')
        return redirect(url_for('main'))
    stats = load_file_stats()
    file_list = []
    for file_id, meta in stats.items():
        if meta.get('uploader') == username:
            # Check if token exists to display link
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM download_tokens WHERE file_id = ?', (file_id,))
            has_tok = cursor.fetchone() is not None
            conn.close()
            file_list.append({'file_id': file_id, 'name': meta.get('filename'), 'has_token': '' if not has_tok else request.args.get('token_for_'+file_id, ''), **meta})
    can_upload = (session['username'] == username and username != "Anonymous")
    can_delete = can_upload
    max_upload_size = get_user_upload_limit(username)
    user_quota = get_user_quota(username, users[username][1])
    user_used = get_user_total_upload(username)
    folder_protected = False
    # Pull any recent token for display then clear it
    recent = session.get('recent_tokens', {})
    recent_for_user = recent.get(username, {})
    display_tokens = {}
    for item in file_list:
        file_id = item['file_id']
        if file_id in recent_for_user:
            display_tokens[file_id] = recent_for_user[file_id]
    if username in recent:
        recent.pop(username, None)
        session['recent_tokens'] = recent
    return render_template_string(user_folder_template, username=username, files=file_list, can_upload=can_upload, can_delete=can_delete, max_upload_size=max_upload_size, user_quota=user_quota, user_used=user_used, folder_protected=folder_protected, display_tokens=display_tokens)

@app.route('/user/<username>/upload', methods=['POST'])
@with_expiry_cleanup
def upload_to_user(username):
    if 'username' not in session or session['username'] != username:
        flash('You can only upload to your own folder.')
        return redirect(url_for('user_folder', username=username))
    if username == "Anonymous":
        flash("Anonymous users cannot upload files.")
        return redirect(url_for('user_folder', username=username))

    user = username
    users = load_users()
    priv = users.get(user, (None, PRIV_USER))[1]
    max_upload_size = get_user_upload_limit(user)
    user_quota = get_user_quota(user, priv)
    user_total = get_user_total_upload(user)
    if 'file' not in request.files:
        flash('No file part in the request.')
        return redirect(url_for('user_folder', username=username))
    file = request.files['file']
    if file.filename == '':
        flash('No file selected.')
        return redirect(url_for('user_folder', username=username))
    if file:
        filename = secure_filename(file.filename)
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        if size > max_upload_size:
            flash(f'File exceeds max upload size ({max_upload_size // (1024*1024)} MB).')
            return redirect(url_for('user_folder', username=username))
        if user_total + size > user_quota:
            flash(f'Uploading this file would exceed your quota ({user_quota // (1024*1024)} MB).')
            return redirect(url_for('user_folder', username=username))
        temporary = request.form.get('temporary') == '1'
        # Read all expiry fields
        expiry_seconds = int(request.form.get('expiry_seconds', 0) or 0)
        expiry_minutes = int(request.form.get('expiry_minutes', 0) or 0)
        expiry_hours = int(request.form.get('expiry_hours', 0) or 0)
        expiry_days = int(request.form.get('expiry_days', 0) or 0)
        expiry_weeks = int(request.form.get('expiry_weeks', 0) or 0)
        expiry_months = int(request.form.get('expiry_months', 0) or 0)
        expiry_years = int(request.form.get('expiry_years', 0) or 0)
        expiry = None
        if temporary and (expiry_seconds or expiry_minutes or expiry_hours or expiry_days or expiry_weeks or expiry_months or expiry_years):
            now = datetime.datetime.now()
            delta = datetime.timedelta(
                seconds=expiry_seconds,
                minutes=expiry_minutes,
                hours=expiry_hours,
                days=expiry_days + expiry_weeks*7 + expiry_months*30 + expiry_years*365
            )
            expiry = (now + delta).isoformat()
        # Save temporarily to plaintext path for encryption stage
        plaintext_path = os.path.join(get_user_folder(username), filename)
        file.save(plaintext_path)
        file_id = make_file_id(user, filename)
        add_file_metadata(file_id, filename, user, size, expiry=expiry, temporary=temporary, unlisted=False)
        log_file_event('upload', filename, user, request.remote_addr, {'size': size, 'temporary': temporary, 'expiry': expiry})
        token_value = ensure_download_token(user, filename, file_id)
        # Stash token in session for owner convenience
        try:
            recent = session.get('recent_tokens', {})
            user_tokens = recent.get(user, {})
            user_tokens[file_id] = token_value
            recent[user] = user_tokens
            session['recent_tokens'] = recent
        except Exception:
            pass
        if temporary and expiry:
            schedule_file_expiry(file_id, user, filename, expiry)
        return jsonify({'message': f'File "{filename}" successfully uploaded.', 'token': token_value, 'link': url_for('download_token', token=token_value, _external=True)})

@app.route('/user/<username>/download/<filename>')
@with_expiry_cleanup
def download_from_user(username, filename):
    if 'username' not in session or session['username'] != username:
        return "Not found", 404
    file_id = make_file_id(username, filename)
    # Owner direct download: decrypt via token record
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT nonce, blob_path FROM download_tokens WHERE file_id = ?', (file_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return "Not found", 404
    return "Not found", 404

@app.route('/user/<username>/delete/<path:file_id>', methods=['POST'])
@with_expiry_cleanup
def delete_from_user(username, file_id):
    if 'username' not in session or (session['username'] != username and not is_admin()):
        flash('You do not have permission to delete this file.')
        return redirect(url_for('user_folder', username=username))
    folder = get_user_folder(username)
    stats = load_file_stats()
    meta = stats.get(file_id)
    if not meta:
        flash('File not found.')
        return redirect(url_for('user_folder', username=username))
    filename = meta.get('filename')
    try:
        # Remove blob file if exists
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT blob_path FROM download_tokens WHERE file_id = ?', (file_id,))
        row = cursor.fetchone()
        conn.close()
        if row and row[0] and os.path.exists(row[0]):
            try:
                os.remove(row[0])
            except Exception:
                pass
        # Remove any plaintext remnants
        candidate_plain = os.path.join(folder, filename)
        if os.path.exists(candidate_plain):
            os.remove(candidate_plain)
        remove_file_metadata(file_id)
        log_file_event('delete', filename, session['username'], request.remote_addr)
        flash('File deleted.')
    except Exception as e:
        flash(f'Error deleting file: {e}')
    return redirect(url_for('user_folder', username=username))

@app.route('/user/<username>/link/<path:file_id>', methods=['POST'])
def generate_link(username, file_id):
    if 'username' not in session or session['username'] != username:
        return jsonify({'error': 'Unauthorized'}), 403
    # Ensure file belongs to user
    stats = load_file_stats()
    meta = stats.get(file_id)
    if not meta or meta.get('uploader') != username:
        return jsonify({'error': 'Not found'}), 404
    filename = meta.get('filename')
    token_value = regenerate_download_token(username, filename, file_id)
    return jsonify({'token': token_value, 'link': url_for('download_token', token=token_value, _external=True)})

@app.route('/d/<token>')
@with_expiry_cleanup
def download_token(token):
    rec = get_token_record(token)
    if not rec or not rec['meta']:
        return "Not found", 404
    filename = rec['filename']
    uploader = rec['meta'].get('uploader')
    if not uploader:
        return "Not found", 404
    dl_template = '''
    <!doctype html>
    <title>Download {{ filename }}</title>
    <div style="max-width:720px;margin:30px auto;font-family:Arial, sans-serif;">
      <h2 style="margin-bottom:8px;">Download request</h2>
      <div style="margin-bottom:16px;color:#555;">You are requesting to download the file:</div>
      <div style="font-size:18px;font-weight:bold;margin-bottom:24px;">{{ filename }}</div>

      <div style="padding:16px;border:1px solid #ddd;border-radius:6px;margin-bottom:24px;background:#fafafa;">
        <h3 style="margin-top:0;margin-bottom:12px;">Download</h3>
        <div style="margin-bottom:12px;color:#555;">Click the button below to start the download.</div>
        <form method="post" action="{{ url_for('download_token_post', token=token) }}">
          <button type="submit" style="padding:10px 18px;font-size:14px;">Download</button>
        </form>
      </div>

      <hr style="border:none;border-top:1px solid #e0e0e0;margin:24px 0;">

      <div style="padding:16px;border:1px solid #ffd6d6;border-radius:6px;background:#fff8f8;">
        <h3 style="margin-top:0;margin-bottom:12px;">Report this file</h3>
        <div style="margin-bottom:12px;color:#555;">If this file is harmful or inappropriate, select a reason and optionally provide details, then submit a report.</div>
        <form method="post" action="{{ url_for('report_token_post', token=token) }}">
          <label for="reason" style="display:block;margin-bottom:6px;">Reason</label>
          <select id="reason" name="reason" style="min-width:240px;margin-bottom:12px;">
            <option value="malware">Malware</option>
            <option value="copyright">Copyright infringement</option>
            <option value="personal">Personal data / Doxxing</option>
            <option value="illegal">Illegal content</option>
            <option value="other">Other</option>
          </select>
          <label for="details" style="display:block;margin-bottom:6px;">Details (optional)</label>
          <input id="details" type="text" name="details" placeholder="Additional context" style="width:100%;max-width:100%;box-sizing:border-box;margin-bottom:12px;">
          <button type="submit" style="padding:8px 14px;font-size:13px;">Submit report</button>
        </form>
      </div>
    </div>
    '''
    return render_template_string(dl_template, filename=filename, token=token)

@app.route('/d/<token>', methods=['POST'])
@with_expiry_cleanup
def download_token_post(token):
    rec = get_token_record(token)
    if not rec or not rec['meta']:
        return "Not found", 404
    file_id = rec['file_id']
    filename = rec['filename']
    uploader = rec['meta'].get('uploader')
    if not uploader:
        return "Not found", 404
    nonce, blob_path = rec['nonce_blob']
    try:
        wrapped = rec.get('wrapped_key')
        if not wrapped:
            return "Not found", 404
        wrap_nonce = wrapped[:12]
        wrapped_key_ct = wrapped[12:]
        wrapper = AESGCM(MASTER_KEY)
        file_key = wrapper.decrypt(wrap_nonce, wrapped_key_ct, None)
        aesgcm = AESGCM(file_key)
        with open(blob_path, 'rb') as bf:
            ciphertext = bf.read()
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        return "Not found", 404
    increment_download_count(file_id)
    user_for_logging = session.get('username', 'Anonymous')
    log_file_event('download', filename, user_for_logging, request.remote_addr)
    return app.response_class(plaintext, mimetype='application/octet-stream', headers={
        'Content-Disposition': f'attachment; filename="{filename}"'
    })

@app.route('/d/<token>/report', methods=['POST'])
def report_token_post(token):
    rec = get_token_record(token)
    if not rec or not rec['meta']:
        return "Not found", 404
    file_id = rec['file_id']
    reason = request.form.get('reason', 'other')
    details = request.form.get('details', '')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    conn = get_db_connection()
    cursor = conn.cursor()
    # Enforce one open report per IP per file
    cursor.execute('SELECT 1 FROM reports WHERE file_id = ? AND reporter_ip = ? AND status = "open"', (file_id, ip))
    exists = cursor.fetchone()
    if not exists:
        cursor.execute('INSERT INTO reports (file_id, token_hash, reporter_ip, reason, details, created) VALUES (?, ?, ?, ?, ?, ?)', (
            file_id, _hash_token(token), ip, reason, details, datetime.datetime.now().isoformat()
        ))
        conn.commit()
    conn.close()
    return 'Report submitted. Thank you.', 200

def load_file_stats():
    """Load all file stats from database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT file_id, filename, uploader, upload_time, size, download_count, expiry, temporary, unlisted
        FROM file_stats
    ''')
    stats = {}
    for row in cursor.fetchall():
        stats[row[0]] = {
            'filename': row[1],
            'uploader': row[2],
            'upload_time': row[3],
            'size': row[4],
            'download_count': row[5],
            'expiry': row[6],
            'temporary': bool(row[7]),
            'unlisted': bool(row[8])
        }
    conn.close()
    return stats

def save_file_stats(stats):
    """Save file stats to database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # Clear existing stats and insert new ones
    cursor.execute('DELETE FROM file_stats')
    for file_id, meta in stats.items():
        cursor.execute('''
            INSERT INTO file_stats (file_id, filename, uploader, upload_time, size, download_count, expiry, temporary, unlisted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            file_id,
            meta['filename'],
            meta['uploader'],
            meta['upload_time'],
            meta['size'],
            meta.get('download_count', 0),
            meta.get('expiry'),
            meta.get('temporary', False),
            meta.get('unlisted', False)
        ))
    conn.commit()
    conn.close()

def load_user_quotas():
    """Load all user quotas from database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username, quota_bytes FROM user_quotas')
    quotas = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()
    return quotas

def save_user_quotas(quotas):
    """Save user quotas to database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    for username, quota in quotas.items():
        cursor.execute('''
            INSERT OR REPLACE INTO user_quotas (username, quota_bytes)
            VALUES (?, ?)
        ''', (username, quota))
    conn.commit()
    conn.close()

def get_max_upload_size():
    """Get the global max upload size from database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT max_size_bytes FROM max_upload_size WHERE id = 1')
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else DEFAULT_MAX_UPLOAD_SIZE

def get_user_quota(username, priv=None):
    """Get user quota from database or return default based on privilege."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT quota_bytes FROM user_quotas WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return result[0]
    
    if priv is None:
        users = load_users()
        priv = int(users.get(username, (None, PRIV_USER))[1])
    
    if priv == PRIV_SUPERUSER:
        return DEFAULT_SUPERUSER_QUOTA
    elif priv == PRIV_ADMIN:
        return DEFAULT_ADMIN_QUOTA
    else:
        return DEFAULT_USER_QUOTA

def set_user_quota(username, quota):
    """Set user quota in database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO user_quotas (username, quota_bytes)
        VALUES (?, ?)
    ''', (username, quota))
    conn.commit()
    conn.close()

def get_user_total_upload(username):
    stats = load_file_stats()
    total = 0
    for meta in stats.values():
        if meta.get('uploader') == username:
            total += meta.get('size', 0)
    return total

def add_file_metadata(file_id, filename, uploader, size, expiry=None, temporary=False, unlisted=False):
    """Add file metadata to database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO file_stats (file_id, filename, uploader, upload_time, size, download_count, expiry, temporary, unlisted)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        file_id,
        filename,
        uploader,
        datetime.datetime.now().isoformat(),
        size,
        0,
        expiry,
        temporary,
        unlisted
    ))
    conn.commit()
    conn.close()

def increment_download_count(file_id):
    """Increment download count for a file."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE file_stats 
        SET download_count = download_count + 1 
        WHERE file_id = ?
    ''', (file_id,))
    conn.commit()
    conn.close()

def _token_key_from_token(token_value):
    # Derive a 256-bit key from the token using SHA-256
    return hashlib.sha256(token_value.encode('utf-8')).digest()

def _hash_token(token_value):
    return hashlib.sha256(('hash:' + token_value).encode('utf-8')).hexdigest()

def ensure_download_token(uploader, filename, file_id):
    """Ensure a stable download token exists for a file and return it."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT token_hash FROM download_tokens WHERE file_id = ?', (file_id,))
    row = cursor.fetchone()
    if row and row[0]:
        conn.close()
        return 'exists'
    # Generate token
    token_value = secrets.token_urlsafe(24)
    # Generate a per-file key and wrap it with MASTER_KEY
    file_key = os.urandom(32)
    wrap_nonce = os.urandom(12)
    wrapper = AESGCM(MASTER_KEY)
    wrapped_key = wrapper.encrypt(wrap_nonce, file_key, None)
    # Use a different nonce for file encryption
    nonce = os.urandom(12)
    aesgcm = AESGCM(file_key)
    # Read plaintext from user's folder
    plaintext_path = os.path.join(get_user_folder(uploader), filename)
    with open(plaintext_path, 'rb') as pf:
        plaintext = pf.read()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    # Write blob
    blob_id = secrets.token_hex(16)
    blob_path = os.path.join(BLOB_FOLDER, blob_id)
    with open(blob_path, 'wb') as bf:
        bf.write(ciphertext)
    # Remove plaintext from uploads
    try:
        os.remove(plaintext_path)
    except Exception:
        pass
    # Store token hash and blob metadata
    cursor.execute('INSERT OR REPLACE INTO download_tokens (file_id, token_hash, nonce, blob_path, wrapped_key, created) VALUES (?, ?, ?, ?, ?, ?)', (
        file_id, _hash_token(token_value), nonce, blob_path, wrap_nonce + wrapped_key, datetime.datetime.now().isoformat()
    ))
    conn.commit()
    conn.close()
    return token_value

def regenerate_download_token(uploader, filename, file_id):
    """Generate a new token for an existing file."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT nonce, blob_path FROM download_tokens WHERE file_id = ?', (file_id,))
    row = cursor.fetchone()
    # If missing, perform initial encryption
    if not row:
        conn.close()
        return ensure_download_token(uploader, filename, file_id)
    nonce, blob_path = row
    token_value = secrets.token_urlsafe(24)
    cursor.execute('UPDATE download_tokens SET token_hash = ?, created = ? WHERE file_id = ?', (
        _hash_token(token_value), datetime.datetime.now().isoformat(), file_id
    ))
    conn.commit()
    conn.close()
    return token_value

def get_token_record(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT file_id, nonce, blob_path, wrapped_key FROM download_tokens WHERE token_hash = ?', (_hash_token(token),))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    file_id = row[0]
    stats = load_file_stats()
    meta = stats.get(file_id)
    if not meta:
        return None
    filename = meta.get('filename')
    return {'file_id': file_id, 'filename': filename, 'meta': meta, 'nonce_blob': (row[1], row[2]), 'wrapped_key': row[3]}

def remove_file_metadata(file_id):
    """Remove file metadata from database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM file_stats WHERE file_id = ?', (file_id,))
    cursor.execute('DELETE FROM download_tokens WHERE file_id = ?', (file_id,))
    conn.commit()
    conn.close()

expiry_timers = {}

def schedule_file_expiry(file_id, uploader, filename, expiry_iso):
    try:
        expiry_time = datetime.datetime.fromisoformat(expiry_iso)
        now = datetime.datetime.now()
        seconds = (expiry_time - now).total_seconds()
        if seconds <= 0:
            # Already expired, delete immediately
            folder = get_user_folder(uploader)
            try:
                os.remove(os.path.join(folder, filename))
            except Exception:
                pass
            remove_file_metadata(file_id)
            log_file_event('expired_delete', filename, 'system', 'localhost')
            return
        def delete_file_at_expiry():
            folder = get_user_folder(uploader)
            try:
                os.remove(os.path.join(folder, filename))
            except Exception:
                pass
            remove_file_metadata(file_id)
            log_file_event('expired_delete', filename, 'system', 'localhost')
        timer = threading.Timer(seconds, delete_file_at_expiry)
        timer.daemon = True
        timer.start()
        expiry_timers[file_id] = timer
    except Exception:
        pass

def reschedule_all_expiry_timers():
    stats = load_file_stats()
    for file_id, meta in stats.items():
        if meta.get('temporary') and meta.get('expiry') and meta.get('uploader'):
            schedule_file_expiry(file_id, meta['uploader'], meta['filename'], meta['expiry'])

admin_template = '''
<!doctype html>
<title>Admin Controls</title>
<h2>Admin Controls</h2>
<form method="post" action="{{ url_for('admin') }}">
  <h3>Set Global Max Upload Size (MB)</h3>
  <input type="number" name="max_upload_size" min="1" value="{{ max_upload_size // (1024*1024) }}">
  <button type="submit" name="action" value="set_max_upload_size">Update</button>
</form>

<h3>User Quotas & Upload Limits (MB)</h3>
<form method="post" action="{{ url_for('admin') }}">
  <table border="1" style="margin:auto;">
    <tr><th>Username</th><th>Current Quota</th><th>Set New Quota</th><th>Current Upload Limit</th><th>Set New Upload Limit</th></tr>
    {% for user in user_quotas.keys() %}
      <tr>
        <td>{{ user }}</td>
        <td>{{ user_quotas[user] // (1024*1024) }}</td>
        <td><input type="number" name="quota_{{ user }}" min="1"></td>
        <td>
          {% if user_upload_limits[user] is not none %}
            {{ user_upload_limits[user] // (1024*1024) }}
          {% else %}
            {{ max_upload_size // (1024*1024) }} (global)
          {% endif %}
        </td>
        <td><input type="number" name="upload_limit_{{ user }}" min="1" placeholder="(blank=global)"></td>
      </tr>
    {% endfor %}
  </table>
  <button type="submit" name="action" value="set_quotas">Update Quotas & Upload Limits</button>
</form>

<h3>User Management</h3>
<table border="1" style="margin:auto;">
  <tr><th>Username</th><th>Privilege</th><th>Change Password</th><th>Promote/Demote</th><th>Delete User</th></tr>
  {% for user in users.keys() %}
    <tr>
      <td>{{ user }}</td>
      <td>{{ users[user][1] }}</td>
      <td>
        <form method="post" action="{{ url_for('admin') }}" style="display:inline;">
          <input type="hidden" name="action" value="change_password">
          <input type="hidden" name="target_user" value="{{ user }}">
          <input type="password" name="new_password" placeholder="New password">
          <button type="submit">Set</button>
        </form>
      </td>
      <td>
        {% if is_superuser %}
          <form method="post" action="{{ url_for('admin') }}" style="display:inline;">
            <input type="hidden" name="target_user" value="{{ user }}">
            {% if users[user][1] == '0' %}
              <input type="hidden" name="action" value="promote">
              <button type="submit">Promote to Admin</button>
            {% elif users[user][1] == '1' %}
              <input type="hidden" name="action" value="demote">
              <button type="submit">Demote to User</button>
            {% else %}
              Superuser
            {% endif %}
          </form>
        {% else %}
          {% if users[user][1] == '2' %}
            Superuser
          {% else %}
            (No permission)
          {% endif %}
        {% endif %}
      </td>
      <td>
        <form method="post" action="{{ url_for('admin') }}" style="display:inline;" onsubmit="return confirm('Delete user {{ user }} and all their files?');">
          <input type="hidden" name="action" value="delete_user">
          <input type="hidden" name="target_user" value="{{ user }}">
          <button type="submit">Delete</button>
        </form>
      </td>
    </tr>
  {% endfor %}
</table>

<h3>Ban / Unban IPs</h3>
<form method="post" action="{{ url_for('admin') }}">
  <input type="text" name="target_ip" placeholder="IP address">
  <button type="submit" name="action" value="ban_ip">Ban IP</button>
  <button type="submit" name="action" value="unban_ip">Unban IP</button>
</form>

<p><a href="/">Back to File List</a></p>
'''

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not is_admin():
        flash('Admin access required.')
        return redirect(url_for('main'))
    max_upload_size = get_max_upload_size()
    user_quotas = load_user_quotas()
    user_upload_limits = load_user_upload_limits()
    users = load_users()
    # Add all users to quotas dict if missing
    for u in users:
        if u not in user_quotas:
            user_quotas[u] = get_user_quota(u, users[u][1])
        if u not in user_upload_limits:
            user_upload_limits[u] = None
    # Fetch aggregated open reports by file_id
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT file_id, COUNT(*) as cnt FROM reports WHERE status = "open" GROUP BY file_id ORDER BY cnt DESC')
    report_rows = cursor.fetchall()
    # For details per file, collect distinct reporter IPs and last reason/details
    stats = load_file_stats()
    aggregated = []
    for r in report_rows:
        file_id, cnt = r
        meta = stats.get(file_id)
        if not meta:
            continue
        fname = meta.get('filename', 'unknown')
        uploader = meta.get('uploader', 'unknown')
        cursor.execute('SELECT reporter_ip FROM reports WHERE file_id = ? AND status = "open" GROUP BY reporter_ip', (file_id,))
        ips = [row[0] for row in cursor.fetchall()]
        cursor.execute('SELECT reason, details, created FROM reports WHERE file_id = ? AND status = "open" ORDER BY created DESC LIMIT 1', (file_id,))
        last = cursor.fetchone() or ('', '', '')
        aggregated.append((file_id, fname, uploader, cnt, ips, last[0], last[1]))
    conn.close()

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'set_max_upload_size':
            try:
                new_size = int(request.form.get('max_upload_size')) * 1024 * 1024
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('UPDATE max_upload_size SET max_size_bytes = ? WHERE id = 1', (new_size,))
                conn.commit()
                conn.close()
                flash('Max upload size updated.')
            except Exception as e:
                flash(f'Error updating max upload size: {e}')
        elif action == 'set_quotas':
            for u in users:
                qval = request.form.get(f'quota_{u}')
                if qval:
                    try:
                        user_quotas[u] = int(qval) * 1024 * 1024
                    except Exception:
                        pass
                ulval = request.form.get(f'upload_limit_{u}')
                if ulval:
                    try:
                        user_upload_limits[u] = int(ulval) * 1024 * 1024
                    except Exception:
                        pass
            save_user_quotas(user_quotas)
            save_user_upload_limits(user_upload_limits)
            flash('User quotas and upload limits updated.')
        elif action == 'change_password':
            target_user = request.form.get('target_user')
            new_password = request.form.get('new_password')
            if target_user and new_password:
                pw_hash = generate_password_hash(new_password)
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET password_hash = ? WHERE username = ?', (pw_hash, target_user))
                conn.commit()
                conn.close()
                flash(f'Password for {target_user} updated.')
        elif action == 'ban_ip':
            target_ip = request.form.get('target_ip')
            if target_ip:
                ban_ip(target_ip)
                flash(f'IP {target_ip} has been banned.')
        elif action == 'unban_ip':
            target_ip = request.form.get('target_ip')
            if target_ip:
                unban_ip(target_ip)
                flash(f'IP {target_ip} has been unbanned.')
        elif action == 'delete_user':
            target_user = request.form.get('target_user')
            if target_user:
                # Remove from database
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('DELETE FROM users WHERE username = ?', (target_user,))
                cursor.execute('DELETE FROM user_quotas WHERE username = ?', (target_user,))
                cursor.execute('DELETE FROM user_upload_limits WHERE username = ?', (target_user,))
                cursor.execute('DELETE FROM user_folder_passwords WHERE username = ?', (target_user,))
                conn.commit()
                conn.close()
                # Remove user folder and files
                folder = get_user_folder(target_user)
                if os.path.exists(folder):
                    for fname in os.listdir(folder):
                        try:
                            os.remove(os.path.join(folder, fname))
                        except Exception:
                            pass
                    try:
                        os.rmdir(folder)
                    except Exception:
                        pass
                # Remove file metadata for their files
                stats = load_file_stats()
                to_remove = [file_id for file_id, meta in stats.items() if meta.get('uploader') == target_user]
                for file_id in to_remove:
                    remove_file_metadata(file_id)
                flash(f'User {target_user} and their files deleted.')
                return redirect(url_for('admin'))
            else:
                flash('Missing target user.')
        elif action == 'promote':
            if not is_superuser():
                flash('Only superusers can promote admins.')
            else:
                target_user = request.form.get('target_user')
                if target_user:
                    # Promote to admin
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute('UPDATE users SET privilege_level = ? WHERE username = ?', (PRIV_ADMIN, target_user))
                    conn.commit()
                    conn.close()
                    flash(f'User {target_user} promoted to admin.')
                    return redirect(url_for('admin'))
        
        elif action == 'demote':
            if not is_superuser():
                flash('Only superusers can demote admins.')
            else:
                target_user = request.form.get('target_user')
                if target_user:
                    # Demote to user
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute('UPDATE users SET privilege_level = ? WHERE username = ?', (PRIV_USER, target_user))
                    conn.commit()
                    conn.close()
                    flash(f'User {target_user} demoted to user.')
                    return redirect(url_for('admin'))
        
        elif action == 'resolve_report':
            resolution = request.form.get('resolution', 'none')
            target_user = request.form.get('target_user')
            target_file_id = request.form.get('target_file_id')
            target_ip = request.form.get('target_ip', '')
            # Apply actions
            if resolution in ('ban_ip', 'ban_ip_delete') and target_ip:
                ban_ip(target_ip)
            if resolution in ('ban_user', 'ban_user_delete') and target_user:
                # Delete user entirely
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('DELETE FROM users WHERE username = ?', (target_user,))
                cursor.execute('DELETE FROM user_quotas WHERE username = ?', (target_user,))
                cursor.execute('DELETE FROM user_upload_limits WHERE username = ?', (target_user,))
                cursor.execute('DELETE FROM user_folder_passwords WHERE username = ?', (target_user,))
                conn.commit()
                conn.close()
            if resolution in ('delete_file', 'ban_ip_delete', 'ban_user_delete') and target_user and target_file_id:
                # Remove file and metadata
                folder = get_user_folder(target_user)
                meta = stats.get(target_file_id)
                if meta:
                    filename = meta.get('filename')
                    try:
                        # blob
                        conn = get_db_connection()
                        cursor = conn.cursor()
                        cursor.execute('SELECT blob_path FROM download_tokens WHERE file_id = ?', (target_file_id,))
                        row = cursor.fetchone()
                        conn.close()
                        if row and row[0] and os.path.exists(row[0]):
                            try:
                                os.remove(row[0])
                            except Exception:
                                pass
                        if os.path.exists(os.path.join(folder, filename)):
                            os.remove(os.path.join(folder, filename))
                    except Exception:
                        pass
                    remove_file_metadata(target_file_id)
            # Mark all reports for this file resolved
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('UPDATE reports SET status = ?, resolved_by = ?, resolved_at = ? WHERE file_id = ? AND status = "open"', (
                'resolved', session.get('username', ''), datetime.datetime.now().isoformat(), target_file_id
            ))
            conn.commit()
            conn.close()
            flash('Report processed.')
        else:
            flash('Missing target user or new password.')
    # Render reports section
    reports_html = '<h3>Reports</h3><table border="1" style="margin:auto;"><tr><th>File ID</th><th>Filename</th><th>Uploader</th><th>Report Count</th><th>Reporter IPs</th><th>Last Reason</th><th>Last Details</th><th>View</th><th>Actions</th></tr>'
    for r in aggregated:
        file_id, fname, uploader, rcnt, rips, rreason, rdetails = r
        reports_html += f'<tr><td>{file_id}</td><td>{fname}</td><td>{uploader}</td><td>{rcnt}</td><td>{", ".join(rips)}</td><td>{rreason}</td><td>{rdetails or ""}</td>'
        reports_html += f'<td><a href="{url_for("admin_view_file", file_id=file_id)}" target="_blank">View</a></td><td>'
        reports_html += '<form method="post" action="' + url_for('admin') + '" style="display:inline;">'
        reports_html += '<input type="hidden" name="action" value="resolve_report">'
        reports_html += f'<input type="hidden" name="target_user" value="{uploader}">'
        reports_html += f'<input type="hidden" name="target_file_id" value="{file_id}">'
        reports_html += f'<input type="hidden" name="target_ip" value="{rips[0] if rips else ""}">'
        reports_html += '<select name="resolution">'
        reports_html += '<option value="none">Mark resolved (no action)</option>'
        reports_html += '<option value="delete_file">Delete file</option>'
        reports_html += '<option value="ban_ip">Ban IP</option>'
        reports_html += '<option value="ban_user">Ban user</option>'
        reports_html += '<option value="ban_ip_delete">Ban IP + Delete file</option>'
        reports_html += '<option value="ban_user_delete">Ban user + Delete file</option>'
        reports_html += '</select> '
        reports_html += '<button type="submit">Apply</button>'
        reports_html += '</form>'
        reports_html += '</td></tr>'
    reports_html += '</table>'

    return render_template_string(admin_template + reports_html, max_upload_size=max_upload_size, user_quotas=user_quotas, user_upload_limits=user_upload_limits, users=users, is_superuser=is_superuser())

@app.route('/admin/file/<path:file_id>')
def admin_view_file(file_id):
    if not is_admin():
        return "Admin access required", 403
    # Lookup encryption metadata
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT nonce, blob_path, wrapped_key FROM download_tokens WHERE file_id = ?', (file_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return "Not found", 404
    nonce, blob_path, wrapped = row
    stats = load_file_stats()
    meta = stats.get(file_id)
    if not meta:
        return "Not found", 404
    filename = meta.get('filename', 'unknown')
    try:
        if not wrapped:
            return "Not found", 404
        wrap_nonce = wrapped[:12]
        wrapped_key_ct = wrapped[12:]
        # Unwrap using MASTER_KEY (admin-only capability)
        wrapper = AESGCM(MASTER_KEY)
        file_key = wrapper.decrypt(wrap_nonce, wrapped_key_ct, None)
        aesgcm = AESGCM(file_key)
        with open(blob_path, 'rb') as bf:
            ciphertext = bf.read()
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        return "Not found", 404
    # Stream as download to the admin
    return app.response_class(plaintext, mimetype='application/octet-stream', headers={
        'Content-Disposition': f'attachment; filename="{filename}"'
    })

def start_expiry_cleanup_thread():
    def run():
        while True:
            try:
                cleanup_expired_files()
            except Exception:
                pass
            time.sleep(60)  # Run every 60 seconds
    t = threading.Thread(target=run, daemon=True)
    t.start()

# Migration function to add file_id to existing databases
def migrate_database():
    """Migrate old database schema to new file_id based schema."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if file_id column exists in file_stats
    cursor.execute("PRAGMA table_info(file_stats)")
    columns = [row[1] for row in cursor.fetchall()]
    
    if 'file_id' not in columns:
        print("Migrating database to support duplicate filenames...")
        
        # Create new tables with file_id
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_stats_new (
                file_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                uploader TEXT NOT NULL,
                upload_time TEXT NOT NULL,
                size INTEGER NOT NULL,
                download_count INTEGER NOT NULL DEFAULT 0,
                expiry TEXT,
                temporary BOOLEAN NOT NULL DEFAULT 0,
                unlisted BOOLEAN NOT NULL DEFAULT 0,
                FOREIGN KEY (uploader) REFERENCES users (username)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS download_tokens_new (
                file_id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                nonce BLOB NOT NULL,
                blob_path TEXT NOT NULL,
                wrapped_key BLOB,
                created TEXT NOT NULL,
                FOREIGN KEY (file_id) REFERENCES file_stats (file_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                reporter_ip TEXT NOT NULL,
                reason TEXT NOT NULL,
                details TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                created TEXT NOT NULL,
                resolved_by TEXT,
                resolved_at TEXT
            )
        ''')
        
        # Migrate data from old tables if they exist
        try:
            cursor.execute("SELECT filename, uploader, upload_time, size, download_count, expiry, temporary, unlisted FROM file_stats")
            old_files = cursor.fetchall()
            for row in old_files:
                filename, uploader, upload_time, size, download_count, expiry, temporary, unlisted = row
                file_id = make_file_id(uploader, filename)
                cursor.execute('''
                    INSERT OR IGNORE INTO file_stats_new 
                    (file_id, filename, uploader, upload_time, size, download_count, expiry, temporary, unlisted)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (file_id, filename, uploader, upload_time, size, download_count, expiry, temporary, unlisted))
        except Exception as e:
            print(f"Note: Could not migrate file_stats: {e}")
        
        try:
            cursor.execute("SELECT filename, token_hash, nonce, blob_path, wrapped_key, created FROM download_tokens")
            old_tokens = cursor.fetchall()
            # Need to get uploader from file_stats to create file_id
            for row in old_tokens:
                filename = row[0]
                cursor.execute("SELECT uploader FROM file_stats WHERE filename = ?", (filename,))
                uploader_row = cursor.fetchone()
                if uploader_row:
                    uploader = uploader_row[0]
                    file_id = make_file_id(uploader, filename)
                    cursor.execute('''
                        INSERT OR IGNORE INTO download_tokens_new 
                        (file_id, token_hash, nonce, blob_path, wrapped_key, created)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (file_id, row[1], row[2], row[3], row[4], row[5]))
        except Exception as e:
            print(f"Note: Could not migrate download_tokens: {e}")
        
        try:
            cursor.execute("SELECT filename, token_hash, reporter_ip, reason, details, status, created, resolved_by, resolved_at FROM reports")
            old_reports = cursor.fetchall()
            for row in old_reports:
                filename = row[0]
                cursor.execute("SELECT uploader FROM file_stats WHERE filename = ?", (filename,))
                uploader_row = cursor.fetchone()
                if uploader_row:
                    uploader = uploader_row[0]
                    file_id = make_file_id(uploader, filename)
                    cursor.execute('''
                        INSERT INTO reports_new 
                        (file_id, token_hash, reporter_ip, reason, details, status, created, resolved_by, resolved_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (file_id, row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8]))
        except Exception as e:
            print(f"Note: Could not migrate reports: {e}")
        
        # Drop old tables and rename new ones
        cursor.execute("DROP TABLE IF EXISTS file_stats")
        cursor.execute("DROP TABLE IF EXISTS download_tokens")
        cursor.execute("DROP TABLE IF EXISTS reports")
        
        cursor.execute("ALTER TABLE file_stats_new RENAME TO file_stats")
        cursor.execute("ALTER TABLE download_tokens_new RENAME TO download_tokens")
        cursor.execute("ALTER TABLE reports_new RENAME TO reports")
        
        conn.commit()
        print("Database migration completed successfully!")
    
    conn.close()

if __name__ == '__main__':
    migrate_database()
    reschedule_all_expiry_timers()
    start_expiry_cleanup_thread()
    app.run(host='0.0.0.0', port=5008, debug=True)