import os
import datetime
import logging
from flask import Flask, request, redirect, url_for, render_template_string, session, flash, jsonify, send_from_directory, get_flashed_messages
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import time

app = Flask(__name__)
app.secret_key = 'eS2MCmVxhg'

# ---------------------------
# Remove update logs from terminal output
class NoUpdatesFilter(logging.Filter):
    def filter(self, record):
        return '/updates' not in record.getMessage()

class NoUserUpdateFilter(logging.Filter):
    def filter(self, record):
        return 'active_updates' not in record.getMessage()

logging.getLogger('werkzeug').addFilter(NoUpdatesFilter())
logging.getLogger('werkzeug').addFilter(NoUserUpdateFilter())
# ---------------------------

# Global set to track active usernames
active_users = set()

# Global set to track already logged banned IPs (so we log each only once)
banned_ips_logged = set()

# Chat log file
CHAT_LOG = 'chat.log'

# Banned IPs file
BANNED_IPS_FILE = 'banned_ips.txt'

# Users file for storing credentials
USERS_FILE = 'users.txt'

# Private messages file
PRIVATE_MSG_FILE = 'private_messages.txt'

# Rate limiting: minimum seconds between messages
RATE_LIMIT_SECONDS = 2

# User privilege levels
PRIV_USER = '0'
PRIV_ADMIN = '1'
PRIV_SUPERUSER = '2'

# Track forced logouts in a set
forced_logout_users = set()

# Track banned users in a set for forced logout
banned_users = set()

FORCED_LOGOUT_FILE = 'forced_logout_users.txt'

def load_forced_logout_users():
    users = set()
    if os.path.exists(FORCED_LOGOUT_FILE):
        with open(FORCED_LOGOUT_FILE, 'r', encoding='utf-8') as f:
            users = set(line.strip() for line in f if line.strip())
    return users

def save_forced_logout_users(users):
    with open(FORCED_LOGOUT_FILE, 'w', encoding='utf-8') as f:
        for user in users:
            f.write(user + '\n')

def can_send_message():
    now = time.time()
    last_time = session.get('last_message_time', 0)
    if now - last_time < RATE_LIMIT_SECONDS:
        return False
    session['last_message_time'] = now
    return True

def check_session_password():
    if 'username' not in session or 'pw_hash' not in session:
        return False
    users = load_users()
    username = session['username']
    if username not in users:
        return False
    # If password hash in session does not match current hash, password was reset
    return session['pw_hash'] == users[username][0]

# Ensure the chat log file exists
if not os.path.exists(CHAT_LOG):
    with open(CHAT_LOG, 'a'):
        pass

# Ensure the banned IPs file exists
if not os.path.exists(BANNED_IPS_FILE):
    with open(BANNED_IPS_FILE, 'w'):
        pass

# Ensure the users file exists
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'a'):
        pass

# Ensure the private messages file exists
if not os.path.exists(PRIVATE_MSG_FILE):
    with open(PRIVATE_MSG_FILE, 'a'):
        pass

def load_banned_ips():
    """Load banned IP addresses from the banned_ips file."""
    with open(BANNED_IPS_FILE, 'r') as f:
        # Return a set of non-empty, stripped lines
        return set(line.strip() for line in f if line.strip())

def load_users():
    """Load users from the users file. Returns a dict {username: (password_hash, priv)}"""
    users = {}
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            if ':' in line:
                parts = line.strip().split(':')
                if len(parts) >= 3:
                    username = parts[0]
                    priv = parts[-1]
                    pw_hash = ':'.join(parts[1:-1])
                elif len(parts) == 2:
                    username, pw_hash = parts
                    priv = PRIV_USER  # default to user for legacy
                else:
                    continue
                users[username] = (pw_hash, priv)
    return users

def save_user(username, password, priv=PRIV_USER):
    """Save a new user with a hashed password and admin flag."""
    pw_hash = generate_password_hash(password)
    with open(USERS_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{username}:{pw_hash}:{priv}\n")

# Privilege checks
def is_superuser():
    users = load_users()
    if 'username' not in session:
        return False
    username = session['username']
    return username in users and users[username][1] == PRIV_SUPERUSER

def is_admin():
    users = load_users()
    if 'username' not in session:
        return False
    username = session['username']
    return username in users and users[username][1] in (PRIV_ADMIN, PRIV_SUPERUSER)

# Save a private message to the private messages file
def save_private_message(sender, recipient, message):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    entry = f"[{timestamp}] {sender} -> {recipient}: {message}"
    with open(PRIVATE_MSG_FILE, 'a', encoding='utf-8') as f:
        f.write(entry + "\n")

# Load all private messages between two users
def load_private_messages(user1, user2):
    messages = []
    with open(PRIVATE_MSG_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            if f"{user1} -> {user2}:" in line or f"{user2} -> {user1}:" in line:
                messages.append(line.strip())
    return messages

# Admin page template
admin_template = """
<!doctype html>
<title>Admin Controls</title>
<h2>Admin Controls</h2>
<ul>
  <li><form method='post' action='{{ url_for('ban_user') }}'>Ban user: <input name='ban_username'><input type='submit' value='Ban'></form></li>
  <li><form method='post' action='{{ url_for('unban_user') }}'>Unban user: <input name='unban_username'><input type='submit' value='Unban'></form></li>
  {% if is_superuser %}
    <li><form method='post' action='{{ url_for('force_logout_all') }}'><input type='submit' value='Force Logout All Users'></form></li>
    <li><form method='post' action='{{ url_for('unregister_all_users') }}' onsubmit="return confirm('Are you sure you want to unregister (delete) all users? This cannot be undone!');"><input type='submit' value='Unregister All Users'></form></li>
    <li><form method='post' action='{{ url_for('clear_chat') }}'><input type='submit' value='Clear Chat Log'></form></li>
    <li><form method='post' action='{{ url_for('clear_private_messages') }}'><input type='submit' value='Clear All Private Messages'></form></li>
    <li><form method='post' action='{{ url_for('promote_user') }}'>Promote to admin: <input name='promote_username'><input type='submit' value='Promote'></form></li>
    <li><form method='post' action='{{ url_for('demote_user') }}'>Demote from admin: <input name='demote_username'><input type='submit' value='Demote'></form></li>
  {% endif %}
  <li><form method='post' action='{{ url_for('unregister_user') }}'>Unregister user: <input name='unreg_username'><input type='submit' value='Unregister'></form></li>
  <li><form method='post' action='{{ url_for('logout_user') }}'>Log out user: <input name='logout_username'><input type='submit' value='Log Out'></form></li>
  <li><form method='post' action='{{ url_for('reset_password') }}'>Reset password for user: <input name='reset_username'><input type='password' name='new_password' placeholder='New Password'><input type='submit' value='Reset'></form></li>
  <li><a href='{{ url_for('view_private_messages') }}'>View All Private Messages</a></li>
  <li><a href='{{ url_for('download_log', logtype="chat") }}'>Download Chat Log</a></li>
  <li><a href='{{ url_for('download_log', logtype="private") }}'>Download Private Messages Log</a></li>
  <li><a href='{{ url_for('view_user_info') }}'>View User Registration Times</a></li>
</ul>
<p><a href='{{ url_for('chat') }}'>Back to Chat</a></p>
"""

# View all private messages template
view_private_template = """
<!doctype html>
<title>All Private Messages</title>
<h2>All Private Messages</h2>
<div style='border:1px solid #000; padding:10px; height:300px; overflow:auto;'>
{% for line in private_lines %}
  <p>{{ line }}</p>
{% endfor %}
</div>
<p><a href='{{ url_for('admin') }}'>Back to Admin</a></p>
"""

def load_banned_users():
    banned_usernames = set()
    if os.path.exists(BANNED_IPS_FILE):
        with open(BANNED_IPS_FILE, 'r', encoding='utf-8') as f:
            banned_usernames = set(line.strip() for line in f if line.strip())
    return banned_usernames

@app.before_request
def check_banned_ips():
    banned_ips = load_banned_ips()
    user_ip = request.remote_addr
    banned_usernames = load_banned_users()
    if user_ip in banned_ips or ('username' in session and session['username'] in banned_usernames):
        # Log the banned IP only once per server session
        if user_ip not in banned_ips_logged:
            app.logger.info(f"Blocked access from banned IP or banned user: {user_ip}")
            banned_ips_logged.add(user_ip)
        session.clear()
        # Redirect to login instead of forbidden for forced logout/unregister
        return redirect(url_for('login'))

@app.before_request
def check_forced_logout():
    global forced_logout_users, banned_users
    forced_logout_users = load_forced_logout_users()
    banned_users = load_banned_users()
    if 'username' in session:
        if session['username'] in forced_logout_users or session['username'] in banned_users:
            user = session['username']
            session.clear()
            forced_logout_users.discard(user)
            save_forced_logout_users(forced_logout_users)
            flash('You have been logged out by an admin or banned.')
            return redirect(url_for('login'))

# Serve favicon.ico
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.dirname(__file__), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

# Forbidden page template (optional since banned IPs now get a direct 403)
forbidden_template = """
<!doctype html>
<title>Forbidden</title>
<h1>403 Forbidden</h1>
<p>Your IP has been banned from accessing this service.</p>
"""

@app.route('/forbidden')
def forbidden():
    return render_template_string(forbidden_template), 403

# Login page template
login_template = """
<!doctype html>
<title>Login</title>
{% with messages = get_flashed_messages(with_categories=True) %}
  {% if messages %}
    <ul>
    {% for category, msg in messages %}
      {% if category != 'admin' %}
        <li>{{ msg }}</li>
      {% endif %}
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
<h2>Login to your account:</h2>
<form method="post" action="{{ url_for('login') }}">
  <input type="text" name="username" required placeholder="Username">
  <input type="password" name="password" required placeholder="Password">
  <input type="submit" value="Login">
</form>
<p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a></p>
"""

# Chat page template with AJAX polling for updates and conditional auto-scrolling
chat_template = """
<!doctype html>
<title>Chat Messenger</title>
<p>Logged in as: {{ username }} |
  <a href="{{ url_for('logout') }}">Logout</a> |
  <a href="{{ url_for('active') }}">View Active Users</a>
  {% if is_admin %}| <a href="{{ url_for('admin') }}">Admin Panel</a>{% endif %}
</p>
<div>
  <strong>Start Private Chat:</strong>
  <ul>
    {% for user in all_users %}
      {% if user != username %}
        <li><a href="{{ url_for('private_chat', recipient=user) }}">{{ user }}</a></li>
      {% endif %}
    {% endfor %}
  </ul>
</div>
<div id="chat" style="border: 1px solid #000; padding: 10px; height:300px; overflow:auto;">
  {% for line in chat_lines %}
    <p>{{ line }}</p>
  {% endfor %}
</div>
<br>
<form id="sendForm" method="post" action="{{ url_for('send') }}" onsubmit="return sendMessage();">
  <input type="text" id="message" name="message" required style="width:300px;">
  <input type="submit" value="Send">
</form>

<script>
  // Helper to check if user is selecting text inside the chat div
  function isSelectingInChat() {
    const chatDiv = document.getElementById("chat");
    const selection = window.getSelection();
    if (!selection || selection.isCollapsed) return false;
    if (!selection.anchorNode || !selection.focusNode) return false;
    // Check if selection is within chatDiv
    return chatDiv.contains(selection.anchorNode) && chatDiv.contains(selection.focusNode);
  }

  let lastChatLines = [];
  let chatInitialized = false;

  // Function to poll for new chat messages every 100ms
  function fetchUpdates() {
    fetch("{{ url_for('updates') }}")
      .then(response => {
          if (response.status === 403 || response.redirected) {
              window.location.href = "/forbidden";
              return;
          }
          return response.json();
      })
      .then(data => {
          if (!data) return;
          const chatDiv = document.getElementById("chat");
          if (isSelectingInChat()) return; // Don't update if user is selecting text
          // On first update, always clear and rebuild
          if (!chatInitialized) {
            chatDiv.innerHTML = "";
            data.lines.forEach(function(line) {
                const p = document.createElement("p");
                p.textContent = line;
                chatDiv.appendChild(p);
            });
            lastChatLines = data.lines.slice();
            chatInitialized = true;
          } else if (data.lines.length < lastChatLines.length) {
            chatDiv.innerHTML = "";
            data.lines.forEach(function(line) {
                const p = document.createElement("p");
                p.textContent = line;
                chatDiv.appendChild(p);
            });
            lastChatLines = data.lines.slice();
          } else if (data.lines.length > lastChatLines.length) {
            // Only append new lines
            for (let i = lastChatLines.length; i < data.lines.length; i++) {
                const p = document.createElement("p");
                p.textContent = data.lines[i];
                chatDiv.appendChild(p);
            }
            lastChatLines = data.lines.slice();
          }
          // If same length, do nothing
          // Auto-scroll if near bottom
          const isNearBottom = chatDiv.scrollTop + chatDiv.clientHeight >= chatDiv.scrollHeight - 50;
          if (isNearBottom) {
            chatDiv.scrollTop = chatDiv.scrollHeight;
          }
      });
  }
  setInterval(fetchUpdates, 100);
  
  function sendMessage() {
    const form = document.getElementById("sendForm");
    const formData = new FormData(form);
    fetch(form.action, {
      method: "POST",
      body: formData
    }).then(response => {
      if (response.status === 403 || response.redirected) {
          window.location.href = "/forbidden";
          return;
      }
      document.getElementById("message").value = "";
      return response.text();
    }).catch(error => {
      console.error("Error sending message:", error);
    });
    return false;
  }
</script>
"""

# Active users page template (for the server operator)
active_template = """
<!doctype html>
<title>Active Users</title>
<h2>Current Active Users</h2>
<ul id="activeUsers">
  {% for user in users %}
    <li>{{ user }}</li>
  {% endfor %}
</ul>
<p><a href="{{ url_for('chat') }}">Back to Chat</a></p>
<script>
  // Poll for active users every second
  function fetchActiveUsers() {
    fetch("{{ url_for('active_updates') }}")
      .then(response => response.json())
      .then(data => {
          const list = document.getElementById("activeUsers");
          list.innerHTML = "";
          data.users.forEach(function(user) {
              const li = document.createElement("li");
              li.textContent = user;
              list.appendChild(li);
          });
      });
  }
  setInterval(fetchActiveUsers, 1000);
</script>
"""

# Registration page template
registration_template = """
<!doctype html>
<title>Register</title>
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <ul>
    {% for msg in messages %}
      <li>{{ msg }}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
<h2>Register a new account:</h2>
<form method="post" action="{{ url_for('register') }}">
  <input type="text" name="username" required placeholder="Username">
  <input type="password" name="password" required placeholder="Password">
  <input type="submit" value="Register">
</form>
<p>Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
"""

# Private messaging page template
private_template = """
<!doctype html>
<title>Private Messages</title>
<h2>Private chat with {{ recipient }}</h2>
<div id="privateChat" style="border: 1px solid #000; padding: 10px; height:300px; overflow:auto;">
  {% for line in private_lines %}
    <p>{{ line }}</p>
  {% endfor %}
</div>
<br>
<form id="privateSendForm" method="post" action="{{ url_for('private_send', recipient=recipient) }}" onsubmit="return sendPrivateMessage();">
  <input type="text" id="private_message" name="message" required style="width:300px;">
  <input type="submit" value="Send">
</form>
<p><a href="{{ url_for('chat') }}">Back to Chat</a></p>
<script>
  function fetchPrivateUpdates() {
    fetch("{{ url_for('private_updates', recipient=recipient) }}")
      .then(response => response.json())
      .then(data => {
          const chatDiv = document.getElementById("privateChat");
          chatDiv.innerHTML = "";
          data.lines.forEach(function(line) {
              const p = document.createElement("p");
              p.textContent = line;
              chatDiv.appendChild(p);
          });
          chatDiv.scrollTop = chatDiv.scrollHeight;
      });
  }
  setInterval(fetchPrivateUpdates, 1000);
  function sendPrivateMessage() {
    const form = document.getElementById("privateSendForm");
    const formData = new FormData(form);
    fetch(form.action, {
      method: "POST",
      body: formData
    }).then(response => {
      document.getElementById("private_message").value = "";
      return response.text();
    });
    return false;
  }
</script>
"""

@app.route('/', methods=['GET'])
def index():
    if 'username' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

# Save registration time on new user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            flash("Username and password cannot be empty.")
            return redirect(url_for('register'))
        users = load_users()
        if username in users:
            flash("Username already exists. Please choose another.")
            return redirect(url_for('register'))
        save_user(username, password, priv=PRIV_USER)
        save_user_registration(username)
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
        if username in forced_logout_users:
            forced_logout_users.remove(username)
            save_forced_logout_users(forced_logout_users)
        if username in banned_users:
            flash("You are banned and cannot log in.")
            return redirect(url_for('login'))
        if any(user.lower() == username.lower() for user in active_users):
            flash("Username is already in use. Choose another one.")
            return redirect(url_for('login'))
        session['username'] = username
        session['pw_hash'] = users[username][0]
        active_users.add(username)
        return redirect(url_for('chat'))
    return render_template_string(login_template)

@app.route('/chat', methods=['GET'])
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    with open(CHAT_LOG, 'r', encoding='utf-8') as f:
        chat_lines = [line.strip() for line in f.readlines()]
    all_users = list(load_users().keys())
    return render_template_string(
        chat_template,
        username=session['username'],
        chat_lines=chat_lines,
        all_users=all_users,
        is_admin=is_admin()
    )

@app.route('/send', methods=['POST'])
def send():
    if 'username' not in session:
        return redirect(url_for('login'))
    if not check_session_password():
        user = session['username']
        session.clear()
        forced_logout_users = load_forced_logout_users()
        forced_logout_users.add(user)
        save_forced_logout_users(forced_logout_users)
        flash('Your password has changed. Please log in again.')
        return redirect(url_for('login'))
    if not can_send_message():
        flash(f"You are sending messages too quickly. Please wait {RATE_LIMIT_SECONDS} seconds between messages.")
        return jsonify({"status": "rate_limited"}), 429
    message = request.form.get('message').strip()
    if message:
        username = session['username']
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {username}: {message}"
        with open(CHAT_LOG, 'a', encoding='utf-8') as f:
            f.write(log_entry + "\n")
        print(log_entry)
    return jsonify({"status": "success"})

@app.route('/updates', methods=['GET'])
def updates():
    with open(CHAT_LOG, 'r', encoding='utf-8') as f:
        chat_lines = [line.strip() for line in f.readlines()]
    return jsonify({"lines": chat_lines})

@app.route('/active', methods=['GET'])
def active():
    # Show all registered users, not just active_users
    return render_template_string(active_template, users=list(load_users().keys()))

@app.route('/active_updates', methods=['GET'])
def active_updates():
    # Return all registered users as JSON
    return jsonify({"users": list(load_users().keys())})

@app.route('/logout', methods=['GET'])
def logout():
    if 'username' in session:
        active_users.discard(session['username'])
        forced_logout_users.discard(session['username'])
        session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/private/<recipient>', methods=['GET'])
def private_chat(recipient):
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    if recipient == username:
        flash("You cannot private message yourself.")
        return redirect(url_for('chat'))
    private_lines = load_private_messages(username, recipient)
    return render_template_string(private_template, recipient=recipient, private_lines=private_lines)

@app.route('/private_send/<recipient>', methods=['POST'])
def private_send(recipient):
    if 'username' not in session:
        return redirect(url_for('login'))
    if not check_session_password():
        user = session['username']
        session.clear()
        forced_logout_users = load_forced_logout_users()
        forced_logout_users.add(user)
        save_forced_logout_users(forced_logout_users)
        flash('Your password has changed. Please log in again.')
        return redirect(url_for('login'))
    if not can_send_message():
        flash(f"You are sending messages too quickly. Please wait {RATE_LIMIT_SECONDS} seconds between messages.")
        return jsonify({"status": "rate_limited"}), 429
    username = session['username']
    message = request.form.get('message', '').strip()
    if message:
        save_private_message(username, recipient, message)
    return jsonify({"status": "success"})

@app.route('/private_updates/<recipient>', methods=['GET'])
def private_updates(recipient):
    if 'username' not in session:
        return jsonify({"lines": []})
    username = session['username']
    private_lines = load_private_messages(username, recipient)
    return jsonify({"lines": private_lines})

@app.route('/admin', methods=['GET'])
def admin():
    if not is_admin():
        flash('Admin access required.')
        return redirect(url_for('chat'))
    return render_template_string(admin_template, is_superuser=is_superuser())

@app.route('/ban_user', methods=['POST'])
def ban_user():
    if not is_admin():
        flash('Admin access required.')
        return redirect(url_for('chat'))
    ban_username = request.form.get('ban_username', '').strip()
    users = load_users()
    if ban_username in users:
        ban_priv = users[ban_username][1]
        # Only superuser can ban admins, and superusers cannot ban each other
        if ban_priv == PRIV_SUPERUSER:
            if not is_superuser():
                flash('Only superusers can ban other superusers.', 'admin')
                return redirect(url_for('admin'))
            else:
                flash('Superusers cannot ban each other.', 'admin')
                return redirect(url_for('admin'))
        if ban_priv == PRIV_ADMIN and not is_superuser():
            flash('Only superusers can ban admins.', 'admin')
            return redirect(url_for('admin'))
        # If banning an admin, demote and force logout
        if ban_priv == PRIV_ADMIN and is_superuser():
            # Demote admin to user
            pw_hash = users[ban_username][0]
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            with open(USERS_FILE, 'w', encoding='utf-8') as f:
                for line in lines:
                    if line.startswith(ban_username + ':'):
                        f.write(f"{ban_username}:{pw_hash}:{PRIV_USER}\n")
                    else:
                        f.write(line)
            flash(f"Admin {ban_username} demoted and banned.", 'admin')
        # Ban user
        with open(BANNED_IPS_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{ban_username}\n")
        banned_users.add(ban_username)
        forced_logout_users.add(ban_username)
        flash(f"User {ban_username} banned and logged out.", 'admin')
    else:
        flash("User not found.", 'admin')
    return redirect(url_for('admin'))

@app.route('/unban_user', methods=['POST'])
def unban_user():
    if not is_admin():
        flash('Admin access required.')
        return redirect(url_for('chat'))
    unban_username = request.form.get('unban_username', '').strip()
    # Remove from banned file
    with open(BANNED_IPS_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    with open(BANNED_IPS_FILE, 'w', encoding='utf-8') as f:
        for line in lines:
            if line.strip() != unban_username:
                f.write(line)
    banned_users.discard(unban_username)
    forced_logout_users.discard(unban_username)
    flash(f"User {unban_username} unbanned.")
    return redirect(url_for('admin'))

# Only superuser can promote/demote admins, force logout/unregister all users, clear chat/private messages
@app.route('/promote_user', methods=['POST'])
def promote_user():
    if not is_superuser():
        flash('Superuser access required.')
        return redirect(url_for('chat'))
    promote_username = request.form.get('promote_username', '').strip()
    users = load_users()
    if promote_username in users:
        pw_hash = users[promote_username][0]
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            for line in lines:
                if line.startswith(promote_username + ':'):
                    f.write(f"{promote_username}:{pw_hash}:{PRIV_ADMIN}\n")
                else:
                    f.write(line)
        flash(f'User {promote_username} promoted to admin.')
    else:
        flash('User not found.')
    return redirect(url_for('admin'))

@app.route('/demote_user', methods=['POST'])
def demote_user():
    if not is_superuser():
        flash('Superuser access required.')
        return redirect(url_for('chat'))
    demote_username = request.form.get('demote_username', '').strip()
    users = load_users()
    if demote_username in users:
        pw_hash = users[demote_username][0]
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            for line in lines:
                if line.startswith(demote_username + ':'):
                    f.write(f"{demote_username}:{pw_hash}:{PRIV_USER}\n")
                else:
                    f.write(line)
        flash(f'User {demote_username} demoted to user.')
    else:
        flash('User not found.')
    return redirect(url_for('admin'))

@app.route('/force_logout_all', methods=['POST'])
def force_logout_all():
    if not is_superuser():
        flash('Superuser access required.')
        return redirect(url_for('chat'))
    active_users.clear()
    forced_logout_users.update(load_users().keys())
    save_forced_logout_users(forced_logout_users)
    flash('All users have been logged out (session will end on next request).')
    return redirect(url_for('admin'))

@app.route('/unregister_all_users', methods=['POST'])
def unregister_all_users():
    if not is_superuser():
        flash('Superuser access required.')
        return redirect(url_for('chat'))
    open(USERS_FILE, 'w').close()
    active_users.clear()
    flash('All users have been unregistered and logged out.')
    return redirect(url_for('admin'))

@app.route('/clear_chat', methods=['POST'])
def clear_chat():
    if not is_superuser():
        flash('Superuser access required.')
        return redirect(url_for('chat'))
    open(CHAT_LOG, 'w').close()
    flash('Chat log cleared.')
    return redirect(url_for('admin'))

@app.route('/clear_private_messages', methods=['POST'])
def clear_private_messages():
    if not is_superuser():
        flash('Superuser access required.')
        return redirect(url_for('chat'))
    open(PRIVATE_MSG_FILE, 'w').close()
    flash('All private messages have been cleared.')
    return redirect(url_for('admin'))

@app.route('/logout_user', methods=['POST'])
def logout_user():
    if not is_admin():
        flash('Admin access required.')
        return redirect(url_for('chat'))
    logout_username = request.form.get('logout_username', '').strip()
    if logout_username:
        users = load_forced_logout_users()
        users.add(logout_username)
        save_forced_logout_users(users)
        flash(f'User {logout_username} will be logged out on their next request.')
    else:
        flash('No username provided.')
    return redirect(url_for('admin'))

@app.route('/reset_password', methods=['POST'])
def reset_password():
    if not is_admin():
        flash('Admin access required.')
        return redirect(url_for('chat'))
    reset_username = request.form.get('reset_username', '').strip()
    new_password = request.form.get('new_password', '').strip()
    users = load_users()
    if reset_username in users and new_password:
        pw_hash = generate_password_hash(new_password)
        is_admin_flag = users[reset_username][1]
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            for line in lines:
                if line.startswith(reset_username + ':'):
                    f.write(f"{reset_username}:{pw_hash}:{is_admin_flag}\n")
                else:
                    f.write(line)
        flash(f'Password for {reset_username} has been reset.')
    else:
        flash('User not found or no new password provided.')
    return redirect(url_for('admin'))

# User registration times (stub: you could store this in a new file or extend users.txt)
USER_REG_FILE = 'user_reg_times.txt'

def save_user_registration(username):
    with open(USER_REG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{username}:{datetime.datetime.now().isoformat()}\n")

def load_user_registrations():
    reg = {}
    if os.path.exists(USER_REG_FILE):
        with open(USER_REG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if ':' in line:
                    user, t = line.strip().split(':', 1)
                    reg[user] = t
    return reg

@app.route('/download_log/<logtype>', methods=['GET'])
def download_log(logtype):
    if not is_admin():
        flash('Admin access required.')
        return redirect(url_for('chat'))
    if logtype == 'chat':
        path = CHAT_LOG
        filename = 'chat.log'
    elif logtype == 'private':
        path = PRIVATE_MSG_FILE
        filename = 'private_messages.txt'
    else:
        flash('Invalid log type.')
        return redirect(url_for('admin'))
    return send_from_directory(os.path.dirname(os.path.abspath(path)), os.path.basename(path), as_attachment=True, download_name=filename)

@app.route('/view_private_messages', methods=['GET'])
def view_private_messages():
    if not is_admin():
        flash('Admin access required.')
        return redirect(url_for('chat'))
    with open(PRIVATE_MSG_FILE, 'r', encoding='utf-8') as f:
        private_lines = [line.strip() for line in f.readlines()]
    return render_template_string(view_private_template, private_lines=private_lines)

@app.route('/view_user_info', methods=['GET'])
def view_user_info():
    if not is_admin():
        flash('Admin access required.')
        return redirect(url_for('chat'))
    reg = load_user_registrations()
    users = load_users()
    info = []
    for user in users:
        info.append(f"{user} - Registered: {reg.get(user, 'Unknown')}, Admin: {users[user][1]}")
    return render_template_string("""
    <h2>User Info</h2>
    <ul>
    {% for line in info %}<li>{{ line }}</li>{% endfor %}
    </ul>
    <p><a href='{{ url_for('admin') }}'>Back to Admin</a></p>
    """, info=info)

@app.route('/unregister_user', methods=['POST'])
def unregister_user():
    if not is_admin():
        flash('Admin access required.')
        return redirect(url_for('chat'))
    unreg_username = request.form.get('unreg_username', '').strip()
    users = load_users()
    if unreg_username in users:
        # Remove user from users.txt
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            for line in lines:
                if not line.startswith(unreg_username + ':'):
                    f.write(line)
        active_users.discard(unreg_username)
        # Remove from forced logout and banned sets and files
        fl_users = load_forced_logout_users()
        fl_users.discard(unreg_username)
        save_forced_logout_users(fl_users)
        banned_users.discard(unreg_username)
        flash(f'User {unreg_username} has been unregistered and logged out.')
    else:
        flash('User not found.')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5087)