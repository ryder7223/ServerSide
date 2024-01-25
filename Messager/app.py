from flask import Flask, render_template, request, make_response
from flask_socketio import SocketIO, emit
import uuid
import hashlib
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

# Configure the logging for the Flask app
app_logger = logging.getLogger('werkzeug')
app_logger.setLevel(logging.INFO)

# Configure the logging for new connections
new_connection_logger = logging.getLogger('new_connection_logger')
new_connection_logger.setLevel(logging.INFO)
new_connection_handler = logging.StreamHandler()  # Output to terminal
new_connection_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
new_connection_logger.addHandler(new_connection_handler)

# List of banned IPs
banned_ips = {'0.0.0.0', '0.0.0.0'}  # Add the IP addresses you want to ban to this set

messages = {}
user_data = {}

def generate_color_tag(user_id):
    # Generate a color tag based on the user_id using hashlib
    hash_object = hashlib.md5(user_id.encode())
    color_hex = hash_object.hexdigest()[:6]
    return "#" + color_hex

@app.route('/')
def index():
    return render_template('index.html', messages=messages)

@socketio.on('connect')
def handle_connect():
    sid = request.sid
    ip = request.remote_addr

    if ip in banned_ips:
        # Reject the connection if the IP is banned
        return

    user_id = user_data.get(sid)

    if user_id is None:
        # If the user_id is not present, generate a new one
        user_id = str(uuid.uuid4())
        user_data[sid] = user_id

    color_tag = generate_color_tag(user_id)

    # Set the user_id and color_tag in the session cookie
    response = make_response(render_template('index.html', messages=messages, color_tag=color_tag))
    response.set_cookie('user_id', user_id)
    response.set_cookie('color_tag', color_tag)

    messages[sid] = {'user_id': user_id, 'color_tag': color_tag, 'ip': ip, 'messages': []}

    # Log the new connection using the new_connection_logger
    new_connection_logger.info(f'New connection from IP: {ip}')

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    user_data.pop(sid, None)
    messages.pop(sid, None)

@socketio.on('message')
def handle_message(data):
    sid = request.sid
    ip = messages.get(sid, {}).get('ip', 'Unknown IP')
    
    try:
        user_id = messages[sid]['user_id']
        color_tag = messages[sid]['color_tag']
    except KeyError:
        # User not found in messages, likely a banned user
        new_connection_logger.info(f'Banned user ({ip}) tried to send a message: {data["message"]}')
        return

    # Check if the message content is empty
    if not data['message'].strip():
        # You can choose to ignore empty messages or send an error response
        return

    # Check if the message exceeds the character limit
    max_chars = 250
    if len(data['message']) > max_chars:
        # Truncate the message if it exceeds the limit
        data['message'] = data['message'][:max_chars]

    formatted_message = f"[<span style='color: {color_tag}'>User {user_id}</span>] {data['message']}"
    messages[sid]['messages'].append(formatted_message)

    # Log the message and associated IP address using the new_connection_logger
    new_connection_logger.info(f'Message from IP {ip}: {data["message"]}')

    emit('message', {'message': formatted_message}, broadcast=True)

if __name__ == '__main__':
    # Set up a logger for the startup logs
    startup_logger = logging.getLogger('startup_logger')
    startup_logger.setLevel(logging.INFO)

    # Output to terminal
    startup_handler_terminal = logging.StreamHandler()
    startup_handler_terminal.setFormatter(logging.Formatter('%(message)s'))
    startup_logger.addHandler(startup_handler_terminal)

    # Get the host and port from the Flask app
    host = app.config.get('HOST', '0.0.0.0')
    port = app.config.get('PORT', 5000)

    # Log the startup message
    startup_logger.info(f' * Running on http://{host}:{port}')

    # Set the Werkzeug logger to a higher level
    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.setLevel(logging.WARNING)

    # Run the SocketIO app
    socketio.run(app, host=host, port=port, debug=True)
