import logging
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

# Define a custom logging filter to exclude successful access logs (HTTP 200)
class Exclude200Filter(logging.Filter):
    def filter(self, record):
        # Exclude log records with code 200 for access logs
        return record.levelname != 'INFO' or 'Incremented by' in record.getMessage()

# Apply the custom filter to the werkzeug logger
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.addFilter(Exclude200Filter())

# Initial counter value
counter = 0

# File path for banned IPs
banned_ips_file = 'banned_ips.txt'

def load_banned_ips():
    try:
        with open(banned_ips_file, 'r') as file:
            return set(file.read().splitlines())
    except FileNotFoundError:
        return set()

def save_banned_ips(banned_ips):
    with open(banned_ips_file, 'w') as file:
        file.write('\n'.join(banned_ips))

# Load banned IPs on startup
banned_ips = load_banned_ips()

@app.route('/')
def index():
    return render_template('index.html', counter=counter)

@app.route('/increment', methods=['POST'])
def increment():
    global counter

    # Get the user's IP address
    ip_address = request.remote_addr

    # Load banned IPs on every request to ensure the latest list is considered
    banned_ips = load_banned_ips()

    # Check if the user is banned
    if ip_address in banned_ips:
        return jsonify({'error': 'You are banned from incrementing the counter.'}), 403

    # Increment the counter
    counter += 1

    # Log the increment action with the IP address and the new counter value
    app.logger.info(f'Incremented by {ip_address}. New counter value: {counter}')

    return jsonify({'counter': counter})

@app.route('/ban/<ip>', methods=['POST'])
def ban_ip(ip):
    # Add the specified IP address to the banned list
    banned_ips.add(ip)
    save_banned_ips(banned_ips)
    app.logger.info(f'User with IP {ip} has been banned.')
    return jsonify({'message': f'User with IP {ip} has been banned.'})

if __name__ == '__main__':
    app.run(host='192.168.0.175', port=5000, debug=True)
