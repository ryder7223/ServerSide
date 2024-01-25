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

# Set of banned IP addresses
banned_ips = {'0.0.0.0', '0.0.0.0'}

@app.route('/')
def index():
    return render_template('index.html', counter=counter)

@app.route('/increment', methods=['POST'])
def increment():
    global counter

    # Get the user's IP address
    ip_address = request.remote_addr

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
    app.logger.info(f'User with IP {ip} has been banned.')
    return jsonify({'message': f'User with IP {ip} has been banned.'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
