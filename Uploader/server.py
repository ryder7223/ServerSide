from flask import Flask, request, render_template, send_from_directory
import os
import logging

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure the logging for file-related actions
file_logger = logging.getLogger('file_logger')
file_logger.setLevel(logging.INFO)

# Output to terminal
file_handler_terminal = logging.StreamHandler()
file_handler_terminal.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
file_logger.addHandler(file_handler_terminal)

# Output to file (if needed)
# file_handler_file = logging.FileHandler('file_logs.log')
# file_handler_file.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
# file_logger.addHandler(file_handler_file)

@app.route('/')
def index():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('index.html', files=files)

@app.route('/upload', methods=['POST'])
def upload_files():
    uploaded_files = request.files.getlist('files[]')

    if not uploaded_files:
        return 'No files selected'

    for uploaded_file in uploaded_files:
        if uploaded_file.filename != '':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
            
            with open(file_path, 'wb') as file:
                file.write(uploaded_file.read())

            # Log the file upload action
            file_logger.info(f'File uploaded: {uploaded_file.filename}')

    return 'Files uploaded successfully'

@app.route('/uploads/<filename>')
def download_file(filename):
    # Log the file download action
    file_logger.info(f'File downloaded: {filename}')
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    # Set the logging level for Werkzeug to a higher level (e.g., WARNING)
    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.setLevel(logging.WARNING)

    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(host='0.0.0.0', port=5000, debug=True)
