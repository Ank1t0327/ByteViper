import os
import threading
from flask import Flask, render_template, jsonify

app = Flask(__name__)

# Basic in-memory store for packets (to be replaced by streamer)
app.config['PACKETS'] = []

@app.route('/')
def index():
    return render_template('index.html')

def run_server(host='127.0.0.1', port=5000):
    # Disable flask reloader in thread
    app.run(host=host, port=port, debug=False, use_reloader=False)

def start_web_server():
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    return server_thread
