import os
import threading
from flask import Flask, render_template, jsonify, request
from src.web.streamer import streamer

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/packets')
def get_packets():
    since = request.args.get('since', default=0.0, type=float)
    packets = streamer.get_packets_since(since)
    return jsonify({"packets": packets})

@app.route('/api/clear', methods=['POST'])
def clear_packets():
    streamer.clear()
    return jsonify({"status": "success"})

def run_server(host='127.0.0.1', port=5000):
    # Disable flask reloader in thread
    app.run(host=host, port=port, debug=False, use_reloader=False)

def start_web_server():
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    return server_thread
