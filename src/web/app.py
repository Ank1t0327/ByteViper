import os
import threading
from flask import Flask, render_template, jsonify, request
from web.streamer import streamer
from modules.session import session_tracker
import logging

# Disable Flask/Werkzeug default request logging to prevent terminal spam
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/packets')
def get_packets():
    since = request.args.get('since', default=0.0, type=float)
    packets = streamer.get_packets_since(since)
    return jsonify({"packets": packets})

@app.route('/api/sessions')
def get_sessions():
    sessions = session_tracker.get_active_sessions()
    return jsonify({"sessions": sessions})

@app.route('/api/alerts')
def get_alerts():
    since = request.args.get('since', default=0.0, type=float)
    alerts = streamer.get_alerts_since(since)
    return jsonify({"alerts": alerts})

@app.route('/api/status')
def get_status():
    from modules.anomaly import anomaly_engine
    from feeds.updater import threat_intel
    return jsonify({
        "anomaly_engine": anomaly_engine.get_status(),
        "threat_intel": threat_intel.get_status()
    })

@app.route('/api/threat_intel/status')
def get_threat_intel_status():
    from feeds.updater import threat_intel
    return jsonify(threat_intel.get_status())

@app.route('/api/threat_intel/update', methods=['POST'])
def update_threat_intel():
    from feeds.updater import threat_intel
    started = threat_intel.update_feeds_async()
    return jsonify({"status": "started" if started else "already_running"})


@app.route('/api/clear', methods=['POST'])
def clear_packets():
    streamer.clear()
    session_tracker.sessions.clear() # clear sessions too
    return jsonify({"status": "success"})

def run_server(host='127.0.0.1', port=5000):
    # Disable flask reloader in thread
    app.run(host=host, port=port, debug=False, use_reloader=False)

def start_web_server():
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    return server_thread
