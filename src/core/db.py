import os
import sqlite3
import json

DB_FILE = os.path.join(os.path.dirname(__file__), "byteviper.db")

class DatabaseManager:
    def __init__(self, db_path=DB_FILE):
        self.db_path = db_path
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        """Initialize tables if they do not exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Packets table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    length INTEGER,
                    protocol TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    summary TEXT,
                    layers_json TEXT,
                    payload TEXT,
                    payload_hexdump TEXT
                )
            """)

            # Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    rule_name TEXT,
                    severity TEXT,
                    description TEXT,
                    src_ip TEXT
                )
            """)

            # Sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    protocol TEXT,
                    state TEXT,
                    endpoint_a TEXT,
                    endpoint_b TEXT,
                    packet_count INTEGER,
                    total_bytes INTEGER,
                    start_time REAL,
                    last_time REAL,
                    UNIQUE(protocol, endpoint_a, endpoint_b) ON CONFLICT REPLACE
                )
            """)
            conn.commit()

    def add_packet(self, parsed_data):
        timestamp = parsed_data.get("timestamp", 0.0)
        length = parsed_data.get("length", 0)
        summary = parsed_data.get("summary", "")
        payload = parsed_data.get("payload", "")
        payload_hexdump = parsed_data.get("payload_hexdump", "")
        
        layers = parsed_data.get("layers", [])
        src_ip = "-"
        dst_ip = "-"
        protocol = "-"
        
        ip_layer = next((l for l in layers if l.get("layer") in ["IPv4", "IPv6"]), None)
        if ip_layer:
            src_ip = ip_layer.get("src_ip", "-")
            dst_ip = ip_layer.get("dst_ip", "-")
        else:
            eth_layer = next((l for l in layers if l.get("layer") == "Ethernet"), None)
            if eth_layer:
                src_ip = eth_layer.get("src_mac", "-")
                dst_ip = eth_layer.get("dst_mac", "-")
                
        if layers:
            protocol = layers[-1].get("layer", "-")
            
        try:
            layers_json = json.dumps(layers)
        except Exception:
            layers_json = "[]"
            
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO packets (timestamp, length, protocol, src_ip, dst_ip, summary, layers_json, payload, payload_hexdump)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, length, protocol, src_ip, dst_ip, summary, layers_json, payload, payload_hexdump))
            conn.commit()

    def add_alert(self, alert_data):
        timestamp = alert_data.get("timestamp", 0.0)
        rule_name = alert_data.get("rule_name", "")
        severity = alert_data.get("severity", "")
        description = alert_data.get("description", "")
        src_ip = alert_data.get("src_ip", "")
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts (timestamp, rule_name, severity, description, src_ip)
                VALUES (?, ?, ?, ?, ?)
            """, (timestamp, rule_name, severity, description, src_ip))
            conn.commit()

    def add_session(self, session_data):
        protocol = session_data.get("protocol", "")
        state = session_data.get("state", "")
        endpoint_a = session_data.get("endpoint_a", "")
        endpoint_b = session_data.get("endpoint_b", "")
        packet_count = session_data.get("packet_count", 0)
        total_bytes = session_data.get("total_bytes", 0)
        start_time = session_data.get("start_time", 0.0)
        last_time = session_data.get("last_time", 0.0)
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sessions (protocol, state, endpoint_a, endpoint_b, packet_count, total_bytes, start_time, last_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (protocol, state, endpoint_a, endpoint_b, packet_count, total_bytes, start_time, last_time))
            conn.commit()

    def get_packets(self, limit=1000):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM packets ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            packets = []
            for row in rows:
                p = dict(row)
                try:
                    p["layers"] = json.loads(p["layers_json"])
                except Exception:
                    p["layers"] = []
                packets.append(p)
            return packets

    def get_alerts(self, limit=1000):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_sessions(self, limit=1000):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sessions ORDER BY last_time DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def clear_all(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM packets")
            cursor.execute("DELETE FROM alerts")
            cursor.execute("DELETE FROM sessions")
            conn.commit()

# Global database manager instance
db_manager = DatabaseManager()
