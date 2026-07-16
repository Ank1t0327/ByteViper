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

# Global database manager instance
db_manager = DatabaseManager()
