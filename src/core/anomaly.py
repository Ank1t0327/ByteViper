import time
import math
import threading
from core.rules import Alert

class AnomalyEngine:
    def __init__(self, learning_period=30, deviation_threshold=3.0):
        self.learning_period = learning_period
        self.deviation_threshold = deviation_threshold
        
        # Historical buckets (per second)
        self.history_bytes = []
        self.history_packets = []
        
        # Current bucket
        self.current_sec = int(time.time())
        self.bytes_this_sec = 0
        self.packets_this_sec = 0
        
        # Baselines
        self.mean_bytes = 0.0
        self.std_bytes = 0.0
        self.mean_packets = 0.0
        self.std_packets = 0.0
        
        self.callbacks = []
        self.is_learning = True
        self.lock = threading.Lock()

    def register_callback(self, callback):
        self.callbacks.append(callback)

    def process_packet(self, parsed_data):
        with self.lock:
            now_sec = int(time.time())
            
            # If we crossed into a new second, process the previous bucket
            if now_sec > self.current_sec:
                self._evaluate_bucket()
                
                # Fill in missing seconds with 0s if there was a gap
                gap = now_sec - self.current_sec - 1
                for _ in range(min(gap, 10)): # cap gap fills
                    self.history_bytes.append(0)
                    self.history_packets.append(0)
                    if len(self.history_bytes) > self.learning_period:
                        self.history_bytes.pop(0)
                        self.history_packets.pop(0)
                
                self.current_sec = now_sec
                self.bytes_this_sec = 0
                self.packets_this_sec = 0
                
            # Add to current bucket
            self.bytes_this_sec += parsed_data.get('length', 0)
            self.packets_this_sec += 1

    def _evaluate_bucket(self):
        if self.is_learning:
            self.history_bytes.append(self.bytes_this_sec)
            self.history_packets.append(self.packets_this_sec)
            
            if len(self.history_bytes) > self.learning_period:
                self.history_bytes.pop(0)
                self.history_packets.pop(0)
                
            if len(self.history_bytes) >= self.learning_period:
                self._compute_baseline()
                self.is_learning = False
                
        else:
            # Active detection
            z_bytes = 0
            if self.std_bytes > 0:
                z_bytes = (self.bytes_this_sec - self.mean_bytes) / self.std_bytes
                
            z_packets = 0
            if self.std_packets > 0:
                z_packets = (self.packets_this_sec - self.mean_packets) / self.std_packets
                
            alerts = []
            
            # Avoid triggering on absolute zero or tiny variance where a single packet spikes z-score
            if z_bytes > self.deviation_threshold and self.bytes_this_sec > max(1000, self.mean_bytes * 2):
                alerts.append(Alert(
                    "Anomaly: Bandwidth Spike", 
                    "HIGH", 
                    f"Traffic surged to {self.bytes_this_sec} bytes/sec (Z-Score: {z_bytes:.1f})", 
                    "Network"
                ))
            
            if z_packets > self.deviation_threshold and self.packets_this_sec > max(10, self.mean_packets * 2):
                alerts.append(Alert(
                    "Anomaly: Packet Rate Spike", 
                    "HIGH", 
                    f"Packet rate surged to {self.packets_this_sec} pkts/sec (Z-Score: {z_packets:.1f})", 
                    "Network"
                ))
            
            for alert in alerts:
                for cb in self.callbacks:
                    cb(alert.to_dict())
            
            # Update history rolling window
            self.history_bytes.append(self.bytes_this_sec)
            self.history_packets.append(self.packets_this_sec)
            self.history_bytes.pop(0)
            self.history_packets.pop(0)
            
            # Recompute rolling baseline dynamically
            self._compute_baseline()

    def _compute_baseline(self):
        if not self.history_bytes:
            return
            
        n = len(self.history_bytes)
        
        self.mean_bytes = sum(self.history_bytes) / n
        var_bytes = sum((x - self.mean_bytes) ** 2 for x in self.history_bytes) / n
        self.std_bytes = math.sqrt(var_bytes)
        
        self.mean_packets = sum(self.history_packets) / n
        var_packets = sum((x - self.mean_packets) ** 2 for x in self.history_packets) / n
        self.std_packets = math.sqrt(var_packets)

    def get_status(self):
        with self.lock:
            return {
                "is_learning": self.is_learning,
                "progress": min(100, int((len(self.history_bytes) / self.learning_period) * 100)) if self.is_learning else 100,
                "mean_bytes": self.mean_bytes,
                "mean_packets": self.mean_packets
            }

anomaly_engine = AnomalyEngine(learning_period=30)