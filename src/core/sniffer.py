import threading
import time
from collections import deque
from scapy.all import AsyncSniffer, get_if_list, get_if_hwaddr, conf
from core.parser import PacketParser
from web.streamer import streamer

class PacketSniffer:
    def __init__(self, interface=None, max_history=2000):
        self.interface = interface
        self.packet_count = 0
        self.sniffer = None
        self._is_capturing = False
        self.parser = PacketParser()
        self.live_output = False
        self.callbacks = []
        self.raw_packets = deque(maxlen=max_history)

    def register_callback(self, callback):
        self.callbacks.append(callback)

    @staticmethod
    def get_interfaces():
        """Returns a list of available network interfaces."""
        interfaces = get_if_list()
        # Some systems might have weird interfaces, we'll just return the list
        return interfaces

    def set_interface(self, interface):
        self.interface = interface

    def _packet_handler(self, packet):
        """Callback function called for each captured packet."""
        self.packet_count += 1
        self.raw_packets.append(packet)
        streamer.add_raw_packet(packet)
        try:
            parsed_data = self.parser.parse(packet)
            parsed_data['timestamp'] = float(packet.time)
            if self.live_output:
                layers_list = [layer.get("layer", "Unknown") for layer in parsed_data.get("layers", [])]
                layers_str = " -> ".join(layers_list)
                print(f"  [Packet {self.packet_count}] {parsed_data.get('length')} bytes | {layers_str}")
            
            for cb in self.callbacks:
                cb(parsed_data)
        except Exception as e:
            # Silently handle parsing errors for now
            pass

    def start(self, live=False):
        """Starts the packet capture in a background thread."""
        if self._is_capturing:
            return False

        if not self.interface:
            raise ValueError("No interface selected for capture.")

        self.packet_count = 0
        self._is_capturing = True
        self.live_output = live

        # AsyncSniffer runs in its own thread
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._packet_handler,
            store=False # Don't keep packets in memory to save RAM
        )
        
        try:
            self.sniffer.start()
        except Exception as e:
            self._is_capturing = False
            raise e

        return True

    def stop(self):
        """Stops the packet capture."""
        if not self._is_capturing:
            return False

        if self.sniffer:
            self.sniffer.stop()
            self.sniffer.join()
        
        self._is_capturing = False
        return True

    def get_packet_count(self):
        return self.packet_count
    
    def is_running(self):
        return self._is_capturing

    def get_raw_packets(self):
        return list(self.raw_packets)

    def clear_raw_packets(self):
        self.raw_packets.clear()
