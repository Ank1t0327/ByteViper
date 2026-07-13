import threading
import time
from scapy.all import AsyncSniffer, get_if_list, get_if_hwaddr, conf

class PacketSniffer:
    def __init__(self, interface=None):
        self.interface = interface
        self.packet_count = 0
        self.sniffer = None
        self._is_capturing = False
        
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

    def start(self):
        """Starts the packet capture in a background thread."""
        if self._is_capturing:
            return False

        if not self.interface:
            raise ValueError("No interface selected for capture.")

        self.packet_count = 0
        self._is_capturing = True

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
