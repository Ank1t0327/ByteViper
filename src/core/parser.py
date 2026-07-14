import socket
from scapy.all import Packet, Ether, IP, IPv6, ARP

class PacketParser:
    """
    Protocol Parsing Engine for ByteViper NDS.
    Extracts structured data from captured Scapy packets.
    """
    
    def __init__(self):
        pass

    def parse(self, packet: Packet) -> dict:
        """
        Main entry point for parsing a packet.
        Returns a dictionary with extracted layer data.
        """
        parsed_data = {
            "summary": packet.summary(),
            "length": len(packet),
            "layers": []
        }

        # Layer 2
        if packet.haslayer(Ether):
            parsed_data["layers"].append(self._parse_ethernet(packet[Ether]))
        if packet.haslayer(ARP):
            parsed_data["layers"].append(self._parse_arp(packet[ARP]))

        # Layer 3
        if packet.haslayer(IP):
            parsed_data["layers"].append(self._parse_ip(packet[IP]))
        elif packet.haslayer(IPv6):
            parsed_data["layers"].append(self._parse_ipv6(packet[IPv6]))

        return parsed_data

    def _parse_ethernet(self, eth_layer) -> dict:
        return {
            "layer": "Ethernet",
            "src_mac": eth_layer.src,
            "dst_mac": eth_layer.dst,
            "type": eth_layer.type
        }

    def _parse_arp(self, arp_layer) -> dict:
        return {
            "layer": "ARP",
            "op": arp_layer.op,
            "hwsrc": arp_layer.hwsrc,
            "psrc": arp_layer.psrc,
            "hwdst": arp_layer.hwdst,
            "pdst": arp_layer.pdst
        }

    def _parse_ip(self, ip_layer) -> dict:
        return {
            "layer": "IPv4",
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "protocol": ip_layer.proto,
            "ttl": ip_layer.ttl,
            "length": ip_layer.len,
            "flags": str(ip_layer.flags)
        }

    def _parse_ipv6(self, ipv6_layer) -> dict:
        return {
            "layer": "IPv6",
            "src_ip": ipv6_layer.src,
            "dst_ip": ipv6_layer.dst,
            "next_header": ipv6_layer.nh,
            "hlim": ipv6_layer.hlim,
            "length": ipv6_layer.plen
        }
