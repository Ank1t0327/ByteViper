import socket
from scapy.all import Packet, Ether, IP, IPv6, ARP, TCP, UDP, ICMP, DNS, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse

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

        # Layer 4
        if packet.haslayer(TCP):
            parsed_data["layers"].append(self._parse_tcp(packet[TCP]))
        elif packet.haslayer(UDP):
            parsed_data["layers"].append(self._parse_udp(packet[UDP]))
        elif packet.haslayer(ICMP):
            parsed_data["layers"].append(self._parse_icmp(packet[ICMP]))

        # Layer 7 (Application)
        if packet.haslayer(DNS):
            parsed_data["layers"].append(self._parse_dns(packet[DNS]))
        if packet.haslayer(HTTPRequest):
            parsed_data["layers"].append(self._parse_http_req(packet[HTTPRequest]))
        elif packet.haslayer(HTTPResponse):
            parsed_data["layers"].append(self._parse_http_resp(packet[HTTPResponse]))

        # Raw Payload Extraction
        raw_payload = b""
        if packet.haslayer(Raw):
            raw_payload = packet[Raw].load
        else:
            for proto in [TCP, UDP]:
                if packet.haslayer(proto):
                    try:
                        payload_layer = packet[proto].payload
                        if payload_layer:
                            p_bytes = bytes(payload_layer)
                            if p_bytes:
                                raw_payload = p_bytes
                                break
                    except Exception:
                        pass

        # Store raw payload bytes internally for DPI rules, truncate/decode for frontend/JSON transmission
        parsed_data["raw_payload_bytes"] = raw_payload
        
        ui_payload = raw_payload
        is_truncated = False
        if len(raw_payload) > 2048:
            ui_payload = raw_payload[:2048]
            is_truncated = True

        parsed_data["payload"] = ui_payload.decode("utf-8", errors="replace") if ui_payload else ""
        parsed_data["payload_hex"] = ui_payload.hex() if ui_payload else ""
        
        hexdump_str = self._format_hexdump(ui_payload) if ui_payload else ""
        if is_truncated:
            hexdump_str += f"\n... [Truncated; payload exceeds 2KB (Total size: {len(raw_payload)} bytes)]"
            
        parsed_data["payload_hexdump"] = hexdump_str

        return parsed_data

    def _format_hexdump(self, data: bytes) -> str:
        if not data:
            return ""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            left_parts = [f"{b:02x}" for b in chunk[:8]]
            right_parts = [f"{b:02x}" for b in chunk[8:]]
            
            left_str = " ".join(left_parts)
            right_str = " ".join(right_parts)
            
            left_str_padded = f"{left_str:<23}"
            right_str_padded = f"{right_str:<23}"
            
            hex_str = f"{left_str_padded}  {right_str_padded}"
            
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_str}  |{ascii_str}|")
        return "\n".join(lines)

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

    def _parse_tcp(self, tcp_layer) -> dict:
        return {
            "layer": "TCP",
            "src_port": tcp_layer.sport,
            "dst_port": tcp_layer.dport,
            "seq": tcp_layer.seq,
            "ack": tcp_layer.ack,
            "flags": str(tcp_layer.flags),
            "window": tcp_layer.window
        }

    def _parse_udp(self, udp_layer) -> dict:
        return {
            "layer": "UDP",
            "src_port": udp_layer.sport,
            "dst_port": udp_layer.dport,
            "length": udp_layer.len
        }

    def _parse_icmp(self, icmp_layer) -> dict:
        return {
            "layer": "ICMP",
            "type": icmp_layer.type,
            "code": icmp_layer.code,
            "id": getattr(icmp_layer, 'id', None),
            "seq": getattr(icmp_layer, 'seq', None)
        }

    def _parse_dns(self, dns_layer) -> dict:
        qname = None
        if hasattr(dns_layer, 'qd') and dns_layer.qd is not None:
            qname = dns_layer.qd.qname.decode('utf-8', errors='ignore') if isinstance(dns_layer.qd.qname, bytes) else dns_layer.qd.qname
        
        return {
            "layer": "DNS",
            "id": dns_layer.id,
            "qr": dns_layer.qr,
            "opcode": dns_layer.opcode,
            "rcode": dns_layer.rcode,
            "qname": qname
        }

    def _parse_http_req(self, http_req_layer) -> dict:
        return {
            "layer": "HTTP Request",
            "method": http_req_layer.Method.decode('utf-8', errors='ignore') if http_req_layer.Method else None,
            "host": http_req_layer.Host.decode('utf-8', errors='ignore') if http_req_layer.Host else None,
            "path": http_req_layer.Path.decode('utf-8', errors='ignore') if http_req_layer.Path else None,
            "user_agent": http_req_layer.User_Agent.decode('utf-8', errors='ignore') if getattr(http_req_layer, 'User_Agent', None) else None
        }

    def _parse_http_resp(self, http_resp_layer) -> dict:
        return {
            "layer": "HTTP Response",
            "status_code": http_resp_layer.Status_Code.decode('utf-8', errors='ignore') if http_resp_layer.Status_Code else None,
            "reason": http_resp_layer.Reason_Phrase.decode('utf-8', errors='ignore') if getattr(http_resp_layer, 'Reason_Phrase', None) else None,
            "server": http_resp_layer.Server.decode('utf-8', errors='ignore') if getattr(http_resp_layer, 'Server', None) else None
        }
