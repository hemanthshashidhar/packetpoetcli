"""
Packet Reader Module
Uses Scapy to ingest PCAP files and extract packet data
"""

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime


@dataclass
class PacketEvent:
    """Standardized packet event for analysis"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    flags: Optional[str]
    payload_info: str
    raw_summary: str


class PacketReader:
    """Reads PCAP files and converts to structured events"""
    
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.packets: List[PacketEvent] = []
        
    def read(self) -> List[PacketEvent]:
        """Read PCAP and convert to PacketEvent objects"""
        print(f"[*] Reading {self.pcap_path}...")
        
        try:
            scapy_packets = rdpcap(self.pcap_path)
        except Exception as e:
            print(f"[!] Error reading PCAP: {e}")
            return []
            
        for pkt in scapy_packets:
            event = self._parse_packet(pkt)
            if event:
                self.packets.append(event)
                
        print(f"[+] Parsed {len(self.packets)} packets")
        return self.packets
    
    def _parse_packet(self, pkt) -> Optional[PacketEvent]:
        """Extract relevant fields from Scapy packet"""
        
        # Get timestamp
        timestamp = datetime.fromtimestamp(float(pkt.time))
        
        # Initialize defaults
        src_ip = "unknown"
        dst_ip = "unknown"
        protocol = "OTHER"
        src_port = None
        dst_port = None
        flags = None
        payload_info = ""
        
        # IP Layer
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            # TCP
            if TCP in pkt:
                protocol = "TCP"
                src_port = int(pkt[TCP].sport) if pkt[TCP].sport else None
                dst_port = int(pkt[TCP].dport) if pkt[TCP].dport else None
                flags = self._interpret_tcp_flags(pkt[TCP].flags)
                
                # Detect common services
                if dst_port == 80 or src_port == 80:
                    payload_info = "HTTP traffic"
                elif dst_port == 443 or src_port == 443:
                    payload_info = "HTTPS encrypted"
                elif dst_port == 22:
                    payload_info = "SSH connection"
                elif dst_port == 53:
                    payload_info = "DNS query"
                    
            # UDP
            elif UDP in pkt:
                protocol = "UDP"
                src_port = int(pkt[UDP].sport) if pkt[UDP].sport else None
                dst_port = int(pkt[UDP].dport) if pkt[UDP].dport else None
                
                if dst_port == 53:
                    payload_info = "DNS request"
                elif dst_port == 123:
                    payload_info = "NTP sync"
                    
            # ICMP
            elif ICMP in pkt:
                protocol = "ICMP"
                payload_info = f"Type={pkt[ICMP].type}"
                
        # ARP
        elif ARP in pkt:
            protocol = "ARP"
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            payload_info = f"Who has {pkt[ARP].pdst}? Tell {pkt[ARP].psrc}" if pkt[ARP].op == 1 else f"{pkt[ARP].psrc} is at {pkt[ARP].hwsrc}"
            
        return PacketEvent(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            length=len(pkt),
            flags=flags,
            payload_info=payload_info,
            raw_summary=pkt.summary()
        )
    
    def _interpret_tcp_flags(self, flags) -> str:
        """Convert TCP flags to readable string"""
        flag_str = str(flags)
        meanings = []
        
        if 'S' in flag_str and 'A' not in flag_str:
            meanings.append("SYN")
        if 'S' in flag_str and 'A' in flag_str:
            meanings.append("SYN-ACK")
        if 'F' in flag_str:
            meanings.append("FIN")
        if 'R' in flag_str:
            meanings.append("RST")
        if 'P' in flag_str:
            meanings.append("PSH")
        if 'A' in flag_str and 'S' not in flag_str:
            meanings.append("ACK")
            
        return "|".join(meanings) if meanings else flag_str


def get_sample_pcap() -> str:
    """Generate a sample PCAP for testing if user doesn't have one"""
    from scapy.all import wrpcap, Ether, IP, TCP, UDP, RandIP, RandMAC
    
    print("[*] Generating sample capture...")
    
    packets = []
    
    # Simulate a web browsing session
    for i in range(5):
        # HTTP request
        pkt = Ether(src=RandMAC(), dst=RandMAC()) / \
              IP(src="192.168.1.100", dst="93.184.216.34") / \
              TCP(sport=12345+i, dport=80, flags="S")
        packets.append(pkt)
        
        # HTTP response
        pkt = Ether(src=RandMAC(), dst=RandMAC()) / \
              IP(src="93.184.216.34", dst="192.168.1.100") / \
              TCP(sport=80, dport=12345+i, flags="SA")
        packets.append(pkt)
        
    # Add some "suspicious" scanning
    for port in [22, 23, 25, 80, 443, 3306]:
        pkt = Ether(src=RandMAC(), dst=RandMAC()) / \
              IP(src="192.168.1.200", dst="192.168.1.100") / \
              TCP(sport=54321, dport=port, flags="S")
        packets.append(pkt)
        
    sample_path = "/tmp/sample_capture.pcap"
    wrpcap(sample_path, packets)
    print(f"[+] Sample saved to {sample_path}")
    
    return sample_path
