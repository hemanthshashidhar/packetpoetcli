"""
Traffic Analyzer Module
Reconstructs flows, detects anomalies, builds narrative context
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional
from datetime import datetime, timedelta

from .reader import PacketEvent


@dataclass
class Flow:
    """A bidirectional communication flow"""
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    start_time: datetime
    end_time: datetime = field(default_factory=datetime.now)
    packet_count: int = 0
    byte_count: int = 0
    events: List[PacketEvent] = field(default_factory=list)
    state: str = "UNKNOWN"
    
    # Narrative enrichment
    service_guess: str = "unknown"
    suspicious: bool = False
    notes: List[str] = field(default_factory=list)
    
    @property
    def duration(self) -> timedelta:
        """Calculate flow duration"""
        try:
            return self.end_time - self.start_time
        except (TypeError, AttributeError):
            return timedelta(0)


@dataclass
class TrafficProfile:
    """Complete analysis of a packet capture"""
    total_packets: int
    duration: timedelta
    unique_hosts: Set[str]
    flows: List[Flow]
    anomalies: List[Dict]
    timeline: List[Dict]


class TrafficAnalyzer:
    """Analyzes packet events to build intelligence"""
    
    PORT_PERSONALITIES = {
        20: ("FTP-Data", "the file transfer channel"),
        21: ("FTP", "the old file messenger"),
        22: ("SSH", "the secure backdoor"),
        23: ("Telnet", "the ancient whisperer"),
        25: ("SMTP", "the letter carrier"),
        53: ("DNS", "the name keeper"),
        80: ("HTTP", "the public square"),
        110: ("POP3", "the mailbox"),
        143: ("IMAP", "the organized mailbox"),
        443: ("HTTPS", "the encrypted vault"),
        3306: ("MySQL", "the memory vault"),
        3389: ("RDP", "the remote window"),
        5432: ("PostgreSQL", "the elephant's memory"),
        8080: ("HTTP-Alt", "the alternate entrance"),
    }
    
    def __init__(self, events: List[PacketEvent]):
        self.events = sorted(events, key=lambda x: x.timestamp)
        self.flows: Dict[Tuple, Flow] = {}
        self.hosts: Set[str] = set()
        
    def analyze(self) -> TrafficProfile:
        """Main analysis pipeline"""
        if not self.events:
            return TrafficProfile(0, timedelta(0), set(), [], [], [])
            
        self._reconstruct_flows()
        self._identify_services()
        self._detect_anomalies()
        
        timeline = self._build_timeline()
        
        for flow in self.flows.values():
            self.hosts.add(flow.src_ip)
            self.hosts.add(flow.dst_ip)
            
        duration = self.events[-1].timestamp - self.events[0].timestamp
        
        return TrafficProfile(
            total_packets=len(self.events),
            duration=duration,
            unique_hosts=self.hosts,
            flows=list(self.flows.values()),
            anomalies=self._collect_anomalies(),
            timeline=timeline
        )
    
    def _reconstruct_flows(self):
        """Group packets into bidirectional flows"""
        for event in self.events:
            # Ensure ports are integers, default to 0 if None
            src_port = event.src_port if event.src_port is not None else 0
            dst_port = event.dst_port if event.dst_port is not None else 0
            
            if event.protocol in ["TCP", "UDP"]:
                key = tuple(sorted([
                    (event.src_ip, src_port),
                    (event.dst_ip, dst_port)
                ]) + [event.protocol])
            else:
                key = (event.src_ip, event.dst_ip, event.protocol)
                
            if key not in self.flows:
                self.flows[key] = Flow(
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    dst_port=dst_port,
                    protocol=event.protocol,
                    start_time=event.timestamp,
                    service_guess=self._guess_service(dst_port)
                )
                
            flow = self.flows[key]
            flow.events.append(event)
            flow.packet_count += 1
            flow.byte_count += event.length
            flow.end_time = event.timestamp
            
            if event.flags:
                if "SYN" in event.flags and "ACK" not in event.flags:
                    flow.state = "INITIATING"
                elif "SYN-ACK" in event.flags:
                    flow.state = "HANDSHAKING"
                elif "RST" in event.flags:
                    flow.state = "ABORTED"
                elif "FIN" in event.flags:
                    flow.state = "CLOSING"
                elif flow.state in ["HANDSHAKING", "ESTABLISHED"]:
                    flow.state = "ESTABLISHED"
    
    def _guess_service(self, port: int) -> str:
        """Guess service name from port"""
        if port in self.PORT_PERSONALITIES:
            return self.PORT_PERSONALITIES[port][0]
        elif port > 49152:
            return "Ephemeral"
        else:
            return f"Port-{port}"
    
    def _identify_services(self):
        """Add personality to flows based on ports"""
        for flow in self.flows.values():
            if flow.dst_port in self.PORT_PERSONALITIES:
                name, personality = self.PORT_PERSONALITIES[flow.dst_port]
                flow.notes.append(f"Speaking to {name}, {personality}")
    
    def _detect_anomalies(self):
        """Flag suspicious patterns"""
        # Port scanning detection
        src_to_ports = defaultdict(set)
        for flow in self.flows.values():
            src_to_ports[flow.src_ip].add(flow.dst_port)
            
        for src_ip, ports in src_to_ports.items():
            if len(ports) > 10:
                for flow in self.flows.values():
                    if flow.src_ip == src_ip:
                        flow.suspicious = True
                        flow.notes.append(f"Possible port scan: touched {len(ports)} ports")
                        
        # Unusual port combinations
        sensitive_ports = {22, 23, 3389, 3306, 5432}
        for flow in self.flows.values():
            if flow.dst_port in sensitive_ports:
                flow.notes.append("Accessing sensitive service")
                # Safe duration check
                try:
                    if flow.duration < timedelta(seconds=1):
                        flow.suspicious = True
                        flow.notes.append("Rapid connection attempt")
                except (TypeError, AttributeError):
                    pass
    
    def _build_timeline(self) -> List[Dict]:
        """Create chronological narrative events"""
        timeline = []
        
        for event in self.events[:50]:
            time_str = event.timestamp.strftime("%H:%M:%S")
            
            entry = {
                "time": time_str,
                "actor": self._get_actor_name(event.src_ip),
                "action": self._describe_action(event),
                "target": self._get_actor_name(event.dst_ip),
                "mood": self._determine_mood(event),
                "raw": event
            }
            timeline.append(entry)
            
        return timeline
    
    def _get_actor_name(self, ip: str) -> str:
        """Assign memorable names to IPs"""
        if ip.startswith("192.168.1."):
            hosts = {
                "192.168.1.1": "The Gateway",
                "192.168.1.100": "Alice",
                "192.168.1.101": "Bob", 
                "192.168.1.200": "The Stranger"
            }
            return hosts.get(ip, f"Host-{ip.split('.')[-1]}")
        elif ip.startswith("10."):
            return "The Insider"
        elif ip.startswith("93.184."):
            return "Example Corp"
        else:
            return f"Machine-{hash(ip) % 1000}"
    
    def _describe_action(self, event: PacketEvent) -> str:
        """Convert technical event to human action"""
        if event.protocol == "TCP":
            if event.flags and "SYN" in event.flags and "ACK" not in event.flags:
                return "knocked on the door of"
            elif event.flags and "SYN-ACK" in event.flags:
                return "answered the call from"
            elif event.flags and "RST" in event.flags:
                return "rejected"
            elif event.flags and "FIN" in event.flags:
                return "hung up on"
            else:
                return "spoke to"
        elif event.protocol == "UDP":
            return "shouted to"
        elif event.protocol == "ARP":
            return "asked about"
        elif event.protocol == "ICMP":
            return "pinged"
        else:
            return "contacted"
    
    def _determine_mood(self, event: PacketEvent) -> str:
        """Determine emotional tone of event"""
        # Safe port check
        dst_port = event.dst_port if event.dst_port is not None else 0
        
        if event.flags and "RST" in event.flags:
            return "tense"
        elif dst_port in [22, 23, 3389]:
            return "suspicious"
        elif event.protocol == "ARP":
            return "curious"
        elif "encrypted" in event.payload_info.lower():
            return "secretive"
        else:
            return "neutral"
    
    def _collect_anomalies(self) -> List[Dict]:
        """Collect all flagged anomalies"""
        anomalies = []
        for flow in self.flows.values():
            if flow.suspicious:
                anomalies.append({
                    "type": "suspicious_flow",
                    "source": flow.src_ip,
                    "target": f"{flow.dst_ip}:{flow.dst_port}",
                    "notes": flow.notes
                })
        return anomalies
