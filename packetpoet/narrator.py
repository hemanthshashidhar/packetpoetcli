"""
Narrator Module
Generates literary output from traffic analysis
"""

from typing import List, Dict
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

from .analyzer import TrafficProfile, Flow


class PacketNarrator:
    """Converts traffic profiles into literature"""
    
    def __init__(self, style: str = "spy"):
        self.style = style
        self.console = Console()
        
    def narrate(self, profile: TrafficProfile) -> str:
        """Main entry: generate complete narrative"""
        if self.style == "spy":
            return self._spy_thriller(profile)
        elif self.style == "technical":
            return self._technical_report(profile)
        elif self.style == "cyberpunk":
            return self._cyberpunk_chronicle(profile)
        else:
            return self._default_narrative(profile)
    
    def _spy_thriller(self, profile: TrafficProfile) -> str:
        """James Bond meets Wireshark - now with technical details"""
        lines = []
        
        # Title
        lines.append("\n")
        lines.append("═" * 70)
        lines.append("  THE NETWORK DOSSIER: Operation Packet Storm")
        lines.append("  Classification: EYES ONLY")
        lines.append(f"  Surveillance Period: {profile.duration}")
        lines.append("═" * 70)
        lines.append("")
        
        # Prologue
        lines.append("The digital city never sleeps. In the shadows of the subnet,")
        lines.append(f"{len(profile.unique_hosts)} entities moved unseen... until now.")
        lines.append("")
        
        # The Players (with real IPs)
        lines.append("─" * 70)
        lines.append("ACTORS IN THIS DRAMA (True Identities)")
        lines.append("─" * 70)
        
        for host in sorted(profile.unique_hosts):
            role = self._assign_role(host)
            lines.append(f"  • {host:20} | Codename: {role}")
        lines.append("")
        
        # The Timeline with technical details
        lines.append("─" * 70)
        lines.append("CHRONOLOGY OF EVENTS")
        lines.append("─" * 70)
        
        for event in profile.timeline[:20]:
            mood = event["mood"]
            emoji = {"tense": "⚠️", "suspicious": "🕵️", "curious": "🔍", 
                     "secretive": "🔒", "neutral": "📡"}[mood]
            
            # Enhanced with technical details
            raw = event["raw"]
            proto_detail = raw.protocol
            if raw.dst_port:
                proto_detail += f":{raw.dst_port}"
            
            line = (f"{emoji} [{event['time']}] {event['actor']} ({raw.src_ip}) "
                   f"{event['action']} {event['target']} ({raw.dst_ip}) "
                   f"via [{proto_detail}]")
            lines.append(line)
            
        lines.append("")
        
        # Flow Summary with technical details
        lines.append("─" * 70)
        lines.append("COMMUNICATION CHANNELS ANALYZED")
        lines.append("─" * 70)
        
        for flow in sorted(profile.flows, key=lambda x: x.packet_count, reverse=True)[:10]:
            duration = flow.duration.total_seconds()
            lines.append(f"  Channel: {flow.src_ip} ↔ {flow.dst_ip}:{flow.dst_port}")
            lines.append(f"     Protocol: {flow.protocol} | Packets: {flow.packet_count} | "
                        f"Duration: {duration:.2f}s | State: {flow.state}")
            if flow.notes:
                lines.append(f"     Notes: {'; '.join(flow.notes)}")
            lines.append("")
        
        # Suspicious Activity
        if profile.anomalies:
            lines.append("!" * 70)
            lines.append("⚠️  SUSPICIOUS ACTIVITY DETECTED")
            lines.append("!" * 70)
            for anomaly in profile.anomalies:
                lines.append(f"  🚨 {anomaly['source']} → {anomaly['target']}")
                for note in anomaly['notes']:
                    lines.append(f"      Intel: {note}")
            lines.append("")
        
        # Epilogue
        lines.append("─" * 70)
        lines.append("FINAL ASSESSMENT")
        lines.append("─" * 70)
        lines.append(f"Total communications intercepted: {profile.total_packets}")
        lines.append(f"Duration of surveillance: {profile.duration}")
        lines.append(f"Suspicious flows flagged: {len(profile.anomalies)}")
        lines.append(f"Unique actors identified: {len(profile.unique_hosts)}")
        lines.append("")
        lines.append("End of Dossier. Burn after reading.")
        lines.append("═" * 70)
        
        return "\n".join(lines)
    
    def _technical_report(self, profile: TrafficProfile) -> str:
        """Standard security report with full technical details"""
        lines = []
        
        lines.append("=" * 80)
        lines.append("NETWORK TRAFFIC ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: PacketPoet v0.1.0")
        lines.append(f"Duration:  {profile.duration}")
        lines.append(f"Packets:   {profile.total_packets}")
        lines.append(f"Hosts:     {len(profile.unique_hosts)}")
        lines.append("")
        
        # Host inventory
        lines.append("-" * 80)
        lines.append("HOST INVENTORY")
        lines.append("-" * 80)
        for host in sorted(profile.unique_hosts):
            role = self._assign_role(host)
            lines.append(f"  {host:20} {role}")
        lines.append("")
        
        # Flow table with full details
        lines.append("-" * 80)
        lines.append("FLOW ANALYSIS")
        lines.append("-" * 80)
        lines.append(f"{'Source':<20} {'Destination':<25} {'Proto':<6} {'Pkts':<6} "
                    f"{'Bytes':<8} {'Duration':<10} {'State':<12}")
        lines.append("-" * 80)
        
        for flow in sorted(profile.flows, key=lambda x: x.start_time):
            src = f"{flow.src_ip}"
            dst = f"{flow.dst_ip}:{flow.dst_port}"
            duration = f"{flow.duration.total_seconds():.2f}s"
            lines.append(f"{src:<20} {dst:<25} {flow.protocol:<6} "
                        f"{flow.packet_count:<6} {flow.byte_count:<8} "
                        f"{duration:<10} {flow.state:<12}")
            
        # Detailed notes
        lines.append("")
        lines.append("-" * 80)
        lines.append("FLOW NOTES")
        lines.append("-" * 80)
        for flow in profile.flows:
            if flow.notes:
                lines.append(f"{flow.src_ip} → {flow.dst_ip}:{flow.dst_port}:")
                for note in flow.notes:
                    lines.append(f"  • {note}")
                lines.append("")
            
        if profile.anomalies:
            lines.append("")
            lines.append("!" * 80)
            lines.append("ANOMALIES DETECTED")
            lines.append("!" * 80)
            for anomaly in profile.anomalies:
                lines.append(f"[!] {anomaly['type'].upper()}")
                lines.append(f"    Source: {anomaly['source']}")
                lines.append(f"    Target: {anomaly['target']}")
                lines.append("    Indicators:")
                for note in anomaly['notes']:
                    lines.append(f"      - {note}")
                lines.append("")
                
        return "\n".join(lines)
    
    def _cyberpunk_chronicle(self, profile: TrafficProfile) -> str:
        """Neon-soaked dystopian network log with full technical overlay"""
        lines = []
        
        lines.append("")
        lines.append("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
        lines.append("  NEURO-NETWORK // PACKET_DUMP // " + str(profile.duration))
        lines.append("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
        lines.append("")
        lines.append("[SYS] Jacking into the neural net...")
        lines.append(f"[SYS] {len(profile.unique_hosts)} nodes detected in the grid")
        lines.append("[SYS] Mapping subnet topology...")
        lines.append("")
        
        # Node registry
        lines.append("<< NODE REGISTRY >>")
        for host in sorted(profile.unique_hosts):
            role = self._assign_role(host).upper()
            lines.append(f"  [{host:20}] :: {role}")
        lines.append("")
        
        # Live feed with full technical details
        lines.append("<< LIVE NEURAL FEED >>")
        
        for event in profile.timeline[:15]:
            time = event["time"].replace(":", ".")
            actor = event["actor"].upper()
            target = event["target"].upper()
            action = event["action"].upper()
            
            # Get raw technical details
            raw = event["raw"]
            src_ip = raw.src_ip
            dst_ip = raw.dst_ip
            proto = raw.protocol
            
            # Cyberpunk color coding
            mood_colors = {
                "tense": "RED ALERT",
                "suspicious": "BLACK ICE", 
                "curious": "SCANNING",
                "secretive": "ENCRYPTED",
                "neutral": "DATA FLOW"
            }
            status = mood_colors.get(event["mood"], "UNKNOWN")
            
            # Enhanced line with IPs and protocol
            if raw.dst_port:
                proto_full = f"{proto}:{raw.dst_port}"
            else:
                proto_full = proto
                
            lines.append(f"[{time}] :: {status:12} :: {actor} ({src_ip}) >> {action} >> {target} ({dst_ip}) [{proto_full}]")
            
        # Flow analysis
        lines.append("")
        lines.append("<< CONNECTION MATRIX >>")
        for flow in sorted(profile.flows, key=lambda x: x.packet_count, reverse=True)[:5]:
            duration = flow.duration.total_seconds()
            lines.append(f"  {flow.src_ip:20} <-> {flow.dst_ip:20}:{flow.dst_port:<5} "
                        f"| {flow.protocol} | {flow.packet_count} packets | {duration:.2f}s")
            
        if profile.anomalies:
            lines.append("")
            lines.append("!!! BLACK ICE DETECTED !!!")
            lines.append("!!! COUNTER-INTRUSION MEASURES ADVISED !!!")
            for anomaly in profile.anomalies:
                lines.append(f"  [ALERT] {anomaly['source']} probing {anomaly['target']}")
                lines.append(f"          Indicators: {', '.join(anomaly['notes'][:2])}")
                
        lines.append("")
        lines.append("[SYS] Neural link terminated")
        lines.append("[SYS] Trace cleared")
        lines.append("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
        
        return "\n".join(lines)
    
    def _default_narrative(self, profile: TrafficProfile) -> str:
        """Simple default output"""
        return self._technical_report(profile)
    
    def _assign_role(self, ip: str) -> str:
        """Assign spy roles to IPs"""
        roles = {
            "192.168.1.1": "The Handler (Gateway)",
            "192.168.1.100": "Agent Alice (Workstation)",
            "192.168.1.101": "Agent Bob (Workstation)",
            "192.168.1.200": "The Shadow (Attacker?)",
            "93.184.216.34": "The Foreign Contact (Internet)"
        }
        return roles.get(ip, "Unknown Operative")
    
    def print_rich(self, text: str):
        """Print with Rich formatting"""
        self.console.print(text)


class StoryTemplate:
    """For custom narrative templates"""
    
    def __init__(self, name: str, opening: str, closing: str, 
                 event_template: str, anomaly_template: str):
        self.name = name
        self.opening = opening
        self.closing = closing
        self.event_template = event_template
        self.anomaly_template = anomaly_template
