# 📡 PacketPoet

> *"Wireshark tells you what happened. We tell you the story."*

PacketPoet transforms sterile network captures into compelling narratives. It's a CLI tool that reads PCAP files (or live traffic) and outputs literary analysis of your network traffic—spy thrillers, cyberpunk logs, or technical reports.

No more scrolling through hex dumps. Understand your network like you're reading a novel.

---

## ✨ What It Does

| Feature | Description |
|---------|-------------|
| **🕵️ Spy Thriller** | James Bond meets Wireshark. "Alice knocked on the door of Example Corp..." |
| **🌆 Cyberpunk** | Neon-soaked dystopian logs. "BLACK ICE DETECTED. The Stranger is probing port 22..." |
| **📊 Technical** | Clean security reports with full flow analysis and anomaly detection |
| **🔴 Live Capture** | Sniff your interface in real-time with `sudo packetpoet capture` |
| **🎯 Interactive** | Choose your style after analysis—no re-scanning needed |

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/packetpoet.git
cd packetpoet

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install system dependencies (Scapy needs these)
sudo apt install tcpdump tshark
# Analyze a PCAP file with interactive menu
python3 main.py read capture.pcap

# Capture live traffic (50 packets from Wi-Fi)
sudo python3 main.py capture --interface wlan0 --count 50

# Direct to specific style
python3 main.py read capture.pcap --style cyberpunk

# Use Wireshark's engine with filters
sudo python3 main.py wireshark -i eth0 -f "tcp port 443"
🛠️ Commands
| Command                                                   | Description                              |
| --------------------------------------------------------- | ---------------------------------------- |
| `python3 main.py read file.pcap`                          | Analyze PCAP with interactive style menu |
| `python3 main.py read file.pcap --style spy`              | Direct output to specific style          |
| `sudo python3 main.py capture -i eth0 -c 100`             | Live capture 100 packets                 |
| `sudo python3 main.py capture -i wlan0 --save my.pcap`    | Capture and save to file                 |
| `sudo python3 main.py wireshark -i eth0 -f "tcp port 80"` | Use Wireshark's tshark engine            |
| `python3 main.py interfaces`                              | List available network interfaces        |
| `python3 main.py demo`                                    | Run with built-in sample data            |

🎨 Architecture
PCAP/Live Traffic → Scapy Parser → Flow Analyzer → Narrative Engine → Your Terminal
                         ↓                ↓                ↓
                    [reader.py]      [analyzer.py]    [narrator.py]
                         ↓                ↓                ↓
                   Extract IPs/    Reconstruct      Apply literary
                   Ports/Protocols  sessions         templates
