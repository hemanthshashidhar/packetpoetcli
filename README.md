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
| **🔌 Wireshark Plugin** | Native integration—click "Tools → PacketPoet" in Wireshark GUI |

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/hemanthshashidhar/packetpoet.git
cd packetpoet

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install system dependencies (Scapy needs these)
sudo apt install tcpdump tshark

Basic Usage (CLI)
# Analyze a PCAP file with interactive menu
python3 main.py read capture.pcap

# Capture live traffic (50 packets from Wi-Fi)
sudo python3 main.py capture --interface wlan0 --count 50

# Direct to specific style
python3 main.py read capture.pcap --style cyberpunk

# Use Wireshark's engine with filters
sudo python3 main.py wireshark -i eth0 -f "tcp port 443"

🔌 Wireshark Integration
PacketPoet integrates directly into Wireshark's GUI for seamless analysis.
Install Wireshark Plugin
# From project root
cd wireshark
./install.sh

Or manually:
# Copy plugin to Wireshark plugins folder
cp wireshark/packetpoet.lua ~/.local/lib/wireshark/plugins/

# Restart Wireshark
Using the Plugin

    Open Wireshark (restart if it was running during install)
    Capture traffic or open a PCAP file
    Go to Tools → PacketPoet and choose:
| Menu Item                    | What it does                                      |
| ---------------------------- | ------------------------------------------------- |
| **Quick Capture (3 sec)**    | Captures 3 seconds of live traffic, then narrates |
| **From File → Interactive**  | Analyze open file with style selection menu       |
| **From File → Spy Thriller** | Direct to spy narrative                           |
| **From File → Cyberpunk**    | Direct to cyberpunk narrative                     |
| **From File → Technical**    | Direct to technical report                        |


Plugin Features

    No terminal needed—click menu, see results
    Works with live captures—analyze what you just captured
    Works with saved files—analyze any open PCAP
    Preserves your analysis—doesn't modify original files

📖 Example Output
Cyberpunk Style
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
  NEURO-NETWORK // PACKET_DUMP // 0:02:34
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

[SYS] Jacking into the neural net...
[SYS] 4 nodes detected in the grid

<< NODE REGISTRY >>
  [192.168.1.100       ] :: ALICE
  [93.184.216.34       ] :: EXAMPLE CORP
  [192.168.1.200       ] :: THE STRANGER

[14.23.01] :: DATA FLOW    :: ALICE (192.168.1.100) >> KNOCKED ON THE DOOR OF >> EXAMPLE CORP (93.184.216.34) [TCP:443]
[14.23.02] :: ENCRYPTED    :: EXAMPLE CORP (93.184.216.34) >> ANSWERED THE CALL FROM >> ALICE (192.168.1.100) [TCP:443]

!!! BLACK ICE DETECTED !!!
[ALERT] 192.168.1.200 probing 192.168.1.100:22
          Indicators: Accessing sensitive service

🛠️ Commands
CLI Commands
| Command                                                   | Description                              |
| --------------------------------------------------------- | ---------------------------------------- |
| `python3 main.py read file.pcap`                          | Analyze PCAP with interactive style menu |
| `python3 main.py read file.pcap --style spy`              | Direct output to specific style          |
| `sudo python3 main.py capture -i eth0 -c 100`             | Live capture 100 packets                 |
| `sudo python3 main.py capture -i wlan0 --save my.pcap`    | Capture and save to file                 |
| `sudo python3 main.py wireshark -i eth0 -f "tcp port 80"` | Use Wireshark's tshark engine            |
| `python3 main.py interfaces`                              | List available network interfaces        |
| `python3 main.py demo`                                    | Run with built-in sample data            |


Wireshark Plugin Menus
Tools → PacketPoet:

    Quick Capture (3 sec) — Capture live traffic immediately
    From File → Interactive — Analyze with menu selection
    From File → [Style] — Direct to specific narrative

🎨 Architecture
PCAP/Live Traffic → Scapy Parser → Flow Analyzer → Narrative Engine → Your Terminal
                         ↓                ↓                ↓
                    [reader.py]      [analyzer.py]    [narrator.py]
                         ↓                ↓                ↓
                   Extract IPs/    Reconstruct      Apply literary
                   Ports/Protocols  sessions         templates
                         
Wireshark GUI → Lua Plugin → Calls CLI → Terminal Output
      ↓
   [Tools Menu] → [packetpoet.lua] → [main.py] → [Rich Terminal]

⚠️ Legal Notice
Only capture traffic on networks you own or have explicit permission to monitor. Unauthorized packet capture may violate privacy laws and computer fraud statutes.
🚧 Roadmap

    [x] Three narrative styles (Spy, Cyberpunk, Technical)
    [x] Live capture mode
    [x] Interactive style selection
    [x] Anomaly detection (port scans, rapid connections)
    [x] Wireshark GUI plugin (Tools menu integration)
    [ ] Export to HTML/PDF reports
    [ ] Custom user-defined templates
    [ ] Real-time dashboard mode
    [ ] Packet animation (Matrix-style rain)

