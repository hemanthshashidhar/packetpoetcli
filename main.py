#!/usr/bin/env python3
"""
PacketPoet - Network Traffic as Literature
Main CLI entry point
"""

import click
import sys
import subprocess
import tempfile
import os
from pathlib import Path

# Add package to path
sys.path.insert(0, str(Path(__file__).parent))

from packetpoet.reader import PacketReader, get_sample_pcap
from packetpoet.analyzer import TrafficAnalyzer
from packetpoet.narrator import PacketNarrator


def interactive_style_menu(profile):
    """Show interactive menu to choose narrative style"""
    print("\n" + "="*60)
    print("PACKETPOET ANALYSIS COMPLETE")
    print("="*60)
    print(f"Packets analyzed: {profile.total_packets}")
    print(f"Unique hosts: {len(profile.unique_hosts)}")
    print(f"Duration: {profile.duration}")
    print(f"Anomalies detected: {len(profile.anomalies)}")
    print("="*60)
    
    while True:
        print("\nChoose your narrative style:")
        print("  [1] SPY THRILLER - James Bond meets Wireshark")
        print("  [2] CYBERPUNK - Neon-soaked dystopian log")
        print("  [3] TECHNICAL - Standard security report")
        print("  [4] Show ALL styles (one by one)")
        print("  [5] Save to file (choose format)")
        print("  [q] Quit")
        
        choice = input("\nEnter choice (1-5 or q): ").strip().lower()
        
        if choice == '1':
            print("\n" + "="*60)
            print("GENERATING SPY THRILLER NARRATIVE...")
            print("="*60)
            narrator = PacketNarrator(style='spy')
            story = narrator.narrate(profile)
            narrator.print_rich(story)
            
        elif choice == '2':
            print("\n" + "="*60)
            print("GENERATING CYBERPUNK CHRONICLE...")
            print("="*60)
            narrator = PacketNarrator(style='cyberpunk')
            story = narrator.narrate(profile)
            narrator.print_rich(story)
            
        elif choice == '3':
            print("\n" + "="*60)
            print("GENERATING TECHNICAL REPORT...")
            print("="*60)
            narrator = PacketNarrator(style='technical')
            story = narrator.narrate(profile)
            narrator.print_rich(story)
            
        elif choice == '4':
            for style in ['spy', 'cyberpunk', 'technical']:
                print("\n" + "="*60)
                print(f"STYLE: {style.upper()}")
                print("="*60)
                narrator = PacketNarrator(style=style)
                story = narrator.narrate(profile)
                narrator.print_rich(story)
                input("\nPress Enter to continue...")
                
        elif choice == '5':
            filename = input("Enter filename (e.g., report.txt): ").strip()
            if filename:
                style = input("Which style? (spy/cyberpunk/technical): ").strip() or 'technical'
                narrator = PacketNarrator(style=style)
                story = narrator.narrate(profile)
                with open(filename, 'w') as f:
                    f.write(story)
                print(f"[+] Saved to {filename}")
                
        elif choice == 'q':
            print("[*] Goodbye!")
            break


@click.group()
@click.version_option(version="0.1.0", prog_name="packetpoet")
def cli():
    """PacketPoet - Turn network captures into stories"""
    pass


@cli.command()
@click.argument('pcap_file', required=False)
@click.option('--style', '-s', 
              type=click.Choice(['spy', 'technical', 'cyberpunk', 'interactive'], case_sensitive=False),
              default='interactive',
              help='Narrative style (default: interactive menu)')
@click.option('--output', '-o', 
              type=click.Path(),
              help='Output file (default: stdout)')
@click.option('--sample', 
              is_flag=True,
              help='Generate and analyze sample capture')
def read(pcap_file, style, output, sample):
    """Read a PCAP file and generate narrative"""
    
    # Handle sample generation
    if sample or not pcap_file:
        if not pcap_file:
            click.echo("[!] No PCAP file provided. Generating sample...")
        pcap_file = get_sample_pcap()
    
    # Validate file
    pcap_path = Path(pcap_file)
    if not pcap_path.exists():
        click.echo(f"[!] Error: File not found: {pcap_file}")
        sys.exit(1)
    
    # Read packets
    reader = PacketReader(str(pcap_path))
    events = reader.read()
    
    if not events:
        click.echo("[!] No packets found in capture")
        sys.exit(1)
    
    # Analyze
    click.echo(f"[*] Analyzing traffic patterns...")
    try:
        analyzer = TrafficAnalyzer(events)
        profile = analyzer.analyze()
    except Exception as e:
        click.echo(f"[!] Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # Output handling
    if output:
        # File output mode
        click.echo(f"[*] Generating {style} narrative...")
        narrator = PacketNarrator(style=style if style != 'interactive' else 'technical')
        story = narrator.narrate(profile)
        with open(output, 'w') as f:
            f.write(story)
        click.echo(f"[+] Story saved to {output}")
    elif style == 'interactive':
        # Interactive menu mode
        interactive_style_menu(profile)
    else:
        # Direct style output
        click.echo(f"[*] Generating {style} narrative...")
        narrator = PacketNarrator(style=style)
        story = narrator.narrate(profile)
        click.echo("\n")
        narrator.print_rich(story)


@cli.command()
@click.option('--interface', '-i', 
              default='eth0',
              help='Network interface to capture (default: eth0)')
@click.option('--count', '-c', 
              default=50,
              help='Number of packets to capture (default: 50)')
@click.option('--timeout', '-t',
              default=30,
              help='Capture timeout in seconds (default: 30)')
@click.option('--style', '-s', 
              type=click.Choice(['spy', 'technical', 'cyberpunk', 'interactive'], case_sensitive=False),
              default='interactive',
              help='Narrative style')
@click.option('--save', '-S',
              type=click.Path(),
              help='Save captured PCAP to file for later analysis')
def capture(interface, count, timeout, style, save):
    """Capture live traffic and narrate (requires sudo)"""
    
    # Check if running as root
    if os.geteuid() != 0:
        click.echo("[!] Live capture requires root privileges.")
        click.echo(f"[*] Run with: sudo python3 {sys.argv[0]} capture --interface {interface}")
        sys.exit(1)
    
    # Check if tcpdump is installed
    if not subprocess.run(['which', 'tcpdump'], capture_output=True).returncode == 0:
        click.echo("[!] tcpdump not found. Installing...")
        subprocess.run(['apt', 'install', '-y', 'tcpdump'], check=True)
    
    # Validate interface
    result = subprocess.run(['ip', 'link', 'show', interface], capture_output=True)
    if result.returncode != 0:
        click.echo(f"[!] Interface {interface} not found.")
        click.echo("[*] Available interfaces:")
        subprocess.run(['ip', '-br', 'link', 'show'])
        sys.exit(1)
    
    click.echo(f"[*] Starting capture on {interface}...")
    click.echo(f"[*] Will capture {count} packets or wait {timeout} seconds")
    click.echo("[*] Press Ctrl+C to stop early")
    click.echo("")
    
    # Create temp file for capture
    if save:
        pcap_path = Path(save)
    else:
        tmp = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
        pcap_path = Path(tmp.name)
        tmp.close()
    
    try:
        # Run tcpdump
        cmd = [
            'tcpdump', 
            '-i', interface,
            '-c', str(count),
            '-w', str(pcap_path)
        ]
        
        # Add timeout if supported
        try:
            result = subprocess.run(['tcpdump', '--help'], capture_output=True, text=True)
            if '-G' in result.stdout:
                cmd.extend(['-G', str(timeout), '-W', '1'])
        except:
            pass
        
        click.echo(f"[*] Running: {' '.join(cmd)}")
        
        # Run capture with real-time output
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Show progress
        try:
            while process.poll() is None:
                import time
                time.sleep(0.5)
                if pcap_path.exists():
                    size = pcap_path.stat().st_size
                    print(f"\r[*] Capturing... {size} bytes captured", end='', flush=True)
        except KeyboardInterrupt:
            click.echo("\n[*] Stopping capture...")
            process.terminate()
            process.wait()
            
        click.echo(f"\n[+] Capture saved to {pcap_path}")
        click.echo(f"[+] Captured {count} packets")
        
        # Now analyze it
        click.echo("[*] Analyzing captured traffic...")
        read.callback(str(pcap_path), style, None, False)
        
    except Exception as e:
        click.echo(f"[!] Capture failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup temp file if not saving
        if not save and pcap_path.exists():
            try:
                pcap_path.unlink(missing_ok=True)
                click.echo(f"[*] Cleaned up temp file")
            except:
                pass


@cli.command()
def interfaces():
    """List available network interfaces"""
    click.echo("[*] Available network interfaces:")
    click.echo("")
    
    result = subprocess.run(['ip', '-br', 'link', 'show'], capture_output=True, text=True)
    lines = result.stdout.strip().split('\n')
    
    for line in lines:
        parts = line.split()
        if len(parts) >= 2:
            iface = parts[0]
            state = parts[1]
            click.echo(f"  {iface:10} - {state}")
            
    click.echo("")
    click.echo("Common interfaces:")
    click.echo("  eth0     - Wired Ethernet connection")
    click.echo("  wlan0    - Wi-Fi connection")
    click.echo("  lo       - Loopback (localhost only)")
    click.echo("  any      - All interfaces combined")


@cli.command()
def demo():
    """Run with built-in sample data and interactive menu"""
    click.echo("=" * 60)
    click.echo("PacketPoet Demo Mode")
    click.echo("=" * 60)
    click.echo("")
    
    # Generate sample
    pcap_file = get_sample_pcap()
    
    # Analyze and show interactive menu
    read.callback(pcap_file, 'interactive', None, False)


if __name__ == '__main__':
    cli()
