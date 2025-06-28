import sys
import os
import socket
import threading
import time
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import json
import platform
import subprocess
from collections import defaultdict, deque
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, ICMP
import psutil
import netifaces
import dpkt
from dpkt.compat import compat_ord
import ipaddress
import logging
from logging.handlers import RotatingFileHandler
import csv
import queue

# Constants
VERSION = "2.0.0"
THEMES = {
    "Dark": {"bg": "#121212", "fg": "#00ff00", "highlight": "#005500", "text_bg": "#222222"},
    "Light": {"bg": "#ffffff", "fg": "#000000", "highlight": "#e0e0e0", "text_bg": "#ffffff"}
}
CONFIG_FILE = "config.json"
LOG_FILE = "security_log.csv"
MAX_LOG_ENTRIES = 5000
MAX_PACKET_QUEUE = 1000
THRESHOLDS = {
    "dos": {"packets": 100, "time_window": 10},  # 100 packets in 10 seconds
    "ddos": {"packets": 500, "time_window": 10, "unique_ips": 20},
    "port_scan": {"ports": 20, "time_window": 30, "unique_ports": 15}
}
PACKET_TYPES = ["TCP", "UDP", "ICMP", "Other"]

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('monitor_debug.log', maxBytes=5*1024*1024, backupCount=2),
        logging.StreamHandler()
    ]
)

class PacketSniffer:
    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=MAX_PACKET_QUEUE)
        self.running = False
        self.sniffer_thread = None
        self.interface = self.detect_network_interface()
        self.monitored_ip = None
        
    def detect_network_interface(self):
        """Detect the primary network interface"""
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                if iface == 'lo':
                    continue
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    return iface
        except Exception as e:
            logging.error(f"Interface detection error: {e}")
        return None
    
    def start_sniffing(self, ip_address):
        """Start packet sniffing on the specified IP"""
        if self.running:
            return False
            
        self.monitored_ip = ip_address
        self.running = True
        self.sniffer_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.sniffer_thread.start()
        return True
    
    def stop_sniffing(self):
        """Stop packet sniffing"""
        self.running = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)
        return True
    
    def _sniff_packets(self):
        """Main packet sniffing loop"""
        try:
            sniff(
                prn=lambda x: self._process_packet(x),
                store=False,
                iface=self.interface,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logging.error(f"Sniffing error: {e}")
    
    def _process_packet(self, packet):
        """Process each captured packet"""
        if not self.running or self.packet_queue.full():
            return
            
        try:
            if IP in packet:
                ip_pkt = packet[IP]
                src_ip = ip_pkt.src
                dst_ip = ip_pkt.dst
                
                # Only monitor traffic to/from our target IP
                if self.monitored_ip not in (src_ip, dst_ip):
                    return
                
                # Get basic packet info
                packet_info = {
                    "timestamp": time.time(),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": None,
                    "src_port": None,
                    "dst_port": None,
                    "length": len(packet),
                    "flags": None
                }
                
                if TCP in packet:
                    tcp_pkt = packet[TCP]
                    packet_info["protocol"] = "TCP"
                    packet_info["src_port"] = tcp_pkt.sport
                    packet_info["dst_port"] = tcp_pkt.dport
                    packet_info["flags"] = self._get_tcp_flags(tcp_pkt.flags)
                elif UDP in packet:
                    udp_pkt = packet[UDP]
                    packet_info["protocol"] = "UDP"
                    packet_info["src_port"] = udp_pkt.sport
                    packet_info["dst_port"] = udp_pkt.dport
                elif ICMP in packet:
                    packet_info["protocol"] = "ICMP"
                else:
                    packet_info["protocol"] = "Other"
                
                self.packet_queue.put(packet_info)
        except Exception as e:
            logging.error(f"Packet processing error: {e}")
    
    def _get_tcp_flags(self, flags):
        """Convert TCP flags to human-readable format"""
        flag_names = []
        if flags & dpkt.tcp.TH_FIN:
            flag_names.append("FIN")
        if flags & dpkt.tcp.TH_SYN:
            flag_names.append("SYN")
        if flags & dpkt.tcp.TH_RST:
            flag_names.append("RST")
        if flags & dpkt.tcp.TH_PUSH:
            flag_names.append("PSH")
        if flags & dpkt.tcp.TH_ACK:
            flag_names.append("ACK")
        if flags & dpkt.tcp.TH_URG:
            flag_names.append("URG")
        return ",".join(flag_names) if flag_names else "None"
    
    def get_packets(self, max_packets=100):
        """Get packets from the queue"""
        packets = []
        while not self.packet_queue.empty() and len(packets) < max_packets:
            packets.append(self.packet_queue.get())
        return packets

class ThreatDetector:
    def __init__(self):
        self.packet_counts = defaultdict(int)
        self.ip_packet_counts = defaultdict(lambda: defaultdict(int))
        self.port_scan_counts = defaultdict(lambda: defaultdict(int))
        self.event_log = deque(maxlen=MAX_LOG_ENTRIES)
        
        # Statistics
        self.total_packets = 0
        self.dos_attempts = 0
        self.ddos_attempts = 0
        self.port_scans = 0
        self.start_time = datetime.now()
        
        # Protocol counts
        self.protocol_counts = defaultdict(int)
        
        # Packet history for rate calculations
        self.packet_history = deque(maxlen=1000)
        
    def analyze_packets(self, packets):
        """Analyze packets for threats"""
        for packet in packets:
            self._process_packet(packet)
    
    def _process_packet(self, packet):
        """Process a single packet"""
        self.total_packets += 1
        current_time = packet["timestamp"]
        src_ip = packet["src_ip"]
        
        # Count packets per protocol
        if packet["protocol"] in PACKET_TYPES:
            self.protocol_counts[packet["protocol"]] += 1
        else:
            self.protocol_counts["Other"] += 1
        
        # Count packets per source IP
        self.packet_counts[src_ip] += 1
        self.ip_packet_counts[src_ip][current_time] += 1
        
        # Add to packet history for rate calculation
        self.packet_history.append(current_time)
        
        # Check for DoS/DDoS
        self._check_dos_ddos(src_ip, current_time)
        
        # Check for port scanning
        if packet["dst_port"] is not None:
            self.port_scan_counts[src_ip][packet["dst_port"]] += 1
            self._check_port_scan(src_ip, current_time)
    
    def _check_dos_ddos(self, src_ip, current_time):
        """Check for DoS or DDoS attacks"""
        window_start = current_time - THRESHOLDS["dos"]["time_window"]
        
        # Calculate packets from this IP in time window
        packets_in_window = sum(
            count for timestamp, count in self.ip_packet_counts[src_ip].items() 
            if timestamp >= window_start
        )
        
        if packets_in_window >= THRESHOLDS["dos"]["packets"]:
            # Check if this is a DDoS (multiple source IPs)
            unique_ips = sum(
                1 for ip in self.ip_packet_counts 
                if any(t >= window_start for t, count in self.ip_packet_counts[ip].items())
            )
            
            if unique_ips >= THRESHOLDS["ddos"]["unique_ips"]:
                self.ddos_attempts += 1
                self.log_event(
                    "DDoS", 
                    f"DDoS detected from {unique_ips} IPs (including {src_ip})",
                    severity="High"
                )
            else:
                self.dos_attempts += 1
                self.log_event(
                    "DoS", 
                    f"DoS detected from {src_ip} ({packets_in_window} packets in {THRESHOLDS['dos']['time_window']}s)",
                    severity="Medium"
                )
    
    def _check_port_scan(self, src_ip, current_time):
        """Check for port scanning activity"""
        window_start = current_time - THRESHOLDS["port_scan"]["time_window"]
        
        # Count unique ports scanned in time window
        unique_ports = len([
            port for port, count in self.port_scan_counts[src_ip].items() 
            if count > 0  # In a real implementation, we'd check timestamps
        ])
        
        if unique_ports >= THRESHOLDS["port_scan"]["unique_ports"]:
            self.port_scans += 1
            self.log_event(
                "Port Scan", 
                f"Port scan detected from {src_ip} ({unique_ports} ports)",
                severity="Medium"
            )
    
    def log_event(self, event_type, message, severity="Low"):
        """Log a security event"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "type": event_type,
            "message": message,
            "severity": severity
        }
        self.event_log.append(log_entry)
        
        # Write to CSV file
        try:
            file_exists = os.path.isfile(LOG_FILE)
            with open(LOG_FILE, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=["timestamp", "type", "message", "severity"])
                if not file_exists:
                    writer.writeheader()
                writer.writerow(log_entry)
        except Exception as e:
            logging.error(f"Error writing to log file: {e}")
    
    def get_stats(self):
        """Get current statistics"""
        uptime = datetime.now() - self.start_time
        packet_rate = self._calculate_packet_rate()
        
        return {
            "uptime": str(uptime).split(".")[0],
            "total_packets": self.total_packets,
            "packet_rate": f"{packet_rate:.1f} pkt/s",
            "dos_attempts": self.dos_attempts,
            "ddos_attempts": self.ddos_attempts,
            "port_scans": self.port_scans,
            "protocol_counts": dict(self.protocol_counts),
            "recent_events": list(self.event_log)[-5:]
        }
    
    def _calculate_packet_rate(self):
        """Calculate current packet rate"""
        if len(self.packet_history) < 2:
            return 0.0
            
        time_window = self.packet_history[-1] - self.packet_history[0]
        if time_window <= 0:
            return 0.0
            
        return len(self.packet_history) / time_window
    
    def get_event_log(self, num_entries=20):
        """Get recent event log entries"""
        return list(self.event_log)[-num_entries:]
    
    def clear_stats(self):
        """Clear all statistics"""
        self.packet_counts.clear()
        self.ip_packet_counts.clear()
        self.port_scan_counts.clear()
        self.event_log.clear()
        self.protocol_counts.clear()
        self.packet_history.clear()
        
        self.total_packets = 0
        self.dos_attempts = 0
        self.ddos_attempts = 0
        self.port_scans = 0
        self.start_time = datetime.now()
        
        self.log_event("System", "Statistics cleared", "Info")

class DashboardApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Accurate Cyber Defense Cyber Drill TOOL 2025 v{VERSION}")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Initialize components
        self.sniffer = PacketSniffer()
        self.detector = ThreatDetector()
        self.current_theme = "Dark"
        self.config = self.load_config()
        
        # Setup UI
        self.setup_menu()
        self.setup_main_frame()
        self.setup_dashboard()
        self.setup_terminal()
        
        # Start periodic updates
        self.update_interval = 2000  # ms
        self.update_dashboard()
        
        # Start packet processing thread
        self.processing_thread = threading.Thread(target=self._process_packets, daemon=True)
        self.processing_thread.start()
    
    def load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r") as f:
                    return json.load(f)
        except Exception as e:
            logging.error(f"Config load error: {e}")
        return {"theme": "Dark", "recent_ips": []}
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(self.config, f)
        except Exception as e:
            logging.error(f"Config save error: {e}")
    
    def apply_theme(self):
        """Apply the current theme to the UI"""
        theme = THEMES[self.current_theme]
        style = ttk.Style()
        
        # Configure main window
        self.root.config(bg=theme["bg"])
        
        # Configure ttk styles
        style.theme_use('clam')
        style.configure('.', background=theme["bg"], foreground=theme["fg"])
        style.configure('TFrame', background=theme["bg"])
        style.configure('TLabel', background=theme["bg"], foreground=theme["fg"])
        style.configure('TButton', background=theme["highlight"], foreground=theme["fg"])
        style.configure('TEntry', fieldbackground=theme["text_bg"], foreground=theme["fg"])
        style.configure('TCombobox', fieldbackground=theme["text_bg"], foreground=theme["fg"])
        style.configure('TNotebook', background=theme["bg"])
        style.configure('TNotebook.Tab', background=theme["highlight"], foreground=theme["fg"])
        
        # Update text widgets
        self._update_widget_colors(self.root, theme)
    
    def _update_widget_colors(self, widget, theme):
        """Recursively update widget colors"""
        if isinstance(widget, (tk.Text, tk.Listbox, tk.Entry)):
            widget.config(
                bg=theme["text_bg"],
                fg=theme["fg"],
                insertbackground=theme["fg"],
                selectbackground=theme["highlight"],
                selectforeground=theme["fg"]
            )
        elif isinstance(widget, tk.Label):
            widget.config(bg=theme["bg"], fg=theme["fg"])
        elif isinstance(widget, tk.Frame):
            widget.config(bg=theme["bg"])
        
        for child in widget.winfo_children():
            self._update_widget_colors(child, theme)
    
    def setup_menu(self):
        """Setup the menu bar"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Data...", command=self.export_data)
        file_menu.add_command(label="Clear Data", command=self.clear_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Dark Theme", command=lambda: self.set_theme("Dark"))
        view_menu.add_command(label="Light Theme", command=lambda: self.set_theme("Light"))
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Ping Tool", command=self.show_ping_tool)
        tools_menu.add_command(label="Port Scanner", command=self.show_port_scanner)
        tools_menu.add_command(label="Packet Analyzer", command=self.show_packet_analyzer)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Detection Thresholds", command=self.show_threshold_settings)
        settings_menu.add_command(label="Network Interface", command=self.show_interface_settings)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def set_theme(self, theme_name):
        """Set the current theme"""
        self.current_theme = theme_name
        self.config["theme"] = theme_name
        self.save_config()
        self.apply_theme()
    
    def setup_main_frame(self):
        """Setup the main frame with paned windows"""
        self.main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.main_paned.pack(fill=tk.BOTH, expand=True)
        
        # Left pane (dashboard)
        self.left_frame = ttk.Frame(self.main_paned, width=800)
        self.main_paned.add(self.left_frame, weight=3)
        
        # Right pane (terminal)
        self.right_frame = ttk.Frame(self.main_paned, width=400)
        self.main_paned.add(self.right_frame, weight=1)
    
    def setup_dashboard(self):
        """Setup the dashboard components"""
        # Top controls
        control_frame = ttk.Frame(self.left_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Monitor IP:").pack(side=tk.LEFT)
        self.ip_entry = ttk.Entry(control_frame, width=20)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        
        self.start_btn = ttk.Button(control_frame, text="Start", command=self.start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)
        
        # Stats frame
        stats_frame = ttk.LabelFrame(self.left_frame, text="Statistics", padding=10)
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.stats_labels = {}
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.BOTH, expand=True)
        
        stats = [
            ("Uptime", "uptime"),
            ("Packet Rate", "packet_rate"),
            ("Monitored IP", "monitored_ip"),
            ("Network Interface", "interface"),
            ("Total Packets", "total_packets"),
            ("DoS Attempts", "dos_attempts"),
            ("DDoS Attempts", "ddos_attempts"),
            ("Port Scans", "port_scans")
        ]
        
        for i, (label, key) in enumerate(stats):
            ttk.Label(stats_grid, text=label+":").grid(row=i, column=0, sticky=tk.W, padx=5, pady=2)
            self.stats_labels[key] = ttk.Label(stats_grid, text="")
            self.stats_labels[key].grid(row=i, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Charts frame
        charts_frame = ttk.Frame(self.left_frame)
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Threat distribution pie chart
        self.pie_frame = ttk.Frame(charts_frame)
        self.pie_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Packet types bar chart
        self.bar_frame = ttk.Frame(charts_frame)
        self.bar_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Event log
        log_frame = ttk.LabelFrame(self.left_frame, text="Event Log", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame, wrap=tk.WORD, width=80, height=10,
            bg=THEMES[self.current_theme]["text_bg"],
            fg=THEMES[self.current_theme]["fg"]
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)
    
    def setup_terminal(self):
        """Setup the terminal emulator"""
        terminal_frame = ttk.LabelFrame(self.right_frame, text="Terminal", padding=10)
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.terminal_output = scrolledtext.ScrolledText(
            terminal_frame, wrap=tk.WORD, width=40, height=20,
            bg=THEMES[self.current_theme]["text_bg"],
            fg=THEMES[self.current_theme]["fg"]
        )
        self.terminal_output.pack(fill=tk.BOTH, expand=True)
        self.terminal_output.config(state=tk.DISABLED)
        
        input_frame = ttk.Frame(terminal_frame)
        input_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.terminal_input = ttk.Entry(input_frame)
        self.terminal_input.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.terminal_input.bind("<Return>", self.process_terminal_command)
        
        ttk.Button(input_frame, text="Send", command=self.process_terminal_command).pack(side=tk.LEFT, padx=5)
        
        # Add welcome message
        self.terminal_print("Advanced Cyber Security Monitor Terminal")
        self.terminal_print(f"Version {VERSION}")
        self.terminal_print("Type 'help' for available commands\n")
    
    def terminal_print(self, message):
        """Print a message to the terminal"""
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.insert(tk.END, message + "\n")
        self.terminal_output.config(state=tk.DISABLED)
        self.terminal_output.see(tk.END)
    
    def process_terminal_command(self, event=None):
        """Process a terminal command"""
        command = self.terminal_input.get().strip()
        self.terminal_input.delete(0, tk.END)
        
        if not command:
            return
            
        self.terminal_print(f"> {command}")
        
        # Process command
        cmd_parts = command.split()
        cmd = cmd_parts[0].lower()
        args = cmd_parts[1:]
        
        if cmd == "help":
            self.show_terminal_help()
        elif cmd == "exit":
            self.root.quit()
        elif cmd == "clear":
            self.clear_terminal()
        elif cmd == "ping":
            self.handle_ping_command(args)
        elif cmd == "start":
            self.handle_start_command(args)
        elif cmd == "stop":
            self.handle_stop_command()
        elif cmd == "stats":
            self.show_terminal_stats()
        elif cmd == "log":
            self.show_terminal_log()
        elif cmd == "export":
            self.handle_export_command(args)
        elif cmd == "ifconfig":
            self.show_interface_info()
        elif cmd == "scan":
            self.handle_scan_command(args)
        else:
            self.terminal_print(f"Unknown command: {cmd}. Type 'help' for available commands.")
    
    def show_terminal_help(self):
        """Show help in terminal"""
        help_text = """\nAvailable commands:
help - Show this help message
exit - Close the application
clear - Clear the terminal
ping <ip> - Ping an IP address
start <ip> - Start monitoring an IP
stop - Stop monitoring
stats - Show current statistics
log - Show recent events
export <filename> - Export data to file
ifconfig - Show network interface info
scan <ip> [start_port] [end_port] - Port scan"""
        self.terminal_print(help_text)
    
    def clear_terminal(self):
        """Clear the terminal"""
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.delete(1.0, tk.END)
        self.terminal_output.config(state=tk.DISABLED)
    
    def handle_ping_command(self, args):
        """Handle ping command in terminal"""
        if len(args) >= 1:
            self.ping_ip(args[0])
        else:
            self.terminal_print("Usage: ping <ip_address>")
    
    def handle_start_command(self, args):
        """Handle start command in terminal"""
        if len(args) >= 1:
            self.start_monitoring(args[0])
        else:
            self.terminal_print("Usage: start <ip_address>")
    
    def handle_stop_command(self):
        """Handle stop command in terminal"""
        self.stop_monitoring()
    
    def show_terminal_stats(self):
        """Show statistics in terminal"""
        stats = self.detector.get_stats()
        self.terminal_print("\nCurrent Statistics:")
        for key, value in stats.items():
            if key not in ["protocol_counts", "recent_events"]:
                self.terminal_print(f"{key.replace('_', ' ').title()}: {value}")
        
        self.terminal_print("\nProtocol Distribution:")
        for proto, count in stats["protocol_counts"].items():
            self.terminal_print(f"{proto}: {count}")
    
    def show_terminal_log(self):
        """Show event log in terminal"""
        events = self.detector.get_event_log(10)
        self.terminal_print("\nRecent Events:")
        for event in events:
            self.terminal_print(f"[{event['timestamp']}] {event['type']}: {event['message']}")
    
    def handle_export_command(self, args):
        """Handle export command in terminal"""
        filename = args[0] if args else "security_data.txt"
        self.export_data(filename)
        self.terminal_print(f"Data exported to {filename}")
    
    def show_interface_info(self):
        """Show network interface info in terminal"""
        iface = self.sniffer.interface
        self.terminal_print(f"\nNetwork Interface: {iface}")
        
        try:
            if iface:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    self.terminal_print(f"IP Address: {ip_info.get('addr', 'Unknown')}")
                    self.terminal_print(f"Netmask: {ip_info.get('netmask', 'Unknown')}")
                    self.terminal_print(f"Broadcast: {ip_info.get('broadcast', 'Unknown')}")
        except Exception as e:
            self.terminal_print(f"Error getting interface info: {str(e)}")
    
    def handle_scan_command(self, args):
        """Handle port scan command in terminal"""
        if len(args) < 1:
            self.terminal_print("Usage: scan <ip> [start_port] [end_port]")
            return
            
        ip = args[0]
        try:
            start_port = int(args[1]) if len(args) > 1 else 1
            end_port = int(args[2]) if len(args) > 2 else 100
        except ValueError:
            self.terminal_print("Ports must be numbers")
            return
            
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            self.terminal_print("Invalid port range (1-65535)")
            return
            
        self.terminal_print(f"\nScanning {ip} ports {start_port}-{end_port}...")
        
        # Run scan in background thread
        threading.Thread(
            target=self._run_terminal_scan,
            args=(ip, start_port, end_port),
            daemon=True
        ).start()
    
    def _run_terminal_scan(self, ip, start_port, end_port):
        """Run a port scan and show results in terminal"""
        open_ports = []
        for port in range(start_port, end_port + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                        self.terminal_print(f"Port {port} is open")
            except:
                pass
        
        if open_ports:
            self.terminal_print(f"\nScan complete. Open ports: {', '.join(map(str, open_ports))}")
        else:
            self.terminal_print("\nScan complete. No open ports found.")
    
    def ping_ip(self, ip_address):
        """Ping an IP address and show results in terminal"""
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            count = "4"
            command = ["ping", param, count, ip_address]
            
            self.terminal_print(f"\nPinging {ip_address}...")
            
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
            
            if output:
                self.terminal_print(output.decode('utf-8', errors='ignore'))
            if error:
                self.terminal_print(error.decode('utf-8', errors='ignore'))
        except Exception as e:
            self.terminal_print(f"Ping error: {str(e)}")
    
    def start_monitoring(self, ip_address=None):
        """Start monitoring an IP address"""
        ip = ip_address or self.ip_entry.get()
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address to monitor")
            return
            
        try:
            # Validate IP address
            ipaddress.ip_address(ip)
        except ValueError:
            messagebox.showerror("Error", "Invalid IP address format")
            return
            
        if self.sniffer.start_sniffing(ip):
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.ip_entry.config(state=tk.DISABLED)
            self.terminal_print(f"Started monitoring IP: {ip}")
            self.detector.log_event("System", f"Started monitoring IP: {ip}", "Info")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        if self.sniffer.stop_sniffing():
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.ip_entry.config(state=tk.NORMAL)
            self.terminal_print("Stopped monitoring")
            self.detector.log_event("System", "Stopped monitoring", "Info")
    
    def _process_packets(self):
        """Background thread to process packets"""
        while True:
            if not self.sniffer.running:
                time.sleep(1)
                continue
                
            packets = self.sniffer.get_packets()
            if packets:
                self.detector.analyze_packets(packets)
            else:
                time.sleep(0.1)
    
    def update_dashboard(self):
        """Update the dashboard with current statistics"""
        stats = self.detector.get_stats()
        
        # Update stats labels
        for key, label in self.stats_labels.items():
            if key in stats:
                label.config(text=str(stats[key]))
        
        # Update event log
        events = self.detector.get_event_log(20)
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        
        for event in events:
            self.log_text.insert(tk.END, f"[{event['timestamp']}] {event['type']}: {event['message']}\n")
        
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)
        
        # Update charts
        self.update_charts()
        
        # Schedule next update
        self.root.after(self.update_interval, self.update_dashboard)
    
    def update_charts(self):
        """Update the charts with current data"""
        # Clear existing charts
        for widget in self.pie_frame.winfo_children():
            widget.destroy()
        for widget in self.bar_frame.winfo_children():
            widget.destroy()
        
        stats = self.detector.get_stats()
        
        # Create threat distribution pie chart
        fig1 = plt.Figure(figsize=(5, 4), dpi=80)
        ax1 = fig1.add_subplot(111)
        
        threats = ["DoS", "DDoS", "Port Scans"]
        counts = [
            self.detector.dos_attempts,
            self.detector.ddos_attempts,
            self.detector.port_scans
        ]
        
        # Only show pie chart if we have data
        if sum(counts) > 0:
            ax1.pie(counts, labels=threats, autopct='%1.1f%%', shadow=True)
            ax1.set_title('Threat Distribution')
            
            canvas1 = FigureCanvasTkAgg(fig1, master=self.pie_frame)
            canvas1.draw()
            canvas1.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Create protocol distribution bar chart
        fig2 = plt.Figure(figsize=(5, 4), dpi=80)
        ax2 = fig2.add_subplot(111)
        
        protocols = list(stats["protocol_counts"].keys())
        counts = list(stats["protocol_counts"].values())
        
        if protocols and counts:
            ax2.bar(protocols, counts)
            ax2.set_title('Protocol Distribution')
            ax2.set_ylabel('Count')
            
            canvas2 = FigureCanvasTkAgg(fig2, master=self.bar_frame)
            canvas2.draw()
            canvas2.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def export_data(self, filename=None):
        """Export data to a file"""
        if not filename:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("CSV Files", "*.csv"), ("All Files", "*.*")]
            )
            if not filename:
                return
        
        try:
            if filename.endswith('.csv'):
                self._export_csv(filename)
            else:
                self._export_text(filename)
            
            messagebox.showinfo("Success", f"Data exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export data: {str(e)}")
    
    def _export_text(self, filename):
        """Export data as text"""
        with open(filename, "w") as f:
            # Write statistics
            stats = self.detector.get_stats()
            f.write("=== Cyber Security Monitor Data Export ===\n\n")
            f.write("Statistics:\n")
            for key, value in stats.items():
                if key not in ["protocol_counts", "recent_events"]:
                    f.write(f"{key.replace('_', ' ').title()}: {value}\n")
            
            # Write protocol distribution
            f.write("\nProtocol Distribution:\n")
            for proto, count in stats["protocol_counts"].items():
                f.write(f"{proto}: {count}\n")
            
            # Write event log
            f.write("\nEvent Log:\n")
            for event in self.detector.get_event_log():
                f.write(f"[{event['timestamp']}] {event['type']}: {event['message']}\n")
    
    def _export_csv(self, filename):
        """Export data as CSV"""
        with open(filename, "w", newline='') as f:
            writer = csv.writer(f)
            
            # Write statistics header
            writer.writerow(["Statistic", "Value"])
            
            # Write statistics
            stats = self.detector.get_stats()
            for key, value in stats.items():
                if key not in ["protocol_counts", "recent_events"]:
                    writer.writerow([key.replace('_', ' ').title(), value])
            
            # Write protocol distribution
            writer.writerow([])
            writer.writerow(["Protocol", "Count"])
            for proto, count in stats["protocol_counts"].items():
                writer.writerow([proto, count])
            
            # Write event log
            writer.writerow([])
            writer.writerow(["Timestamp", "Type", "Message", "Severity"])
            for event in self.detector.get_event_log():
                writer.writerow([event['timestamp'], event['type'], event['message'], event['severity']])
    
    def clear_data(self):
        """Clear all collected data"""
        if messagebox.askyesno("Confirm", "Clear all collected data?"):
            self.detector.clear_stats()
            self.terminal_print("All data cleared")
    
    def show_ping_tool(self):
        """Show a ping utility dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Ping Utility")
        dialog.geometry("400x300")
        
        frame = ttk.Frame(dialog, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="IP Address/Hostname:").pack(pady=5)
        ip_entry = ttk.Entry(frame)
        ip_entry.pack(fill=tk.X, pady=5)
        
        output_text = scrolledtext.ScrolledText(
            frame, wrap=tk.WORD, width=40, height=10,
            bg=THEMES[self.current_theme]["text_bg"],
            fg=THEMES[self.current_theme]["fg"]
        )
        output_text.pack(fill=tk.BOTH, expand=True, pady=5)
        output_text.config(state=tk.DISABLED)
        
        def do_ping():
            ip = ip_entry.get()
            if not ip:
                messagebox.showerror("Error", "Please enter an IP address or hostname")
                return
                
            output_text.config(state=tk.NORMAL)
            output_text.insert(tk.END, f"Pinging {ip}...\n")
            output_text.config(state=tk.DISABLED)
            
            try:
                param = "-n" if platform.system().lower() == "windows" else "-c"
                count = "4"
                command = ["ping", param, count, ip]
                
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = process.communicate()
                
                output_text.config(state=tk.NORMAL)
                if output:
                    output_text.insert(tk.END, output.decode('utf-8', errors='ignore') + "\n")
                if error:
                    output_text.insert(tk.END, error.decode('utf-8', errors='ignore') + "\n")
                output_text.config(state=tk.DISABLED)
                output_text.see(tk.END)
            except Exception as e:
                output_text.config(state=tk.NORMAL)
                output_text.insert(tk.END, f"Error: {str(e)}\n")
                output_text.config(state=tk.DISABLED)
                output_text.see(tk.END)
        
        ttk.Button(frame, text="Ping", command=do_ping).pack(pady=5)
    
    def show_port_scanner(self):
        """Show a port scanner utility dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Port Scanner")
        dialog.geometry("500x400")
        
        frame = ttk.Frame(dialog, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="IP Address:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ip_entry = ttk.Entry(frame)
        ip_entry.grid(row=0, column=1, sticky=tk.EW, pady=5)
        
        ttk.Label(frame, text="Start Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        start_port = ttk.Entry(frame, width=8)
        start_port.grid(row=1, column=1, sticky=tk.W, pady=5)
        start_port.insert(0, "1")
        
        ttk.Label(frame, text="End Port:").grid(row=2, column=0, sticky=tk.W, pady=5)
        end_port = ttk.Entry(frame, width=8)
        end_port.grid(row=2, column=1, sticky=tk.W, pady=5)
        end_port.insert(0, "100")
        
        output_text = scrolledtext.ScrolledText(
            frame, wrap=tk.WORD, width=50, height=15,
            bg=THEMES[self.current_theme]["text_bg"],
            fg=THEMES[self.current_theme]["fg"]
        )
        output_text.grid(row=3, column=0, columnspan=2, sticky=tk.NSEW, pady=5)
        output_text.config(state=tk.DISABLED)
        
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(3, weight=1)
        
        def scan_ports():
            ip = ip_entry.get()
            try:
                start = int(start_port.get())
                end = int(end_port.get())
                
                if start < 1 or end > 65535 or start > end:
                    messagebox.showerror("Error", "Invalid port range (1-65535)")
                    return
            except ValueError:
                messagebox.showerror("Error", "Ports must be numbers")
                return
                
            if not ip:
                messagebox.showerror("Error", "Please enter an IP address")
                return
                
            output_text.config(state=tk.NORMAL)
            output_text.insert(tk.END, f"Scanning {ip} ports {start}-{end}...\n")
            output_text.config(state=tk.DISABLED)
            output_text.see(tk.END)
            
            # Run scan in a separate thread to avoid freezing the UI
            def worker():
                try:
                    open_ports = []
                    for port in range(start, end + 1):
                        try:
                            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                                s.settimeout(0.5)
                                result = s.connect_ex((ip, port))
                                if result == 0:
                                    open_ports.append(port)
                                    output_text.config(state=tk.NORMAL)
                                    output_text.insert(tk.END, f"Port {port} is open\n")
                                    output_text.config(state=tk.DISABLED)
                                    output_text.see(tk.END)
                        except:
                            pass
                    
                    output_text.config(state=tk.NORMAL)
                    if open_ports:
                        output_text.insert(tk.END, f"\nScan complete. Open ports: {', '.join(map(str, open_ports))}\n")
                    else:
                        output_text.insert(tk.END, "\nScan complete. No open ports found.\n")
                    output_text.config(state=tk.DISABLED)
                    output_text.see(tk.END)
                except Exception as e:
                    output_text.config(state=tk.NORMAL)
                    output_text.insert(tk.END, f"Error: {str(e)}\n")
                    output_text.config(state=tk.DISABLED)
                    output_text.see(tk.END)
            
            threading.Thread(target=worker, daemon=True).start()
        
        ttk.Button(frame, text="Scan Ports", command=scan_ports).grid(row=4, column=0, columnspan=2, pady=5)
    
    def show_packet_analyzer(self):
        """Show a packet analyzer dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Packet Analyzer")
        dialog.geometry("600x500")
        
        frame = ttk.Frame(dialog, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Filter controls
        filter_frame = ttk.Frame(frame)
        filter_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
        self.packet_filter = ttk.Combobox(filter_frame, values=["All", "TCP", "UDP", "ICMP", "Other"])
        self.packet_filter.set("All")
        self.packet_filter.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(filter_frame, text="Refresh", command=self.refresh_packets).pack(side=tk.LEFT)
        
        # Packet list
        columns = ("timestamp", "src_ip", "dst_ip", "protocol", "length")
        self.packet_tree = ttk.Treeview(
            frame, columns=columns, show="headings", selectmode="browse"
        )
        
        for col in columns:
            self.packet_tree.heading(col, text=col.replace("_", " ").title())
            self.packet_tree.column(col, width=100, anchor=tk.W)
        
        self.packet_tree.column("timestamp", width=150)
        self.packet_tree.column("src_ip", width=120)
        self.packet_tree.column("dst_ip", width=120)
        
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=scrollbar.set)
        
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Packet details
        details_frame = ttk.LabelFrame(frame, text="Packet Details", padding=5)
        details_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.packet_details = scrolledtext.ScrolledText(
            details_frame, wrap=tk.WORD, width=80, height=10,
            bg=THEMES[self.current_theme]["text_bg"],
            fg=THEMES[self.current_theme]["fg"]
        )
        self.packet_details.pack(fill=tk.BOTH, expand=True)
        self.packet_details.config(state=tk.DISABLED)
        
        # Load initial packets
        self.refresh_packets()
        
        # Bind selection event
        self.packet_tree.bind("<<TreeviewSelect>>", self.show_packet_detail)
    
    def refresh_packets(self):
        """Refresh the packet list"""
        packets = self.sniffer.packet_queue.queue if hasattr(self.sniffer.packet_queue, 'queue') else []
        filter_proto = self.packet_filter.get()
        
        self.packet_tree.delete(*self.packet_tree.get_children())
        
        for packet in packets:
            if filter_proto == "All" or packet["protocol"] == filter_proto:
                timestamp = datetime.fromtimestamp(packet["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                self.packet_tree.insert("", "end", values=(
                    timestamp,
                    packet["src_ip"],
                    packet["dst_ip"],
                    packet["protocol"],
                    packet["length"]
                ))
    
    def show_packet_detail(self, event):
        """Show details of the selected packet"""
        selected = self.packet_tree.focus()
        if not selected:
            return
            
        item = self.packet_tree.item(selected)
        values = item["values"]
        
        self.packet_details.config(state=tk.NORMAL)
        self.packet_details.delete(1.0, tk.END)
        
        # Find the actual packet data
        packets = list(self.sniffer.packet_queue.queue)
        for packet in packets:
            timestamp = datetime.fromtimestamp(packet["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            if (timestamp == values[0] and 
                packet["src_ip"] == values[1] and 
                packet["dst_ip"] == values[2] and 
                packet["protocol"] == values[3] and 
                str(packet["length"]) == str(values[4])):
                
                self.packet_details.insert(tk.END, f"Timestamp: {timestamp}\n")
                self.packet_details.insert(tk.END, f"Source IP: {packet['src_ip']}\n")
                self.packet_details.insert(tk.END, f"Destination IP: {packet['dst_ip']}\n")
                self.packet_details.insert(tk.END, f"Protocol: {packet['protocol']}\n")
                self.packet_details.insert(tk.END, f"Length: {packet['length']} bytes\n")
                
                if packet["src_port"]:
                    self.packet_details.insert(tk.END, f"Source Port: {packet['src_port']}\n")
                if packet["dst_port"]:
                    self.packet_details.insert(tk.END, f"Destination Port: {packet['dst_port']}\n")
                if packet["flags"]:
                    self.packet_details.insert(tk.END, f"TCP Flags: {packet['flags']}\n")
                
                break
        
        self.packet_details.config(state=tk.DISABLED)
    
    def show_threshold_settings(self):
        """Show threshold settings dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Detection Thresholds")
        dialog.geometry("400x300")
        
        frame = ttk.Frame(dialog, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # DoS Threshold
        ttk.Label(frame, text="DoS Threshold (packets/time window):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.dos_packets = ttk.Entry(frame, width=5)
        self.dos_packets.grid(row=0, column=1, sticky=tk.W, pady=5)
        self.dos_packets.insert(0, str(THRESHOLDS["dos"]["packets"]))
        
        ttk.Label(frame, text="packets in").grid(row=0, column=2, sticky=tk.W, pady=5)
        self.dos_window = ttk.Entry(frame, width=5)
        self.dos_window.grid(row=0, column=3, sticky=tk.W, pady=5)
        self.dos_window.insert(0, str(THRESHOLDS["dos"]["time_window"]))
        ttk.Label(frame, text="seconds").grid(row=0, column=4, sticky=tk.W, pady=5)
        
        # DDoS Threshold
        ttk.Label(frame, text="DDoS Threshold (unique IPs):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.ddos_ips = ttk.Entry(frame, width=5)
        self.ddos_ips.grid(row=1, column=1, sticky=tk.W, pady=5)
        self.ddos_ips.insert(0, str(THRESHOLDS["ddos"]["unique_ips"]))
        
        # Port Scan Threshold
        ttk.Label(frame, text="Port Scan Threshold (ports/time window):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.ps_ports = ttk.Entry(frame, width=5)
        self.ps_ports.grid(row=2, column=1, sticky=tk.W, pady=5)
        self.ps_ports.insert(0, str(THRESHOLDS["port_scan"]["unique_ports"]))
        
        ttk.Label(frame, text="ports in").grid(row=2, column=2, sticky=tk.W, pady=5)
        self.ps_window = ttk.Entry(frame, width=5)
        self.ps_window.grid(row=2, column=3, sticky=tk.W, pady=5)
        self.ps_window.insert(0, str(THRESHOLDS["port_scan"]["time_window"]))
        ttk.Label(frame, text="seconds").grid(row=2, column=4, sticky=tk.W, pady=5)
        
        # Save button
        ttk.Button(frame, text="Save", command=lambda: self.save_thresholds(dialog)).grid(row=3, column=0, columnspan=5, pady=10)
    
    def save_thresholds(self, dialog):
        """Save threshold settings"""
        try:
            THRESHOLDS["dos"]["packets"] = int(self.dos_packets.get())
            THRESHOLDS["dos"]["time_window"] = int(self.dos_window.get())
            THRESHOLDS["ddos"]["unique_ips"] = int(self.ddos_ips.get())
            THRESHOLDS["port_scan"]["unique_ports"] = int(self.ps_ports.get())
            THRESHOLDS["port_scan"]["time_window"] = int(self.ps_window.get())
            
            dialog.destroy()
            messagebox.showinfo("Success", "Threshold settings saved")
        except ValueError:
            messagebox.showerror("Error", "All values must be integers")
    
    def show_interface_settings(self):
        """Show network interface settings dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Network Interface Settings")
        dialog.geometry("400x200")
        
        frame = ttk.Frame(dialog, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Get available interfaces
        interfaces = []
        try:
            interfaces = netifaces.interfaces()
            interfaces = [iface for iface in interfaces if iface != 'lo']
        except:
            pass
        
        ttk.Label(frame, text="Network Interface:").pack(pady=5)
        
        self.interface_var = tk.StringVar()
        self.interface_var.set(self.sniffer.interface or "")
        
        if interfaces:
            interface_menu = ttk.Combobox(frame, textvariable=self.interface_var, values=interfaces)
            interface_menu.pack(fill=tk.X, pady=5)
        else:
            ttk.Label(frame, text="No interfaces found").pack(pady=5)
        
        ttk.Button(frame, text="Save", command=lambda: self.save_interface(dialog)).pack(pady=10)
    
    def save_interface(self, dialog):
        """Save interface settings"""
        new_interface = self.interface_var.get()
        if new_interface and new_interface != self.sniffer.interface:
            was_running = self.sniffer.running
            monitored_ip = self.sniffer.monitored_ip
            
            if was_running:
                self.sniffer.stop_sniffing()
            
            self.sniffer.interface = new_interface
            
            if was_running:
                self.sniffer.start_sniffing(monitored_ip)
            
            dialog.destroy()
            messagebox.showinfo("Success", "Interface settings saved")
        else:
            dialog.destroy()
    
    def show_documentation(self):
        """Show documentation"""
        doc_text = """Advanced Cyber Security Monitor

This tool provides real-time monitoring of network traffic for various cyber threats including:
- Denial of Service (DoS) attacks
- Distributed Denial of Service (DDoS) attacks
- Port scanning activity

Features:
- Real-time traffic analysis
- Threat detection and alerting
- Statistical visualization
- Built-in terminal with commands
- Ping and port scanning tools
- Packet analyzer
- Configurable detection thresholds
- Data export capability

Usage:
1. Enter the IP address you want to monitor
2. Click Start to begin monitoring
3. View detected threats in the event log
4. Use the terminal for advanced commands
"""
        messagebox.showinfo("Documentation", doc_text)
    
    def show_about(self):
        """Show about dialog"""
        about_text = f"""Advanced Cyber Security Monitor v{VERSION}
Author:Ian Carter Kulani
Email:iancarterkulani@gmail.com
Phone:+265(0)988061969

A comprehensive network security monitoring tool designed to detect and analyze various cyber threats in real-time.

Features:
- DoS/DDoS detection
- Port scan detection
- Real-time monitoring
- Data visualization
- Command terminal
- Tools for network diagnostics

Developed with Python and Tkinter
"""
        messagebox.showinfo("About", about_text)

def main():
    root = tk.Tk()
    app = DashboardApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()