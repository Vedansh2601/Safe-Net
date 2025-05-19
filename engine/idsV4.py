from scapy.all import sniff, IP, TCP, get_if_list
import datetime
import os
import json
import sys
import threading
import time
import signal
from collections import defaultdict, deque
from colorama import Fore, Style, init as colorama_init

# Initialize colorama for colored terminal output
colorama_init()

# Add engine directory to sys.path to resolve import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from engine.rules import load_rules
except ImportError as e:
    print(f"{Fore.RED}Error importing rules: {e}{Style.RESET_ALL}")
    sys.exit(1)

# Constants
LOG_DIR = os.path.join(os.path.dirname(__file__), '../logs')
LOG_FILE = os.path.join(LOG_DIR, 'alerts.json')
BLOCKED_IPS_FILE = os.path.join(os.path.dirname(__file__), 'blocked_ips.json')
DECAY_INTERVAL = 10
LOG_INTERVAL = 5
BEHAVIOR_WINDOW = 10  # Seconds
PACKET_RATE_THRESHOLD = 50
DIVERSITY_THRESHOLD = 10

# Global state
running = False
syn_tracker = {
    'syn_flood': {},
    'port_scan': {},
    'icmp_flood': {},
    'udp_flood': {},
    'tcp_rst_flood': {},
    'ack_scan': {},
    'syn_ack_scan': {},
    'xmas_scan': {}
}
blocked_ips = set()
packet_count = 0
packet_lock = threading.Lock()
recent_activity = defaultdict(lambda: deque(maxlen=100))  # {ip: deque of (timestamp, dst_port)}

def signal_handler(sig, frame):
    print(f"{Fore.YELLOW}[-] Received SIGTERM, stopping IDS...{Style.RESET_ALL}")
    stop_sniffing()
    sys.exit(0)

def initialize_logs():
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w') as f:
            json.dump([], f)

def update_blocked_ips_file():
    with open(BLOCKED_IPS_FILE, 'w') as f:
        json.dump(sorted(list(blocked_ips)), f, indent=4)

def update_blocked_ips():
    global blocked_ips
    while True:
        if os.path.exists(BLOCKED_IPS_FILE):
            try:
                with open(BLOCKED_IPS_FILE, 'r') as f:
                    blocked_ips_data = json.load(f)
                    blocked_ips = set(blocked_ips_data) if isinstance(blocked_ips_data, list) else set()
            except json.JSONDecodeError:
                print(f"{Fore.RED}[!] Error parsing blocked_ips.json. Resetting to empty set.{Style.RESET_ALL}")
                blocked_ips = set()
        time.sleep(5)

def log_alert(ip, count, rule_type="Anomalous Behavior"):
    if ip in blocked_ips:
        return

    blocked_ips.add(ip)
    update_blocked_ips_file()

    alert = {
        "timestamp": datetime.datetime.now().isoformat(),
        "type": rule_type,
        "ip": ip,
        "count": count
    }

    try:
        with open(LOG_FILE, 'r') as f:
            logs = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        logs = []

    logs.append(alert)
    with open(LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=4)

    alert_msg = (
        f"{Fore.RED}[!!!] BEHAVIOR ALERT!{Style.RESET_ALL}\n"
        f"{Fore.YELLOW}├─ Type   : {rule_type}\n"
        f"├─ Source : {ip}\n"
        f"└─ Events : {count}\n{Style.RESET_ALL}"
    )
    print(alert_msg)

def log_packet_stats():
    global packet_count
    while running:
        time.sleep(LOG_INTERVAL)
        with packet_lock:
            current_count = packet_count
            packet_count = 0
        with open(LOG_FILE, 'r') as f:
            try:
                logs = json.load(f)
                recent_alerts = logs[-10:]
            except (json.JSONDecodeError, KeyError):
                recent_alerts = []
        print(f"{Fore.BLUE}[STATS] Packets in last {LOG_INTERVAL}s: {current_count}, Alerts: {len(recent_alerts)}{Style.RESET_ALL}")

def analyze_behavior(ip, dst_port):
    now = time.time()
    recent_activity[ip].append((now, dst_port))
    timestamps = [t for t, _ in recent_activity[ip] if now - t <= BEHAVIOR_WINDOW]
    ports = {port for t, port in recent_activity[ip] if now - t <= BEHAVIOR_WINDOW}

    if len(timestamps) > PACKET_RATE_THRESHOLD or len(ports) > DIVERSITY_THRESHOLD:
        log_alert(ip, len(timestamps), "Suspicious Behavior: Rate or Port Diversity")

def detect_packet(pkt):
    if not running:
        return

    if IP in pkt:
        with packet_lock:
            global packet_count
            packet_count += 1

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        pkt_len = len(pkt)

        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"PROTO-{proto}")
        print(f"{datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]} IP {src_ip} -> {dst_ip} [{proto_name}] | Size: {pkt_len} bytes | Total: {packet_count}")

        if src_ip in blocked_ips:
            return

        dst_port = None
        if TCP in pkt:
            dst_port = pkt[TCP].dport
        elif hasattr(pkt, 'dport'):
            dst_port = pkt.dport

        if dst_port:
            analyze_behavior(src_ip, dst_port)

        for rule_func in load_rules():
            rule_func(pkt, log_alert, syn_tracker, {})

def start_sniffing():
    global running
    running = True
    print(f"{Fore.CYAN}[+] Starting IDS... analyzing behavioral patterns across all interfaces...{Style.RESET_ALL}")

    threading.Thread(target=update_blocked_ips, daemon=True).start()
    threading.Thread(target=log_packet_stats, daemon=True).start()

    interfaces = get_if_list()
    try:
        sniff(iface=interfaces, filter="ip", prn=detect_packet, store=0)
    except Exception as e:
        print(f"{Fore.RED}[-] Sniffing error: {e}{Style.RESET_ALL}")
    finally:
        running = False
        syn_tracker.clear()

def stop_sniffing():
    global running
    running = False
    print(f"{Fore.YELLOW}[-] IDS stopped.{Style.RESET_ALL}")

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, signal_handler)
    initialize_logs()
    start_sniffing()
