from scapy.all import sniff, IP, TCP, get_if_list
import datetime
import os
import json
import sys
import threading
import time
import signal
from collections import defaultdict, deque
from statistics import mean, stdev
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
FLOW_LOG_FILE = os.path.join(LOG_DIR, 'flow_logs.json')
BLOCKED_IPS_FILE = os.path.join(os.path.dirname(__file__), 'blocked_ips.json')
DECAY_INTERVAL = 10
LOG_INTERVAL = 5
BEHAVIOR_WINDOW = 10  # Seconds
PACKET_RATE_THRESHOLD = 50
DIVERSITY_THRESHOLD = 10
FLOW_TIMEOUT = 60

# Global state
running = False
packet_count = 0
packet_lock = threading.Lock()
syn_tracker = defaultdict(dict)
blocked_ips = set()
recent_activity = defaultdict(lambda: deque(maxlen=100))
flows = {}

class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}_{protocol}"
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = time.time()
        self.last_seen = self.start_time
        self.fwd_packets = []
        self.bwd_packets = []

    def update(self, pkt, direction):
        self.last_seen = time.time()
        pkt_len = len(pkt)
        timestamp = time.time()
        if direction == 'fwd':
            self.fwd_packets.append((timestamp, pkt_len))
        else:
            self.bwd_packets.append((timestamp, pkt_len))

    def to_dict(self):
        duration = self.last_seen - self.start_time
        fwd_lengths = [l for _, l in self.fwd_packets]
        bwd_lengths = [l for _, l in self.bwd_packets]
        return {
            "Flow ID": self.flow_id,
            "Source IP": self.src_ip,
            "Destination IP": self.dst_ip,
            "Source Port": self.src_port,
            "Destination Port": self.dst_port,
            "Protocol": self.protocol,
            "Timestamp": datetime.datetime.fromtimestamp(self.start_time).isoformat(),
            "Flow Duration": int(duration * 1e6),
            "Total Fwd Packets": len(self.fwd_packets),
            "Total Backward Packets": len(self.bwd_packets),
            "Total Length of Fwd Packets": sum(fwd_lengths),
            "Total Length of Bwd Packets": sum(bwd_lengths),
            "Fwd Packet Length Mean": mean(fwd_lengths) if fwd_lengths else 0,
            "Fwd Packet Length Std": stdev(fwd_lengths) if len(fwd_lengths) > 1 else 0,
            "Bwd Packet Length Mean": mean(bwd_lengths) if bwd_lengths else 0,
            "Bwd Packet Length Std": stdev(bwd_lengths) if len(bwd_lengths) > 1 else 0
        }

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
        print(f"{Fore.YELLOW}[!] IP {ip} is already blocked. Skipping...{Style.RESET_ALL}")
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
        f"[+] IP 192.168.1.105 has been added to blocked list and written to file."
    )
    print(alert_msg)
    print(f"{Fore.RED}[!!!] ALERT: {rule_type} from {ip} ({count} events){Style.RESET_ALL}")

def log_packet_stats():
    global packet_count
    while running:
        time.sleep(LOG_INTERVAL)
        with packet_lock:
            current_count = packet_count
            packet_count = 0
        print(f"{Fore.BLUE}[STATS] Packets in last {LOG_INTERVAL}s: {current_count}{Style.RESET_ALL}")

def analyze_behavior(ip, dst_port):
    now = time.time()
    recent_activity[ip].append((now, dst_port))
    timestamps = [t for t, _ in recent_activity[ip] if now - t <= BEHAVIOR_WINDOW]
    ports = {port for t, port in recent_activity[ip] if now - t <= BEHAVIOR_WINDOW}
    if len(timestamps) > PACKET_RATE_THRESHOLD or len(ports) > DIVERSITY_THRESHOLD:
        log_alert(ip, len(timestamps), "Suspicious Behavior: Rate or Port Diversity")

def export_flows():
    while running:
        current_time = time.time()
        expired = []
        for key, flow in list(flows.items()):
            if current_time - flow.last_seen > FLOW_TIMEOUT:
                with open(FLOW_LOG_FILE, 'a') as f:
                    json.dump(flow.to_dict(), f)
                    f.write('\n')
                expired.append(key)
        for key in expired:
            del flows[key]
        time.sleep(10)

# def detect_packet(pkt):
#     if not running:
#         return
#     if IP in pkt:
#         with packet_lock:
#             global packet_count
#             packet_count += 1
#         src_ip = pkt[IP].src
#         dst_ip = pkt[IP].dst
#         proto = pkt[IP].proto
#         if src_ip in blocked_ips:
#             return
#         if TCP in pkt:
#             src_port = pkt[TCP].sport
#             dst_port = pkt[TCP].dport
#         elif hasattr(pkt, 'sport') and hasattr(pkt, 'dport'):
#             src_port = pkt.sport
#             dst_port = pkt.dport
#         else:
#             return
#         key = (src_ip, dst_ip, src_port, dst_port, proto)
#         rev_key = (dst_ip, src_ip, dst_port, src_port, proto)
#         direction = 'fwd' if key in flows else 'bwd' if rev_key in flows else 'fwd'
#         flow_key = key if direction == 'fwd' else rev_key
#         if flow_key not in flows:
#             flows[flow_key] = Flow(*flow_key)
#         flows[flow_key].update(pkt, direction)
#         analyze_behavior(src_ip, dst_port)
#         for rule_func in load_rules():
#             rule_func(pkt, log_alert, syn_tracker, {})



def detect_packet(pkt):
    if not running:
        return

    if IP in pkt:
        with packet_lock:
            global packet_count
            packet_count += 1

        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        ttl = pkt[IP].ttl
        size = len(pkt)

        # Protocol Name
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"PROTO-{proto}")

        # TCP Flags if available
        flags = ""
        if TCP in pkt:
            tcp_flags = pkt[TCP].flags
            flags = str(tcp_flags)

        # Colored output
        print(f"{Fore.GREEN}[{timestamp}]{Style.RESET_ALL} "
              f"{Fore.CYAN}{src_ip}{Style.RESET_ALL} → {Fore.MAGENTA}{dst_ip}{Style.RESET_ALL} "
              f"{Fore.YELLOW}[{proto_name}]{Style.RESET_ALL} "
              f"{Fore.BLUE}Flags: {flags}{Style.RESET_ALL} | "
              f"{Fore.LIGHTYELLOW_EX}Size: {size}B{Style.RESET_ALL} | "
              f"{Fore.LIGHTGREEN_EX}TTL: {ttl}{Style.RESET_ALL} | "
              f"{Fore.LIGHTRED_EX}Pkt #: {packet_count}{Style.RESET_ALL}")

        # Flow and behavioral logic remains
        if src_ip in blocked_ips:
            return

        dst_port = None
        src_port = None

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif hasattr(pkt, 'sport') and hasattr(pkt, 'dport'):
            src_port = pkt.sport
            dst_port = pkt.dport

        if src_port and dst_port:
            key = (src_ip, dst_ip, src_port, dst_port, proto)
            rev_key = (dst_ip, src_ip, dst_port, src_port, proto)
            direction = 'fwd' if key in flows else 'bwd' if rev_key in flows else 'fwd'
            flow_key = key if direction == 'fwd' else rev_key
            if flow_key not in flows:
                flows[flow_key] = Flow(*flow_key)
            flows[flow_key].update(pkt, direction)

        if dst_port:
            analyze_behavior(src_ip, dst_port)

        for rule_func in load_rules():
            rule_func(pkt, log_alert, syn_tracker, {})

def start_sniffing():
    global running
    running = True
    print(f"{Fore.CYAN}[+] Starting IDS...{Style.RESET_ALL}")
    threading.Thread(target=update_blocked_ips, daemon=True).start()
    threading.Thread(target=log_packet_stats, daemon=True).start()
    threading.Thread(target=export_flows, daemon=True).start()
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
