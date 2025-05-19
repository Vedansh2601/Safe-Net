from scapy.all import sniff, IP, TCP , get_if_list
import datetime
import os
import json
import statistics
import sys
import threading
import time
import signal
from collections import defaultdict, deque
from colorama import Fore, Style, init as colorama_init
from flow_logger import write_flow_to_log ,update_flow, flush_old_flows
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

# --- FLOW TRACKING ADDITION ---
import csv
from collections import defaultdict

FLOW_TIMEOUT = 5  # seconds to consider a flow inactive
FLOW_LOG_FILE = os.path.join(LOG_DIR, 'flows_log.csv')
flows = {}

def flush_old_flows():
    now = time.time()
    flushed = []
    for flow_key, flow_data in list(flows.items()):
        if now - flow_data['Last Seen'] > FLOW_TIMEOUT:
            write_flow_to_log(flow_data)
            flushed.append(flow_key)
    for key in flushed:
        del flows[key]

# def flush_old_flows():
#     now = time.time()
#     flushed = []
#     for flow_key, flow_data in list(flows.items()):
#         if now - flow_data['Last Seen'] > FLOW_TIMEOUT:
#             write_flow_to_log(flow_data)
#             flushed.append(flow_key)
#     for key in flushed:
#         del flows[key]  # cleanup

def write_flow_to_log(flow):
    os.makedirs(LOG_DIR, exist_ok=True)
    header = list(flow.keys())
    file_exists = os.path.isfile(FLOW_LOG_FILE)
    with open(FLOW_LOG_FILE, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=header)
        if not file_exists:
            writer.writeheader()
        writer.writerow(flow)

# def write_flow_to_log(flow):
#     fwd_stats = stats(flow['Fwd Packet Lengths'])
#     bwd_stats = stats(flow['Bwd Packet Lengths'])
#     iat_stats = stats(flow['Flow IATs'])

#     row = {
#         'Flow ID': flow['Flow ID'],
#         'Source IP': flow['Source IP'],
#         'Source Port': flow['Source Port'],
#         'Destination IP': flow['Destination IP'],
#         'Destination Port': flow['Destination Port'],
#         'Protocol': flow['Protocol'],
#         'Timestamp': datetime.datetime.fromtimestamp(flow['Timestamp']).isoformat(),
#         'Flow Duration': round(flow['Flow Duration'], 2),

#         'Total Fwd Packets': flow['Total Fwd Packets'],
#         'Total Backward Packets': flow['Total Backward Packets'],
#         'Total Length of Fwd Packets': flow['Total Length of Fwd Packets'],
#         'Total Length of Bwd Packets': flow['Total Length of Bwd Packets'],

#         'Fwd Packet Max': fwd_stats['Max'],
#         'Fwd Packet Min': fwd_stats['Min'],
#         'Fwd Packet Mean': fwd_stats['Mean'],
#         'Fwd Packet Std': fwd_stats['Std'],
#         'Bwd Packet Max': bwd_stats['Max'],
#         'Bwd Packet Min': bwd_stats['Min'],
#         'Bwd Packet Mean': bwd_stats['Mean'],
#         'Bwd Packet Std': bwd_stats['Std'],

#         'Flow Bytes/s': flow['Flow Bytes/s'],
#         'Flow Packets/s': flow['Flow Packets/s'],
#         'Flow IAT Mean': iat_stats['Mean'],
#         'Flow IAT Std': iat_stats['Std'],
#         'Flow IAT Max': iat_stats['Max'],
#         'Flow IAT Min': iat_stats['Min'],

#         'Fwd PSH Flags': flow['Fwd PSH Flags'],
#         'Bwd PSH Flags': flow['Bwd PSH Flags'],
#         'Fwd URG Flags': flow['Fwd URG Flags'],
#         'Bwd URG Flags': flow['Bwd URG Flags'],
#         'FIN Flag Count': flow['FIN Flag Count'],
#         'SYN Flag Count': flow['SYN Flag Count'],
#         'RST Flag Count': flow['RST Flag Count'],
#         'PSH Flag Count': flow['PSH Flag Count'],
#         'ACK Flag Count': flow['ACK Flag Count'],
#         'URG Flag Count': flow['URG Flag Count'],

#         'Fwd Header Length': flow['Fwd Header Length'],
#         'Bwd Header Length': flow['Bwd Header Length']
#     }

#     os.makedirs(LOG_DIR, exist_ok=True)
#     file_exists = os.path.isfile(FLOW_LOG_FILE)
#     with open(FLOW_LOG_FILE, 'a', newline='') as f:
#         writer = csv.DictWriter(f, fieldnames=row.keys())
#         if not file_exists:
#             writer.writeheader()
#         writer.writerow(row)




def update_flow(pkt):
    if IP in pkt:
        proto = pkt[IP].proto
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"PROTO-{proto}")
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[TCP].sport if TCP in pkt else 0
        dst_port = pkt[TCP].dport if TCP in pkt else 0
        pkt_len = len(pkt)
        now = time.time()

        flow_key = (src_ip, dst_ip, src_port, dst_port, proto_name)
        flow = flows.get(flow_key, {
            'Flow ID': f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto_name}",
            'Source IP': src_ip,
            'Source Port': src_port,
            'Destination IP': dst_ip,
            'Destination Port': dst_port,
            'Protocol': proto_name,
            'Timestamp': now,
            'Flow Duration': 0,
            'Total Fwd Packets': 0,
            'Total Backward Packets': 0,
            'Total Length of Fwd Packets': 0,
            'Total Length of Bwd Packets': 0,
            'Fwd Packet Lengths': [],
            'Bwd Packet Lengths': [],
            'Flow Bytes/s': 0,
            'Flow Packets/s': 0,
            'Flow IATs': [],
            'Last Seen': now,
            'Fwd IATs': [],
            'Bwd IATs': [],
            'Fwd PSH Flags': 0,
            'Bwd PSH Flags': 0,
            'Fwd URG Flags': 0,
            'Bwd URG Flags': 0,
            'FIN Flag Count': 0,
            'SYN Flag Count': 0,
            'RST Flag Count': 0,
            'PSH Flag Count': 0,
            'ACK Flag Count': 0,
            'URG Flag Count': 0,
            'Fwd Header Length': 0,
            'Bwd Header Length': 0
        })

        direction = "Fwd" if pkt[IP].src == flow['Source IP'] else "Bwd"
        flow[f'Total {direction} Packets'] += 1
        flow[f'Total Length of {direction} Packets'] += pkt_len
        flow[f'{direction} Packet Lengths'].append(pkt_len)

        iat = now - flow['Last Seen']
        flow['Flow IATs'].append(iat)
        flow[f'{direction} IATs'].append(iat)

        if TCP in pkt:
            flags = pkt[TCP].flags
            if direction == "Fwd":
                flow['Fwd Header Length'] += pkt[TCP].dataofs * 4
            else:
                flow['Bwd Header Length'] += pkt[TCP].dataofs * 4

            if flags & 0x01: flow['FIN Flag Count'] += 1
            if flags & 0x02: flow['SYN Flag Count'] += 1
            if flags & 0x04: flow['RST Flag Count'] += 1
            if flags & 0x08: 
                flow['PSH Flag Count'] += 1
                flow[f'{direction} PSH Flags'] += 1
            if flags & 0x10: flow['ACK Flag Count'] += 1
            if flags & 0x20: 
                flow['URG Flag Count'] += 1
                flow[f'{direction} URG Flags'] += 1

        flow['Flow Duration'] = (now - flow['Timestamp']) * 1_000_000
        flow['Flow Bytes/s'] = flow['Total Length of Fwd Packets'] + flow['Total Length of Bwd Packets']
        flow['Flow Packets/s'] = flow['Total Fwd Packets'] + flow['Total Backward Packets']
        flow['Last Seen'] = now

        flows[flow_key] = flow




# def update_flow(pkt):
#     if IP in pkt:
#         proto = pkt[IP].proto
#         proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"PROTO-{proto}")
#         src_ip = pkt[IP].src
#         dst_ip = pkt[IP].dst
#         src_port = pkt[TCP].sport if TCP in pkt else 0
#         dst_port = pkt[TCP].dport if TCP in pkt else 0
#         pkt_len = len(pkt)
#         now = time.time()

#         flow_key = (src_ip, dst_ip, src_port, dst_port, proto_name)
#         flow = flows.get(flow_key, {
#             'src_ip': src_ip,
#             'dst_ip': dst_ip,
#             'src_port': src_port,
#             'dst_port': dst_port,
#             'protocol': proto_name,
#             'start_time': now,
#             'end_time': now,
#             'total_packets': 0,
#             'total_bytes': 0,
#             'packet_lengths': [],
#             'inter_arrival_times': [],
#             'last_seen': now,
#             'syn_count': 0,
#             'ack_count': 0
#         })

#         flow['total_packets'] += 1
#         flow['total_bytes'] += pkt_len
#         flow['packet_lengths'].append(pkt_len)
#         flow['inter_arrival_times'].append(now - flow['end_time'] if flow['end_time'] else 0)
#         flow['end_time'] = now
#         flow['last_seen'] = now

#         if TCP in pkt:
#             flags = pkt[TCP].flags
#             if flags & 0x02:
#                 flow['syn_count'] += 1
#             if flags & 0x10:
#                 flow['ack_count'] += 1

#         flows[flow_key] = flow



def stats(vals):
    return {
        'Max': max(vals, default=0),
        'Min': min(vals, default=0),
        'Mean': round(statistics.mean(vals), 2) if vals else 0,
        'Std': round(statistics.stdev(vals), 2) if len(vals) > 1 else 0,
        'Variance': round(statistics.variance(vals), 2) if len(vals) > 1 else 0
    }


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
recent_activity = defaultdict(lambda: deque(maxlen=100))

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


blocked_ips_lock = threading.Lock()
def update_blocked_ips():
    global blocked_ips
    while True:  #changed while running to while True
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
    update_flow(pkt)
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

        # proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"PROTO-{proto}")
        proto_name = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",          # Encapsulating Security Payload
    51: "AH",           # Authentication Header
    58: "ICMPv6",
    88: "EIGRP",
    89: "OSPF",
    94: "IPIP",
    103: "PIM",
    112: "VRRP",
    115: "L2TP",
    132: "SCTP",
    137: "MPLS-in-IP",
    143: "ETHERNET",
    255: "Reserved"
}.get(proto, f"PROTO-{proto}")

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

def flush_flows_periodically():
    while running:
        flush_old_flows()
        time.sleep(5)

def start_sniffing():
    global running
    running = True
    print(f"{Fore.CYAN}[+] Starting IDS... analyzing behavioral patterns across all interfaces...{Style.RESET_ALL}")

    threading.Thread(target=update_blocked_ips, daemon=True).start()
    threading.Thread(target=log_packet_stats, daemon=True).start()
    threading.Thread(target=flush_flows_periodically, daemon=True).start()

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
