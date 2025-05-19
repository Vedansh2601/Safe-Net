
import os
import csv
import datetime
import time
import statistics
# --- FLOW TRACKING ADDITION ---
LOG_DIR = os.path.join(os.path.dirname(__file__), '../logs')
FLOW_LOG_FILE = os.path.join(LOG_DIR, 'flows_log.csv')
FLOW_TIMEOUT = 30
flows = {}

def stats(vals):
    return {
        'Max': max(vals, default=0),
        'Min': min(vals, default=0),
        'Mean': round(statistics.mean(vals), 2) if vals else 0,
        'Std': round(statistics.stdev(vals), 2) if len(vals) > 1 else 0,
        'Variance': round(statistics.variance(vals), 2) if len(vals) > 1 else 0
    }

def write_flow_to_log(flow):
    fwd_stats = stats(flow['Fwd Packet Lengths'])
    bwd_stats = stats(flow['Bwd Packet Lengths'])
    iat_stats = stats(flow['Flow IATs'])

    row = {
        'Flow ID': flow['Flow ID'],
        'Source IP': flow['Source IP'],
        'Source Port': flow['Source Port'],
        'Destination IP': flow['Destination IP'],
        'Destination Port': flow['Destination Port'],
        'Protocol': flow['Protocol'],
        'Timestamp': datetime.datetime.fromtimestamp(flow['Timestamp']).isoformat(),
        'Flow Duration': round(flow['Flow Duration'], 2),

        'Total Fwd Packets': flow['Total Fwd Packets'],
        'Total Backward Packets': flow['Total Backward Packets'],
        'Total Length of Fwd Packets': flow['Total Length of Fwd Packets'],
        'Total Length of Bwd Packets': flow['Total Length of Bwd Packets'],

        'Fwd Packet Max': fwd_stats['Max'],
        'Fwd Packet Min': fwd_stats['Min'],
        'Fwd Packet Mean': fwd_stats['Mean'],
        'Fwd Packet Std': fwd_stats['Std'],
        'Bwd Packet Max': bwd_stats['Max'],
        'Bwd Packet Min': bwd_stats['Min'],
        'Bwd Packet Mean': bwd_stats['Mean'],
        'Bwd Packet Std': bwd_stats['Std'],

        'Flow Bytes/s': flow['Flow Bytes/s'],
        'Flow Packets/s': flow['Flow Packets/s'],
        'Flow IAT Mean': iat_stats['Mean'],
        'Flow IAT Std': iat_stats['Std'],
        'Flow IAT Max': iat_stats['Max'],
        'Flow IAT Min': iat_stats['Min'],

        'Fwd PSH Flags': flow['Fwd PSH Flags'],
        'Bwd PSH Flags': flow['Bwd PSH Flags'],
        'Fwd URG Flags': flow['Fwd URG Flags'],
        'Bwd URG Flags': flow['Bwd URG Flags'],
        'FIN Flag Count': flow['FIN Flag Count'],
        'SYN Flag Count': flow['SYN Flag Count'],
        'RST Flag Count': flow['RST Flag Count'],
        'PSH Flag Count': flow['PSH Flag Count'],
        'ACK Flag Count': flow['ACK Flag Count'],
        'URG Flag Count': flow['URG Flag Count'],

        'Fwd Header Length': flow['Fwd Header Length'],
        'Bwd Header Length': flow['Bwd Header Length']
    }

    os.makedirs(LOG_DIR, exist_ok=True)
    file_exists = os.path.isfile(FLOW_LOG_FILE)
    with open(FLOW_LOG_FILE, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

def flush_old_flows():
    now = time.time()
    flushed = []
    for flow_key, flow_data in list(flows.items()):
        if now - flow_data['Last Seen'] > FLOW_TIMEOUT:
            write_flow_to_log(flow_data)
            flushed.append(flow_key)
    for key in flushed:
        del flows[key]  # cleanup



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
