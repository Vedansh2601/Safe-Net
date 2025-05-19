from scapy.all import IP, TCP

def check_ack_scan(pkt, log_alert, tracker, thresholds):
    """Detect ACK scan where packets only have ACK flag set."""
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        if pkt[TCP].flags == 'A':  # ACK-only
            tracker['ack_scan'].setdefault(src_ip, 0)
            tracker['ack_scan'][src_ip] += 1
            threshold = thresholds.get('ACK_SCAN', 20)  # Default to 20 if not set
            if tracker['ack_scan'][src_ip] > threshold:
                log_alert(src_ip, tracker['ack_scan'][src_ip], "ACK Scan Detected")
                tracker['ack_scan'][src_ip] = 0

def load_rules():
    return [check_ack_scan]