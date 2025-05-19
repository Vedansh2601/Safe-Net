from scapy.all import IP, TCP

def check_syn_ack_scan(pkt, log_alert, tracker, thresholds):
    """Detect strange SYN-ACK packets not part of TCP handshake."""
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        if pkt[TCP].flags == 0x12:  # SYN + ACK
            tracker['syn_ack_scan'].setdefault(src_ip, 0)
            tracker['syn_ack_scan'][src_ip] += 1
            threshold = thresholds.get('SYN_ACK_SCAN', 10)  # Default to 10 if not set
            if tracker['syn_ack_scan'][src_ip] > threshold:
                log_alert(src_ip, tracker['syn_ack_scan'][src_ip], "SYN-ACK Scan")
                tracker['syn_ack_scan'][src_ip] = 0

def load_rules():
    return [check_syn_ack_scan]