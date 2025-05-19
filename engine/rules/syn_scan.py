from scapy.all import IP, TCP, UDP, ICMP

def check_syn_flood(pkt, log_alert, tracker, thresholds):
    """Detect SYN flood attacks by excessive SYN packets from one IP."""
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        if pkt[TCP].flags == 'S':
            tracker['syn_flood'].setdefault(src_ip, 0)
            tracker['syn_flood'][src_ip] += 1
            threshold = thresholds.get('SYN_FLOOD', 10)  # Default to 10 if not set
            if tracker['syn_flood'][src_ip] > threshold:
                log_alert(src_ip, tracker['syn_flood'][src_ip], "SYN Flood Attack")
                tracker['syn_flood'][src_ip] = 0

def check_port_scan(pkt, log_alert, tracker, thresholds):
    """Detect port scans by tracking unique destination ports."""
    if IP in pkt and (TCP in pkt or UDP in pkt):
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
        port_tracker = tracker['port_scan']
        port_tracker.setdefault(src_ip, set()).add(dst_port)
        threshold = thresholds.get('PORT_SCAN', 15)  # Default to 15 if not set
        if len(port_tracker[src_ip]) > threshold:
            log_alert(src_ip, len(port_tracker[src_ip]), "Port Scan Detected")
            port_tracker[src_ip].clear()

def check_icmp_flood(pkt, log_alert, tracker, thresholds):
    """Detect ICMP flood attacks by excessive ICMP packets."""
    if IP in pkt and ICMP in pkt:
        src_ip = pkt[IP].src
        tracker['icmp_flood'].setdefault(src_ip, 0)
        tracker['icmp_flood'][src_ip] += 1
        threshold = thresholds.get('ICMP_FLOOD', 50)  # Default to 50 if not set
        if tracker['icmp_flood'][src_ip] > threshold:
            log_alert(src_ip, tracker['icmp_flood'][src_ip], "ICMP Flood Attack")
            tracker['icmp_flood'][src_ip] = 0

def check_tcp_rst_attack(pkt, log_alert, tracker, thresholds):
    """Detect TCP RST flood attacks by excessive RST packets."""
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        if pkt[TCP].flags == 'R':
            tracker['tcp_rst_flood'].setdefault(src_ip, 0)
            tracker['tcp_rst_flood'][src_ip] += 1
            threshold = thresholds.get('TCP_RST_FLOOD', 20)  # Default to 20 if not set
            if tracker['tcp_rst_flood'][src_ip] > threshold:
                log_alert(src_ip, tracker['tcp_rst_flood'][src_ip], "TCP RST Flood Attack")
                tracker['tcp_rst_flood'][src_ip] = 0

def check_udp_flood(pkt, log_alert, tracker, thresholds):
    """Detect UDP flood attacks by excessive UDP packets."""
    if IP in pkt and UDP in pkt:
        src_ip = pkt[IP].src
        tracker['udp_flood'].setdefault(src_ip, 0)
        tracker['udp_flood'][src_ip] += 1
        threshold = thresholds.get('UDP_FLOOD', 30)  # Default to 30 if not set
        if tracker['udp_flood'][src_ip] > threshold:
            log_alert(src_ip, tracker['udp_flood'][src_ip], "UDP Flood Attack")
            tracker['udp_flood'][src_ip] = 0

def load_rules():
    """Return list of rule functions to apply."""
    return [check_syn_flood, check_port_scan, check_icmp_flood, check_tcp_rst_attack, check_udp_flood]