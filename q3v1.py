from scapy.all import sr1, IP, ICMP, TCP
import ipaddress

# Function to perform ICMP scan
def icmp_scan(network):
    alive_hosts = []
    for ip in ipaddress.IPv4Network(network, strict=False):
        # Packet Crafting for ICMP
        packet = IP(dst=str(ip))/ICMP()
        # Transmission
        reply = sr1(packet, timeout=1, verbose=0)
        if reply:
            print(f"{ip} is alive")
            alive_hosts.append(str(ip))
    # Output
    return alive_hosts

# Function to perform TCP scan
def tcp_scan(network, port):
    alive_hosts = []
    for ip in ipaddress.IPv4Network(network, strict=False):
        # Packet Crafting for TCP
        packet = IP(dst=str(ip))/TCP(dport=port, flags="S")
        # Transmission
        reply = sr1(packet, timeout=1, verbose=0)
        if reply and reply[TCP].flags == "SA":  # SYN-ACK flag
            print(f"{ip} is alive on port {port}")
            alive_hosts.append(str(ip))
    # Output
    return alive_hosts

if __name__ == "__main__":
    # Input
    network = input("Enter the network address to scan (e.g., 192.168.2.0/24): ")
    mode = input("Enter the scan mode (ICMP or TCP): ")
    
    if mode.upper() == "TCP":
        port = int(input("Enter the port for TCP scan: "))
        alive_hosts = tcp_scan(network, port)
    else:
        alive_hosts = icmp_scan(network)
        
    # Output unique IPs
    print("Unique IPs that responded:")
    for ip in set(alive_hosts):
        print(ip)
