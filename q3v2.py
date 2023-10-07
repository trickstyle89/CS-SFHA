from scapy.all import sr1, IP, ICMP, TCP
import ipaddress

# Function to perform ICMP scan
def icmp_scan(network):
    # List to store IPs that are alive
    alive_hosts = []
    for ip in ipaddress.IPv4Network(network, strict=False):
        # Packet crafting for ICMP
        packet = IP(dst=str(ip))/ICMP()
        # Packet transmission
        reply = sr1(packet, timeout=1, verbose=0)
        # Check for reply
        if reply:
            print(f"{ip} is alive")
            alive_hosts.append(str(ip))
    # Return the list of alive hosts
    return alive_hosts

# Function to perform TCP scan
def tcp_scan(network, port):
    # List to store IPs that are alive
    alive_hosts = []
    for ip in ipaddress.IPv4Network(network, strict=False):
        # Packet crafting for TCP
        packet = IP(dst=str(ip))/TCP(dport=port, flags="S")
        # Packet transmission
        reply = sr1(packet, timeout=1, verbose=0)
        # Check for reply with SYN-ACK flag
        if reply and reply[TCP].flags == "SA":
            print(f"{ip} is alive on port {port}")
            alive_hosts.append(str(ip))
    # Return the list of alive hosts
    return alive_hosts

if __name__ == "__main__":
    # User input for network address
    network = input("Enter the network address to scan (e.g., 192.168.2.0/24): ")
    # User input for scan mode
    mode = input("Enter the scan mode (ICMP or TCP): ").upper()
    
    # Input validation for scan mode
    if mode not in ["ICMP", "TCP"]:
        print("Invalid scan mode. Exiting.")
        exit(1)
    
    # Perform TCP scan if mode is TCP
    if mode == "TCP":
        # User input for port number
        port = int(input("Enter the port for TCP scan: "))
        # Perform TCP scan and get alive hosts
        alive_hosts = tcp_scan(network, port)
    else:
        # Perform ICMP scan and get alive hosts
        alive_hosts = icmp_scan(network)
    
    # Output unique IPs that responded
    if alive_hosts:
        print("Unique IPs that responded:")
        for ip in set(alive_hosts):
            print(ip)
    else:
        print("No responsive IPs found.")
