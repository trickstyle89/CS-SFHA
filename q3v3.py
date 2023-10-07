from scapy.all import sr1, IP, ICMP, TCP
import ipaddress
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO)

# Function to perform ICMP scan
def icmp_scan(network):
    alive_hosts = []
    for ip in ipaddress.IPv4Network(network, strict=False):
        try:
            packet = IP(dst=str(ip))/ICMP()
            reply = sr1(packet, timeout=0.5, verbose=0)
            if reply:
                logging.info(f"{ip} is alive")
                alive_hosts.append(str(ip))
        except Exception as e:
            logging.error(f"An error occurred while scanning {ip}: {e}")
    return alive_hosts

# Function to perform TCP scan
def tcp_scan(network, port):
    alive_hosts = []
    for ip in ipaddress.IPv4Network(network, strict=False):
        try:
            packet = IP(dst=str(ip))/TCP(dport=port, flags="S")
            reply = sr1(packet, timeout=0.5, verbose=0)
            if reply and reply[TCP].flags == "SA":
                logging.info(f"{ip} is alive on port {port}")
                alive_hosts.append(str(ip))
        except Exception as e:
            logging.error(f"An error occurred while scanning {ip} on port {port}: {e}")
    return alive_hosts

if __name__ == "__main__":
    try:
        network = input("Enter the network address to scan (e.g., 192.168.2.0/24): ")
        mode = input("Enter the scan mode (ICMP or TCP): ").upper()

        if mode not in ["ICMP", "TCP"]:
            logging.error("Invalid scan mode. Exiting.")
            exit(1)

        if mode == "TCP":
            port = int(input("Enter the port for TCP scan: "))
            alive_hosts = tcp_scan(network, port)
        else:
            alive_hosts = icmp_scan(network)

        if alive_hosts:
            print("Unique IPs that responded:")
            for ip in set(alive_hosts):
                print(ip)
        else:
            print("No responsive IPs found.")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
