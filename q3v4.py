from scapy.all import sr1, IP, ICMP, TCP
import ipaddress
import logging
import threading

# Initialize logging
logging.basicConfig(level=logging.INFO)

def scan_host(ip, mode, port=None):
    try:
        if mode == "ICMP":
            packet = IP(dst=str(ip))/ICMP()
            reply = sr1(packet, timeout=0.5, verbose=0)
            if reply:
                logging.info(f"{ip} is alive")
        elif mode == "TCP":
            packet = IP(dst=str(ip))/TCP(dport=port, flags="S")
            reply = sr1(packet, timeout=0.5, verbose=0)
            if reply and reply[TCP].flags == "SA":
                logging.info(f"{ip} is alive on port {port}")
    except Exception as e:
        logging.error(f"An error occurred while scanning {ip}: {e}")

def threaded_scan(network, mode, port=None):
    threads = []
    for ip in ipaddress.IPv4Network(network, strict=False):
        thread = threading.Thread(target=scan_host, args=(ip, mode, port))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    try:
        network = input("Enter the network address to scan (e.g., 192.168.2.0/24): ")
        mode = input("Enter the scan mode (ICMP or TCP): ").upper()

        if mode not in ["ICMP", "TCP"]:
            logging.error("Invalid scan mode. Exiting.")
            exit(1)

        port = None
        if mode == "TCP":
            port = int(input("Enter the port for TCP scan: "))
        
        threaded_scan(network, mode, port)

    except Exception as e:
        logging.error(f"An error occurred: {e}")
