from subprocess import run, PIPE
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1
from tqdm import tqdm
import ipaddress
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
import pyfiglet

# Color text functions
def ctxt(text): print(f"\033[36m{text}\033[0m")  # Cyan
def rtxt(text): print(f"\033[31m{text}\033[0m")  # Red
def lbtxt(text, end="\n"): print(f"\033[94m{text}\033[0m", end=end)  # Light Blue
def lmtxt(text): print(f"\033[95m{text}\033[0m")  # Light Magenta
def ytxt(text): print(f"\033[33m{text}\033[0m")  # Yellow

def display_banner():
    banner_text = "Ping Sweep"
    styled_banner = pyfiglet.figlet_format(banner_text, font="slant")
    rtxt(styled_banner)
    lbtxt("Github : 0xAbolfazl\n".center(20, " "))
    lbtxt("="*60)
    print()

def validate_ip(network_part):
    """Validate the first three octets of an IP address"""
    try:
        if not network_part:
            return "192.168.1"
        
        parts = network_part.split('.')
        if len(parts) != 3:
            raise ValueError("Should be 3 octets (e.g., 192.168.1)")
        
        for part in parts:
            if not 0 <= int(part) <= 255:
                raise ValueError("Each octet must be 0-255")
                
        return network_part
    except ValueError as e:
        rtxt(f"[!] Invalid IP format: {e}")
        raise

def get_scan_parameters():
    """Get user input for scan parameters with validation"""
    try:
        network = validate_ip(input('[?] ENTER FIRST 3 OCTETS OF YOUR IP (DEFAULT: 192.168.1): '))
        
        try:
            timeout = input('[?] ENTER TIMEOUT (ms, DEFAULT: 500): ')
            timeout = int(timeout) if timeout else 500
            
            start = input('[?] ENTER START POINT (DEFAULT: 1): ')
            start = int(start) if start else 1
            
            end = input('[?] ENTER END POINT (DEFAULT: 254): ')
            end = int(end) if end else 254
            
            if not 1 <= start <= end <= 254:
                raise ValueError("Start must be <= end, and both between 1-254")
                
            return network, timeout, start, end
            
        except ValueError as e:
            rtxt(f"[!] Invalid input: {e}")
            raise
            
    except Exception:
        raise

def ping_sweep_icmp(network, start, end, timeout):
    """Scan network using ICMP ping"""
    active_ips = []
    ctxt('[~] ICMP SCAN STARTED...')
    
    for ip in tqdm(range(start, end + 1), desc="Scanning"):
        address = f"{network}.{ip}"
        try:
            # Using system ping command (cross-platform)
            result = run(["ping", "-n", "1", "-w", str(timeout), address], 
                        stdout=PIPE, stderr=PIPE, timeout=(timeout+500)/1000)
            
            if result.returncode == 0:
                active_ips.append(address)
        except Exception:
            continue
    
    if active_ips:
        ctxt('\n[+] ACTIVE HOSTS:')
        for ip in active_ips:
            ctxt(f'[~]    {ip} IS UP')
    else:
        rtxt('[!] NO ACTIVE HOSTS FOUND')

def arp_scan(network, start, end, timeout):
    """Scan network using ARP requests"""
    clients = []
    lbtxt("[~] ARP SCANNING YOUR NETWORK...", end='\n\n')
    
    for ip in tqdm(range(start, end + 1), desc="Scanning"):
        target_ip = f'{network}.{ip}'
        try:
            # Create and send ARP packet
            arp = ARP(pdst=target_ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=timeout/1000, verbose=0, retry=1)[0]
            
            for _, received in result:
                clients.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc
                })
        except Exception:
            continue
    
    if clients:
        lmtxt("\n[+] AVAILABLE DEVICES IN YOUR NETWORK:")
        ctxt("IP" + " "*21 + "MAC")
        ctxt('-'*45)
        
        # Remove duplicates and print
        seen = set()
        for client in clients:
            if client['ip'] not in seen:
                seen.add(client['ip'])
                ytxt(f"{client['ip']:16}    {client['mac']}")
    else:
        rtxt("[!] NO DEVICES FOUND VIA ARP")

def combined_scan(network, start, end, timeout):
    """Combine ARP and ICMP scanning for comprehensive results"""
    devices = set()
    
    # First do ARP scan
    ctxt("[~] STARTING COMBINED SCAN (ARP + ICMP)")
    ctxt("[~] PHASE 1: ARP SCAN")
    arp_results = []
    
    for ip in tqdm(range(start, end + 1), desc="ARP Scan"):
        target_ip = f'{network}.{ip}'
        try:
            arp = ARP(pdst=target_ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=timeout/1000, verbose=0, retry=1)[0]
            
            for _, received in result:
                devices.add((received.psrc, received.hwsrc))
                arp_results.append(received.psrc)
        except Exception:
            continue
    
    # Then do ICMP scan for devices that might not respond to ARP
    ctxt("\n[~] PHASE 2: ICMP SCAN")
    icmp_results = []
    
    for ip in tqdm(range(start, end + 1), desc="ICMP Scan"):
        address = f"{network}.{ip}"
        if address in arp_results:  # Skip if already found by ARP
            continue
            
        try:
            # Using scapy's ICMP for more control
            packet = IP(dst=address)/ICMP()
            response = sr1(packet, timeout=timeout/1000, verbose=0)
            if response:
                devices.add((address, "Unknown MAC"))
                icmp_results.append(address)
        except Exception:
            continue
    
    # Display results
    if devices:
        lmtxt("\n[+] NETWORK DEVICES FOUND:")
        ctxt("IP" + " "*21 + "MAC")
        ctxt('-'*45)
        
        for ip, mac in sorted(devices, key=lambda x: ipaddress.ip_address(x[0])):
            ytxt(f"{ip:16}    {mac}")
    else:
        rtxt("[!] NO DEVICES FOUND")

def ping_sweep_runner():
    """Main function to run the scanner"""
    try:
        # Get scan parameters once
        try:
            network, timeout, start, end = get_scan_parameters()
        except Exception:
            return
            
        print("\n" + "-"*50)
        lbtxt("[~] SELECT SCAN METHOD:")
        ctxt("1. ICMP Ping Scan (faster but less reliable)")
        ctxt("2. ARP Scan (more reliable on local networks)")
        ctxt("3. Combined ARP + ICMP Scan (most comprehensive)")
        print("-"*50)
        
        choice = input("[?] ENTER YOUR CHOICE (1-3): ").strip()
        
        if choice == '1':
            ping_sweep_icmp(network, start, end, timeout)
        elif choice == '2':
            arp_scan(network, start, end, timeout)
        elif choice == '3':
            combined_scan(network, start, end, timeout)
        else:
            rtxt("[!] PLEASE ENTER 1, 2 OR 3")
            
    except KeyboardInterrupt:
        rtxt("\n[!] SCAN INTERRUPTED BY USER")
    except Exception as e:
        rtxt(f"[!] ERROR: {str(e)}")

if __name__ == '__main__':
    display_banner()
    ping_sweep_runner()