from customtkinter import CTk, CTkButton, CTkLabel, CTkEntry, CTkTextbox, CTkFrame, DISABLED, NORMAL, END
from customtkinter import set_default_color_theme, set_appearance_mode, CTkOptionMenu
from scapy.all import Ether, srp, ARP
from threading import Thread
from time import sleep
from subprocess import run, PIPE
import logging

# Configure scapy logging to reduce warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class NetworkScannerApp:
    def __init__(self):
        self.root = CTk()
        self.setup_main_window()
        self.create_interface()
        self.setup_interface_layout()
        self.scan_results = []

    def setup_main_window(self):
        """Configure the main application window"""
        self.root.title('PingSweep')
        self.root.geometry('700x630')
        self.root.resizable(False, False)
        set_appearance_mode("dark")
        set_default_color_theme("blue")

    def create_interface(self):
        """Create all GUI components"""
        # Main container frame
        self.main_frame = CTkFrame(
            master=self.root,
            corner_radius=10,
            border_width=2,
            border_color='red'
        )

        # Title label
        self.title_label = CTkLabel(
            master=self.main_frame,
            text='PingSweep',
            font=('montserrat', 30, 'bold')
        )

        # Network configuration inputs
        self.create_network_inputs()
        
        # Scan method selection
        self.create_method_selection()
        
        # Action buttons
        self.create_action_buttons()
        
        # Results display
        self.create_results_display()

    def create_network_inputs(self):
        """Create network configuration input fields"""
        # IP range inputs
        self.ip_range_label = CTkLabel(
            master=self.main_frame,
            text='NETWORK RANGE (first 3 octets):',
            font=('montserrat', 23)
        )
        
        self.ip_range_entry = CTkEntry(
            master=self.main_frame,
            width=150,
            height=35,
            font=('montserrat', 20),
            border_color='white',
            border_width=2
        )
        self.ip_range_entry.insert(END, '192.168.1')
        
        # Start/End IP inputs
        self.range_label = CTkLabel(
            master=self.main_frame,
            text='START / END HOST:',
            font=('montserrat', 23)
        )
        
        self.start_ip_entry = CTkEntry(
            master=self.main_frame,
            width=72,
            height=35,
            font=('montserrat', 20),
            border_color='white',
            border_width=2
        )
        self.start_ip_entry.insert(END, '1')
        
        self.end_ip_entry = CTkEntry(
            master=self.main_frame,
            width=72,
            height=35,
            font=('montserrat', 20),
            border_color='white',
            border_width=2
        )
        self.end_ip_entry.insert(END, '254')
        
        # Timeout setting
        self.timeout_label = CTkLabel(
            master=self.main_frame,
            text='TIMEOUT (ms):',
            font=('montserrat', 23)
        )
        
        self.timeout_entry = CTkEntry(
            master=self.main_frame,
            width=150,
            height=35,
            font=('montserrat', 20),
            border_color='white',
            border_width=2
        )
        self.timeout_entry.insert(END, '500')

    def create_method_selection(self):
        """Create scan method selection components"""
        self.method_label = CTkLabel(
            master=self.main_frame,
            text='SCAN METHOD:',
            font=('montserrat', 23)
        )
        
        self.method_selector = CTkOptionMenu(
            master=self.main_frame,
            values=['ARP Discovery', 'ICMP Ping'],
            width=150,
            height=35,
            font=('montserrat', 15)
        )

    def create_action_buttons(self):
        """Create action buttons"""
        self.scan_button = CTkButton(
            master=self.main_frame,
            text='START SCAN',
            width=520,
            height=30,
            font=('montserrat', 23, 'bold'),
            command=self.initiate_scan
        )
        
        self.exit_button = CTkButton(
            master=self.main_frame,
            text='EXIT',
            width=520,
            height=30,
            font=('montserrat', 23, 'bold'),
            command=self.root.destroy,
            fg_color='red',
            text_color='white',
            hover_color='#751717'
        )

    def create_results_display(self):
        """Create results display area"""
        self.results_display = CTkTextbox(
            master=self.main_frame,
            width=520,
            height=170,
            font=('montserrat', 15),
            border_color='white',
            border_width=2
        )
        self.results_display.configure(state=DISABLED)

    def setup_interface_layout(self):
        """Position all interface components"""
        self.main_frame.pack(padx=20, pady=20, fill='both', expand=True)
        
        # Title
        self.title_label.place(x=180, y=20)
        
        # Network inputs
        self.ip_range_label.place(x=70, y=120)
        self.ip_range_entry.place(x=440, y=120)
        
        self.range_label.place(x=70, y=160)
        self.start_ip_entry.place(x=440, y=160)
        self.end_ip_entry.place(x=517, y=160)
        
        self.timeout_label.place(x=70, y=200)
        self.timeout_entry.place(x=440, y=200)
        
        # Method selection
        self.method_label.place(x=70, y=240)
        self.method_selector.place(x=440, y=240)
        
        # Buttons
        self.scan_button.place(x=70, y=280)
        self.results_display.place(x=70, y=330)
        self.exit_button.place(x=70, y=520)

    def initiate_scan(self):
        """Start the scanning process in a new thread"""
        Thread(target=self.execute_scan).start()

    def execute_scan(self):
        """Execute the selected scan method"""
        self.display_scan_parameters()
        
        if self.method_selector.get() == 'ARP Discovery':
            self.perform_arp_scan()
        else:
            self.perform_icmp_scan()

    def display_scan_parameters(self):
        """Show the scan configuration in the results box"""
        try:
            self.update_display('', clear=True)
            network = self.ip_range_entry.get()
            start = self.start_ip_entry.get()
            end = self.end_ip_entry.get()
            timeout = self.timeout_entry.get()
            
            self.update_display(f"[+]      FIRST HOST    :  {network}.{start}\n")
            sleep(0.3)
            self.update_display(f"  ...      LAST HOST      :  {network}.{end}\n")
            sleep(0.3)
            self.update_display(f"  ...      TIMEOUT      :  {timeout} (ms)\n")
            sleep(0.3)
            
            method = "ARP DISCOVERY" if self.method_selector.get() == 'ARP Discovery' else "ICMP PING"
            self.update_display(f"  ...      METHOD       :  {method}\n")
            self.update_display("------------------------------------------\n")
            sleep(0.3)
            self.update_display("[~]      SCANNING NETWORK ...\n")
            
        except Exception as e:
            print(f"Error displaying parameters: {e}")

    def perform_arp_scan(self):
        """Perform network scan using ARP requests"""
        try:
            sleep(2.5)  # Small delay for better UI flow
            timeout = float(self.timeout_entry.get())
            network = self.ip_range_entry.get()
            start = int(self.start_ip_entry.get())
            end = int(self.end_ip_entry.get())
            
            discovered_devices = []
            for host in range(start, end + 1):
                target_ip = f'{network}.{host}'
                arp_packet = ARP(pdst=target_ip)
                ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
                full_packet = ether_frame/arp_packet
                result = srp(full_packet, timeout=timeout/1000, verbose=0)[0]
                
                for sent, received in result:
                    discovered_devices.append(
                        f'              {received.psrc}{(13-len(received.psrc))*" "*2}{9*" "}{received.hwsrc}\n'
                    )
            
            self.show_scan_results(discovered_devices, "ARP")

        except Exception as e:
            self.update_display('[!]    SCAN ERROR OCCURRED!\n\n', clear=True)
            self.update_display(str(e))

    def perform_icmp_scan(self):
        """Perform network scan using ICMP ping"""
        sleep(2.5)  # Small delay for better UI flow
        timeout = self.timeout_entry.get()
        network = self.ip_range_entry.get()
        start = int(self.start_ip_entry.get())
        end = int(self.end_ip_entry.get())
        
        active_hosts = []
        for host in range(start, end + 1):
            address = f"{network}.{host}"
            result = run(["ping", "-n", "1", "-w", timeout, address], 
                        stdout=PIPE, stderr=PIPE)
            if result.returncode == 0:
                active_hosts.append(address)
        
        self.show_scan_results(active_hosts, "ICMP")

    def show_scan_results(self, results, scan_type):
        """Display the scan results appropriately"""
        self.update_display("[~]    --- SCAN COMPLETED ---", clear=True)
        sleep(1)
        
        if not results:
            self.update_display("\n[~]    NO DEVICES FOUND", clear=True)
            return
            
        if scan_type == "ARP":
            header = '''[+]         ACTIVE DEVICES FOUND:

              IP ADDRESS           MAC ADDRESS
              -----------------------------------------------
'''
            self.update_display(header, clear=True)
            for device in results:
                self.update_display(device)
        else:
            header = '''[+]         RESPONSIVE HOSTS:

              IP ADDRESS
              ------------------------------------
'''
            self.update_display(header, clear=True)
            for host in results:
                self.update_display(f'              {host}\n')

    def update_display(self, text, clear=False):
        """Update the results display area"""
        self.results_display.configure(state=NORMAL)
        if clear:
            self.results_display.delete(1.0, END)
        self.results_display.insert(END, text)
        self.results_display.configure(state=DISABLED)

    def run(self):
        """Run the application main loop"""
        self.root.mainloop()


def main():
    app = NetworkScannerApp()
    app.run()


if __name__ == '__main__':
    main()