import os
import sys
import ctypes
import threading
import csv
from scapy.all import TCP, ICMP, Ether, IP, ARP, UDP, get_if_hwaddr, conf, sniff, Raw
from queue import Queue

# Banner for the program
banner = '''-----------------------
SniffnDetect v.1.1
-----------------------
'''

class SniffnDetect():
    def __init__(self):
        self.INTERFACE = conf.iface
        self.MY_IP = [x[4] for x in conf.route.routes if x[2] != '0.0.0.0' and x[3] == self.INTERFACE][0]
        self.MY_MAC = get_if_hwaddr(self.INTERFACE)
        self.WEBSOCKET = None
        self.PACKETS_QUEUE = Queue()
        self.MAC_TABLE = {}
        self.RECENT_ACTIVITIES = []
        self.FILTERED_ACTIVITIES = {
            'TCP-SYN': {'flag': False, 'activities': [], 'attacker-mac': []},
            'TCP-SYNACK': {'flag': False, 'activities': [], 'attacker-mac': []},
            'ICMP-POD': {'flag': False, 'activities': [], 'attacker-mac': []},
            'ICMP-SMURF': {'flag': False, 'activities': [], 'attacker-mac': []},
        }
        self.flag = False

        # Open the CSV file in append mode to log attacks
        self.csv_file = open('attack_log.csv', 'a', newline='')  # Corrected filename
        self.csv_writer = csv.writer(self.csv_file)
        self.csv_writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Attack Type', 'Packet Size'])

    def sniffer_threader(self):
        while self.flag:
            pkt = sniff(count=1)
            with threading.Lock():
                self.PACKETS_QUEUE.put(pkt[0])

    def analyze_threader(self):
        while self.flag:
            pkt = self.PACKETS_QUEUE.get()
            self.analyze_packet(pkt)
            self.PACKETS_QUEUE.task_done()

    def check_avg_time(self, activities):
        time = 0
        c = -1
        while c > -31:
            time += activities[c][0] - activities[c-1][0]
            c -= 1
        time /= len(activities)
        return (time < 2 and self.RECENT_ACTIVITIES[-1][0] - activities[-1][0] < 10)

    def set_flags(self):
        for category in self.FILTERED_ACTIVITIES:
            if len(self.FILTERED_ACTIVITIES[category]['activities']) > 20:
                self.FILTERED_ACTIVITIES[category]['flag'] = self.check_avg_time(
                    self.FILTERED_ACTIVITIES[category]['activities'])
                if self.FILTERED_ACTIVITIES[category]['flag']:
                    self.FILTERED_ACTIVITIES[category]['attacker-mac'] = list(
                        set([i[3] for i in self.FILTERED_ACTIVITIES[category]['activities']]))

    def analyze_packet(self, pkt):
        src_ip, dst_ip, src_port, dst_port, tcp_flags, icmp_type = None, None, None, None, None, None
        protocol = []

        if len(self.RECENT_ACTIVITIES) > 15:
            self.RECENT_ACTIVITIES = self.RECENT_ACTIVITIES[-15:]

        for category in self.FILTERED_ACTIVITIES:
            if len(self.FILTERED_ACTIVITIES[category]['activities']) > 30:
                self.FILTERED_ACTIVITIES[category]['activities'] = self.FILTERED_ACTIVITIES[category]['activities'][-30:]

        self.set_flags()

        src_mac = pkt[Ether].src if Ether in pkt else None
        dst_mac = pkt[Ether].dst if Ether in pkt else None

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

        # Ignore UDP packets
        if UDP in pkt:
            return  # Early return if it's a UDP packet

        # Only process TCP packets
        if TCP in pkt:
            protocol.append("TCP")
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            tcp_flags = pkt[TCP].flags.flagrepr()

            # Log TCP packet details in the CSV file
            attack_type = None
            if tcp_flags == "S":
                self.FILTERED_ACTIVITIES['TCP-SYN']['activities'].append([pkt.time])
                attack_type = "SYN Flood"
            elif tcp_flags == "SA":
                self.FILTERED_ACTIVITIES['TCP-SYNACK']['activities'].append([pkt.time])
                attack_type = "SYN-ACK"

            # Log the packet details with attack type
            self.csv_writer.writerow([pkt.time, src_ip, dst_ip, attack_type if attack_type else "TCP", len(pkt)]) 

        if ICMP in pkt:
            protocol.append("ICMP")
            icmp_type = pkt[ICMP].type
            # 8 for echo-request and 0 for echo-reply
            if src_ip == self.MY_IP and src_mac != self.MY_MAC:
                self.FILTERED_ACTIVITIES['ICMP-SMURF']['activities'].append([pkt.time])
                attack_type = "SMURF"
            if Raw in pkt and len(pkt[Raw].load) > 1024:
                self.FILTERED_ACTIVITIES['ICMP-POD']['activities'].append([pkt.time])
                attack_type = "POD"

            # Log the packet details with attack type for ICMP
            if attack_type:
                self.csv_writer.writerow([pkt.time, src_ip, dst_ip, attack_type, len(pkt)]) 

        self.RECENT_ACTIVITIES.append(
            [pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, None, None])

    def start(self):
        if not self.flag:
            self.flag = True
            sniff_thread = threading.Thread(target=self.sniffer_threader)
            sniff_thread.daemon = True
            sniff_thread.start()
            analyze_thread = threading.Thread(target=self.analyze_threader)
            analyze_thread.daemon = True
            analyze_thread.start()
        return self.flag

    def stop(self):
        self.flag = False
        self.PACKETS_QUEUE = Queue()
        self.RECENT_ACTIVITIES = []
        self.FILTERED_ACTIVITIES = {
            'TCP-SYN': {'flag': False, 'activities': [], 'attacker-mac': []},
            'TCP-SYNACK': {'flag': False, 'activities': [], 'attacker-mac': []},
            'ICMP-POD': {'flag': False, 'activities': [], 'attacker-mac': []},
            'ICMP-SMURF': {'flag': False, 'activities': [], 'attacker-mac': []},
        }
        # Close the CSV file when stopping
        self.csv_file.close()

        return self.flag

def clear_screen():
    if "linux" in sys.platform:
        os.system("clear")
    elif "win32" in sys.platform:
        os.system("cls")
    else:
        pass

def is_admin():
    try:
        return os.getuid() == 0  # For Linux-based systems
    except AttributeError:
        pass
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1  # For Windows systems
    except AttributeError:
        return False
