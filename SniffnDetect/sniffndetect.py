import os
import sys
import csv
import ctypes
import threading
import time  # Pour le timestamp
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, sniff, conf, get_if_hwaddr  # Importations de Scapy
from queue import Queue

class SniffnDetect:
    def __init__(self):
        self.INTERFACE = conf.iface
        self.MY_IP = [x[4] for x in conf.route.routes if x[2] != '0.0.0.0' and x[3] == self.INTERFACE][0]
        self.MY_MAC = get_if_hwaddr(self.INTERFACE)  # Correction ici
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
        self.csv_file = open('attack_logs.csv', 'a', newline='')
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
        # Ensure we have at least 2 activities to compare timestamps
        if len(activities) < 2:
            return False

        time_total = 0
        count = 0

        # Only process up to the last 30 activities or fewer
        for i in range(1, min(30, len(activities))):
            # Calculate time difference between consecutive activities
            time_total += activities[-i][0] - activities[-(i + 1)][0]
            count += 1

        # Calculate average time between activities
        avg_time = time_total / count if count > 0 else float('inf')

        # Return True if the average time between packets is less than 2 seconds
        # and the most recent activity happened within 10 seconds
        return avg_time < 2 and (self.RECENT_ACTIVITIES[-1][0] - activities[-1][0] < 10)

    def find_attackers(self, category):
        data = []
        for mac in self.FILTERED_ACTIVITIES[category]['attacker-mac']:
            data.append(
                f"({self.MAC_TABLE[mac]}, {mac})" if mac in self.MAC_TABLE else f"(Unknown IP, {mac})"
            )
        return category + ' Attackers :<br>' + "<br>".join(data) + '<br><br>'

    def set_flags(self):
        for category in self.FILTERED_ACTIVITIES:
            activities = self.FILTERED_ACTIVITIES[category]['activities']
            # Only check if there are enough activities (e.g., more than 2)
            if len(activities) > 2:
                self.FILTERED_ACTIVITIES[category]['flag'] = self.check_avg_time(activities)
                if self.FILTERED_ACTIVITIES[category]['flag']:
                    # Only add the MAC address if the activity has at least 4 elements
                    self.FILTERED_ACTIVITIES[category]['attacker-mac'] = list(
                        set(i[3] for i in activities if len(i) > 3)
                    )

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
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

        if TCP in pkt:
            protocol.append("TCP")
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            tcp_flags = pkt[TCP].flags.flagrepr()
        if UDP in pkt:
            protocol.append("UDP")
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        if ICMP in pkt:
            protocol.append("ICMP")
            icmp_type = pkt[ICMP].type

        if ARP in pkt and pkt[ARP].op in (1, 2):
            protocol.append("ARP")
            if pkt[ARP].hwsrc in self.MAC_TABLE.keys() and self.MAC_TABLE[pkt[ARP].hwsrc] != pkt[ARP].psrc:
                self.MAC_TABLE[pkt[ARP].hwsrc] = pkt[ARP].psrc
            if pkt[ARP].hwsrc not in self.MAC_TABLE.keys():
                self.MAC_TABLE[pkt[ARP].hwsrc] = pkt[ARP].psrc

        load_len = len(pkt[Raw].load) if Raw in pkt else None

        attack_type = None

        if ICMP in pkt:
            if src_ip == self.MY_IP and src_mac != self.MY_MAC:
                self.FILTERED_ACTIVITIES['ICMP-SMURF']['activities'].append([pkt.time, src_ip, dst_ip, src_mac])
                attack_type = 'ICMP-SMURF PACKET'

            if load_len and load_len > 1024:
                self.FILTERED_ACTIVITIES['ICMP-POD']['activities'].append([pkt.time, src_ip, dst_ip, src_mac])
                attack_type = 'ICMP-PoD PACKET'

        if dst_ip == self.MY_IP:
            if TCP in pkt:
                if tcp_flags == "S":
                    self.FILTERED_ACTIVITIES['TCP-SYN']['activities'].append([pkt.time, src_ip, dst_ip, src_mac])
                    attack_type = 'TCP-SYN PACKET'

                elif tcp_flags == "SA":
                    self.FILTERED_ACTIVITIES['TCP-SYNACK']['activities'].append([pkt.time, src_ip, dst_ip, src_mac])
                    attack_type = 'TCP-SYNACK PACKET'

        # Log the attack in the CSV file
        if attack_type:
            self.log_attack_to_csv(src_ip, dst_ip, attack_type, load_len)

        self.RECENT_ACTIVITIES.append(
            [pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, attack_type]
        )

    def log_attack_to_csv(self, src_ip, dst_ip, attack_type, load_len):
        # Get current timestamp
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        self.csv_writer.writerow([timestamp, src_ip, dst_ip, attack_type, load_len])

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
        self.csv_file.close()  # Close the CSV file
