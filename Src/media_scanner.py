import sys
import os

# Verificar se o script está rodando com privilégios de Administrador no Windows
def check_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

if not check_admin():
    print("[!] ERRO: No Windows, este script precisa ser executado como ADMINISTRADOR.")
    print("[!] Clique com o botão direito no Prompt de Comando/PowerShell e selecione 'Executar como Administrador'.")
    sys.exit(1)

from scapy.all import ARP, Ether, srp, IP, TCP, UDP, sr1

# Dicionário expandido de portas de Mídia, AV-over-IP, Iluminação, Automação, Broadcast e IoT
TARGET_PORTS = {
    # Mídia, Controle de Iluminação e Broadcast
    6454: ("UDP", "Art-Net (DMX512 sobre IP - Sem Criptografia)"),
    5568: ("UDP", "sACN / E1.31 (Streaming ACN - Iluminação)"),
    5353: ("UDP", "mDNS / Bonjour (Descoberta de Serviços de Mídia)"),
    1900: ("UDP", "UPnP (SSDP - Descoberta de Dispositivos de Mídia)"),
    5960: ("TCP", "NDI (Network Device Interface - Vídeo sobre IP)"),
    5961: ("TCP", "NDI Metadata / Control"),
    7959: ("UDP", "NDI Discovery Service"),
    8000: ("TCP", "OSC (Open Sound Control) / HTTP Alt"),
    9000: ("UDP", "OSC (Open Sound Control)"),

    # Audio sobre IP (AoIP) e Sincronismo
    319:  ("UDP", "PTP Event (IEEE 1588 - Sincronismo Dante/AES67)"),
    320:  ("UDP", "PTP General (IEEE 1588 - Sincronismo Dante/AES67)"),
    4321: ("UDP", "Dante Control / Discovery (Audinate)"),
    8700: ("UDP", "Dante Routing / Status"),
    8702: ("UDP", "Dante Firmware Update"),

    # Streaming de Vídeo e CFTV
    554:  ("TCP", "RTSP (Real Time Streaming Protocol - Câmeras PTZ/CFTV)"),
    1935: ("TCP", "RTMP (Real-Time Messaging Protocol - Live Streaming)"),
    8080: ("TCP", "HTTP Alternate (Streams MJPEG / Câmeras IP)"),
    8443: ("TCP", "HTTPS Alternate (Streams de Vídeo Seguros)"),
    37777:("TCP", "Dahua / Câmeras IP (Protocolo Proprietário DVR/NVR)"),
    34567:("TCP", "DVR / NVR Chinese Generic Media Port"),
    8001: ("TCP", "Enigma2 / Receiver de TV / Streaming"),

    # Automação Residencial e Corporativa (Sistemas AV)
    41794:("TCP", "Crestron Control Protocol (CIP)"),
    41795:("UDP", "Crestron Auto-Discovery"),
    1319: ("TCP", "AMX ICSP Protocol (Automação AV)"),
    10200:("TCP", "Extron Control / SIS"),
    50000:("TCP", "Extron Driver / eBUS"),
    5200: ("TCP", "Global Cache AV Controller"),

    # IoT, Automação Industrial e Casas Inteligentes
    1883: ("TCP", "MQTT (Mensageria IoT não criptografada)"),
    8883: ("TCP", "MQTT sobre TLS/SSL (IoT Seguro)"),
    5683: ("UDP", "CoAP (Constrained Application Protocol)"),
    502:  ("TCP", "Modbus TCP (Automação Industrial/Predial)"),
    47808:("UDP", "BACnet/IP (Automação Predial / HVAC)"),
    2000: ("TCP", "Cisco SCCP / Skinny Call Control Protocol"),
    5060: ("UDP", "SIP (Telefonia VoIP / Intercom)"),
    5061: ("TCP", "SIP sobre TLS (VoIP Seguro)"),

    # Interfaces Web e Gerenciamento Remoto
    80:   ("TCP", "HTTP (Interface Web não segura / Câmeras e Switches)"),
    443:  ("TCP", "HTTPS (Interface Web Segura)"),
    23:   ("TCP", "Telnet (Acesso Remoto não criptografado)"),
    22:   ("TCP", "SSH (Gerenciamento Remoto Seguro)"),
    161:  ("UDP", "SNMP (Gerenciamento de Rede / Impressoras / Switches)"),
    162:  ("UDP", "SNMP Trap"),
    5900: ("TCP", "VNC (Acesso Remoto de Telas/Mídia)"),
    3389: ("TCP", "RDP (Windows Remote Desktop)")
}

def discover_hosts(ip_range):
    """
    Envia pacotes ARP Request para descobrir todos os endereços IP e MAC ativos na sub-rede.
    """
    print(f"[*] Descobrindo dispositivos ativos na rede ({ip_range})...")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []

    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def inspect_device_ports(ip):
    """
    Testa portas TCP e UDP mapeadas para identificar serviços vulneráveis ou ativos.
    """
    open_services = []

    for port, (proto, description) in TARGET_PORTS.items():
        if proto == "UDP":
            pkt = IP(dst=ip) / UDP(dport=port)
            resp = sr1(pkt, timeout=0.3, verbose=0)
            if resp is not None:
                open_services.append((port, "UDP", description))

        elif proto == "TCP":
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=0.3, verbose=0)
            if resp is not None and resp.haslayer(TCP):
                # Verifica flags SYN-ACK (0x12) indicando porta aberta
                if resp.getlayer(TCP).flags == 0x12:
                    open_services.append((port, "TCP", description))

    return open_services

def main():
    if len(sys.argv) < 2:
        print("Uso: python media_scanner.py <CIDR_DA_REDE>")
        print("Exemplo: python media_scanner.py 192.168.1.0/24")
        sys.exit(1)

    target_network = sys.argv[1]
    active_devices = discover_hosts(target_network)

    print(f"\n[+] Dispositivos encontrados: {len(active_devices)}\n")
    print(f"{'IP':<16} | {'MAC':<18} | {'Porta/Protocolo Identificado'}")
    print("=" * 85)

    for dev in active_devices:
        services = inspect_device_ports(dev['ip'])
        if services:
            for port, proto, desc in services:
                print(f"{dev['ip']:<16} | {dev['mac']:<18} | [{proto} {port:<5}] {desc}")
        else:
            print(f"{dev['ip']:<16} | {dev['mac']:<18} | Nenhum serviço crítico identificado na lista de varredura.")

if __name__ == "__main__":
    main()