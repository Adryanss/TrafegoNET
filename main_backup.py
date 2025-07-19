import os
import ssl
import socket
import subprocess
import platform
import requests
from scapy.all import sniff, IP, ARP, Ether, srp, IP, ICMP, sr1
from datetime import datetime
import time
import re
from collections import defaultdict
 
print("ANALISE DE TRAFEGO \nAUTHOR: ADRYAN")
os_type = platform.system()
print(f"Sistema operacional: {os_type}")
 
#def get_ssid():      IDEIA PARA O FUTURO
#    ssid = str(input("SSID: "))
#    print(ssid)
#    return ssid
    
 
def get_ssid_auto():
    sistema = platform.system()
 
    try:
        if sistema == "Windows":
            resultado = subprocess.check_output("netsh wlan show interfaces", shell=True).decode('utf-8')
            for linha in resultado.split('\n'):
                if "SSID" in linha and "BSSID" not in linha:
                    ssid = linha.split(":")[1].strip()
                    print(f"SSID Atual: {ssid}")
                    return ssid
                    
        elif sistema == "Linux":
            resultado = subprocess.check_output("iwgetid -r", shell=True).decode('utf-8').strip()
            print(f"SSID Atual: {resultado}")
            return resultado
        
        else:
            print("Sistema operacional não suportado ainda")
            return None
        
    except Exception as erro:
        print(f"Erro ao obter SSID: {erro}")
        return None       
    
 
def tcp_udp(proto):
    sistema = platform.system()
    
    if proto not in ["tcp", "udp"]:
        print("Protocolo inválido")
        return
      
    try:
        if sistema == "Windows":
            comando = ["netstat", "-an"]
        elif sistema == "Linux":
            comando = ["ss", "-tun"]
        else:
            print("Sistema não suportado ainda")
            return
        
        resultado = subprocess.check_output(comando).decode(errors='ignore')
        print(f"Conexões {proto.upper()} ativas:\n")
        for linha in resultado.splitlines():
            if proto.lower() in linha.lower():
                print(linha)
    
    except Exception as erro:
        print(f"erro ao listar conexões {proto.upper()}: {erro}")
 
def protocols():
    sistema = platform.system()
    protocolos_detectados = set()
 
    try:
        if sistema == "Windows":
            comando = ["netstat", "-an"]
            saida = subprocess.check_output(comando).decode('latin1')
        elif sistema == "Linux":
            comando = ["ss", "-tunap"]
            saida = subprocess.check_output(comando).decode('utf-8')
        else:
            print("Sistema não suportado")
            return
 
        print("\nProtocolos em uso no momento:\n")
        for linha in saida.splitlines():
            linha = linha.lower()
            if "tcp" in linha:
                protocolos_detectados.add("TCP")
            if "udp" in linha:
                protocolos_detectados.add("UDP")
            if "icmp" in linha:
                protocolos_detectados.add("ICMP")
            if "arp" in linha:
                protocolos_detectados.add("ARP")
 
        if protocolos_detectados:
            for p in sorted(protocolos_detectados):
                print(f"✅ {p}")
        else:
            print("Nenhum protocolo detectado")
    
    except Exception as erro:
        print(f"Erro ao detectar protocolos: {erro}")
 
 
def ip_dns(ipedns):
    if ipedns == "ip":
        try:
            #local
            ip_local = socket.gethostbyname(socket.gethostname())
            print(f"IP Local: {ip_local}")
 
            #público
            ip_publico = requests.get("https://api.ipify.org").text
            print(f"IP Público: {ip_publico}")
 
        except Exception as erro:
            print(f"Erro ao obter IP: {erro}")
 
    elif ipedns == "dns":
        try:
            dominio = input("Digite o domínio pra resolver (ex: google.com): ").strip()
            ip_resolvido = socket.gethostbyname(dominio)
            print(f"DNS -> IP: {dominio} = {ip_resolvido}")
        except Exception as erro:
            print(f"Erro na resolução DNS: {erro}")
 
    else:
        print("Entrada inválida")
 
 
def doors():
    sistema = platform.system()
 
    print("\nPortas em uso no sistema:\n")
 
    try:
        if sistema == "Windows":
            comando = ["netstat", "-ano"]
            resultado = subprocess.check_output(comando).decode("latin1")
        elif sistema == "Linux":
            comando = ["ss", "-tuln"]
            resultado = subprocess.check_output(comando).decode("utf-8")
        else:
            print("Sistema não suportado ainda")
            return
 
        for linha in resultado.splitlines():
            if ":" in linha:
                print(linha)
 
    except Exception as erro:
        print(f"Erro ao listar portas: {erro}")
 
 
def packet_sniffing():
    print("Iniciando captura de pacotes... (Ctrl+C pra parar)\n")
 
    try:
        sniff(filter="ip", prn=mostrar_pacote, store=0)
    except PermissionError:
        print("PERMISSÃO NEGADA! Roda como ADMINISTRADOR")
    except Exception as erro:
        print(f"Deu ruim na captura: {erro}")
 
def mostrar_pacote(pacote):
    if IP in pacote:
        print(f"{pacote[IP].src} -> {pacote[IP].dst}")
    
def locIP():
    print("localização baseada em ip")
    
def anti_intrusão():
    print("Iniciando detecção de intrusão/anomalias... (Ctrl+C pra parar)")
 
    contagem_ip = defaultdict(int)
    tempo_inicio = time.time()
 
    try:
        def analisar_pacote(pacote):
            if IP in pacote:
                ip_origem = pacote[IP].src
                contagem_ip[ip_origem] += 1
 
                # Se um IP mandar mais de 100 pacotes em 10 segundos, printa o alerta
                if contagem_ip[ip_origem] > 100 and (time.time() - tempo_inicio) < 10:
                    print(f"ALERTA de {ip_origem} - {contagem_ip[ip_origem]} pacotes")
 
        sniff(filter="ip", prn=analisar_pacote, store=0)
 
    except PermissionError:
        print("PERMISSÃO NEGADA! Roda como ADMINISTRADOR, seu mula!")
    except Exception as erro:
        print(f"Erro na detecção: {erro}")
    
def grafico():
    print("Grafico de analise")
 
def arp_icmp(arpeicmp):
    if arpeicmp == "arp":
        print("Iniciando varredura ARP... (descobrindo dispositivos na rede)")
        ip_alvo = input("Digite a faixa de IP (ex: 192.168.0.1/24): ").strip()
        
        pacote = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_alvo)
        resposta, _ = srp(pacote, timeout=2, verbose=0)
 
        for enviado, recebido in resposta:
            print(f"IP: {recebido.psrc} | MAC: {recebido.hwsrc}")
 
    elif arpeicmp == "icmp":
        print("📡 Enviando pacote ICMP (PING)")
        destino = input("Digite o IP ou domínio a ser testado (ex: 8.8.8.8): ").strip()
 
        pacote = IP(dst=destino) / ICMP()
        resposta = sr1(pacote, timeout=2, verbose=0)
 
        if resposta:
            print(f"Resposta recebida de {destino} | TTL: {resposta.ttl}")
        else:
            print("Sem resposta. O alvo ignorou ou está offline.")
 
    else:
        print("Opção inválida")
 
def logs():
    print("logs")
    
 
def supIPV6():
    print("ipv6")
    
 
def tls_ssl(tlsessl):
    if tlsessl not in ["tls", "ssl"]:
        print("Opção inválida, digita 'tls' ou 'ssl', seu tapado!")
        return
 
    host = input("Digite o domínio (ex: google.com): ").strip()
    porta = 443  # padrão pra HTTPS/TLS
 
    contexto = ssl.create_default_context()
 
    try:
        with socket.create_connection((host, porta)) as sock:
            with contexto.wrap_socket(sock, server_hostname=host) as conexao_tls:
                cert = conexao_tls.getpeercert()
                protocolo = conexao_tls.version()
                validade = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
 
                print(f"\n {tlsessl.upper()} ATIVO EM {host}")
                print(f" Versão: {protocolo}")
                print(f" Válido até: {validade}")
 
    except Exception as erro:
        print(f"Não foi possível validar {tlsessl.upper()} pra {host}: {erro}")
    
 
conection = {
    "ssid": get_ssid_auto,
    "tcp": lambda: tcp_udp("tcp"),
    "udp": lambda: tcp_udp("udp"),
    "protocol" : protocols,
    "ip" : lambda: ip_dns ("ip"),
    "dns" : lambda: ip_dns ("dns"),
    "doors" : doors,
    "sniffing" : packet_sniffing,
    "locip" : locIP,
    "intrusion" : anti_intrusão,
    "graphic" : grafico,
    "arp" : lambda: arp_icmp ("arp"),
    "icmp" : lambda: arp_icmp ("icmp"),
    "logs" : logs,
    "ipv6" : supIPV6,
    "tls" : lambda: tls_ssl ("tls"),
    "ssl" : lambda: tls_ssl ("ssl")
}
 
while True:
    user = str(input(">>")).strip().lower()
    if user in conection:
        resultado = conection[user]()
        print("funcionando")
 
    elif user == "/all":
        for nome, func in conection.items():
            print(f"\nExecutando {nome.upper()}:")
            func()
    
    elif user == "exit":
        break
    
    elif user == "help":
        with open ("help.txt", "r") as f:
            help = f.read()
            print(help)
 
    else:
        print("incorreto")
 