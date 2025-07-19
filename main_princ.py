import os
import ssl
import socket
import subprocess
import platform
import requests
from scapy.all import sniff, IP, ARP, Ether, srp, ICMP, sr1
from datetime import datetime
import time
import re
from collections import defaultdict
import ipaddress
import netifaces
import threading
 
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

def mostrar_pacote(pacote):
    if IP in pacote:
        print(f"{pacote[IP].src} -> {pacote[IP].dst}")       


def analise_menu():
    while True:
        print("\n=== MODO SEGURANÇA ===")
        print("1 - Sniffing")
        print("2 - Localização IP")
        print("3 - Logs")
        print("0 - Voltar")
        escolha = input(">> ").strip()


        if escolha == "1":
            print("Iniciando captura de pacotes... (Ctrl+C pra parar)\n")
    
            try:
                sniff(filter="ip", prn=mostrar_pacote, store=0)
            except PermissionError:
                print("PERMISSÃO NEGADA! Roda como ADMINISTRADOR")
            except Exception as erro:
                print(f"Deu ruim na captura: {erro}")

        elif escolha == "2":
            print("localização baseada em ip")
 
        elif escolha == "3":
            print("logs")

        elif escolha == "0":
            break







def security_menu():
    while True:
        print("\n=== MODO SEGURANÇA ===")
        print("2 - anti-intrusão com tcp/udp/sniff")
        print("3 - Varredura de IP+MAC com icmp/arp")
        print("4 - Logs")
        print("0 - Voltar")
        escolha = input(">> ").strip()

        #ANTI-INTRUSÃO
        if escolha == "2":
            ips_suspeitos = set()
            lock = threading.Lock()
            contagem_ip = defaultdict(int)
            tempo_inicio = time.time()
            
            def detectar_intrusao():
                print("Iniciando detecção de intrusão/anomalias... (Ctrl+C pra parar)")
            
            def analisar_pacote(pacote):
                if IP in pacote:
                    ip_origem = pacote[IP].src
                    with lock:
                        contagem_ip[ip_origem] += 1
                        if contagem_ip[ip_origem] > 100 and (time.time() - tempo_inicio) < 10:
                            print(f"[INTRUSÃO] {ip_origem} mandou {contagem_ip[ip_origem]} pacotes.")
                            ips_suspeitos.add(ip_origem)
                
            sniff(filter="ip", prn=analisar_pacote, store=0)
            

            def monitorar_conexoes():
                sistema = platform.system()
                comando = ["netstat", "-an"] if sistema == "Windows" else ["ss", "-tun"]

                while True:
                    try:
                        resultado = subprocess.check_output(comando).decode(errors='ignore')
                        for linha in resultado.splitlines():
                            with lock:
                                for ip in ips_suspeitos:
                                    if ip in linha:
                                        print(f"[CONEXÃO SUSPEITA] IP {ip} com conexão ativa ⚠️")
                    except Exception as erro:
                        print(f"[ERRO MONITOR] {erro}")
                    time.sleep(5)

            t1 = threading.Thread(target=detectar_intrusao)
            t2 = threading.Thread(target=monitorar_conexoes)

            t1.start()
            t2.start()

            t1.join()
            t2.join()
 
            #ARP+ICMP
        elif escolha == "3":
            dhcp = netifaces.gateways()
            ip_gateway = dhcp['default'][2][0]


            rede = ipaddress.IPv4Network(f"{ip_gateway}/24", strict=False)

            positivos = []

            for ip in rede.hosts():
                try:
                    resposta = subprocess.check_output(f"ping -n 1 -w 200 {ip}", shell=True, stderr=subprocess.DEVNULL)
        
                    ip_str = str(ip)
                    print(f"[+] {ip_str} ATIVO")
                    positivos.append(ip_str)

                    pacote = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_str)
                    resposta_arp, _ = srp(pacote, timeout=2, verbose=0)
                    if resposta_arp:
                        for _, recebido in resposta_arp:
                            mac = recebido.hwsrc
                        print(f"[ARP] {ip_str} -> {mac}")
                    else:
                        print("Não foi possivel receber o MAC verificar se há bloqueio")

                except subprocess.CalledProcessError: 
                    pass

                #logs

        elif escolha == "4":
            print("logs")


                #voltar
        elif escolha == "0":
            break





conection = {
    "ssid": get_ssid_auto,
    "security" : security_menu,
    "analise" : analise_menu
}

while True:
    print("DIGITE SECURITY/ANALISE PARA MAIS OPÇÕES")
    user = str(input(">>")).strip().lower()
    if user in conection:
        resultado = conection[user]()
 
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
 