🔥 PROJETO DE MONITORAMENTO E ANÁLISE DE TRÁFEGO DE REDE EM TEMPO REAL 🔥

Sistema desenvolvido para escanear, analisar e vigiar redes locais de forma automática, agressiva e inteligente.  
Focado em segurança da informação, varredura de dispositivos e detecção de atividades suspeitas (tipo flood, scan e conexão indevida).

🧠 TECNOLOGIAS E PROTOCOLOS UTILIZADOS:
- ARP + ICMP → Varredura ativa de IPs e descoberta de MACs na rede
- IP Layer + Scapy Sniff → Análise de pacotes ao vivo (detecção de flood por IP)
- Netstat/SS → Monitoramento de conexões TCP/UDP ativas no host
- Python Multithreading → Execução paralela de sniff + scan + detecção

📌 FUNCIONALIDADES ATUAIS:
- Varredura de rede com exibição de IP + MAC
- Detecção de IPs maliciosos (flood/scan)
- Monitoramento de conexões suspeitas em tempo real
- Log de atividades anômalas em arquivo `.log`

🚧 PLANEJAMENTO FUTURO:
- Integração com firewall (iptables)
- Notificação em tempo real (Telegram ou Discord bot)
- Exportação para CSV / Dashboard visual (Tkinter ou Flask)

- PROJECT BY: ADRYAN
