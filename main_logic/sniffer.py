from os import write

import scapy.all as scapy
from scapy.all import Raw
import os
import psutil
from scapy.interfaces import ifaces
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from tqdm import tqdm
from colorama import Fore, Style

requests = []
requests.clear()

def packets_saver(packet):
    request_id = len(requests) + 1
    request = {request_id: packet}
    requests.append(request)

def get_process_by_port(port):
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr and conn.laddr.port == port:
            pid = conn.pid
            if pid:
                try:
                    proc = psutil.Process(pid)
                    return proc.name()
                except psutil.NoSuchProcess:
                    return None
    return None

def packet_process(packet):
    if (packet.haslayer(UDP) or packet.haslayer(TCP)) and packet.haslayer(Raw) and packet[Raw].load:
        try:
            dns = DNS(packet[Raw].load)
            if dns.qr == 0 and dns.qd:
                domain = dns.qd.qname.decode('utf-8').rstrip('.')
                if domain and 'HTTP' not in domain and (all(i.isprintable() for i in domain)) and '.' in domain:
                    if packet.haslayer(UDP):
                        app_name = get_process_by_port(packet[UDP].sport)
                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport
                    else:
                        app_name = get_process_by_port(packet[TCP].sport)
                        src_port = packet[TCP].sport
                        dst_port = packet[TCP].dport

                    tqdm.write(f'{Fore.MAGENTA}||'f'{Fore.LIGHTRED_EX} {src_port} -> {dst_port} '
                               f'{Fore.MAGENTA}|'f'{Fore.LIGHTBLUE_EX} URL: {domain}'f'{Fore.MAGENTA} '
                               f'{Fore.MAGENTA}|'f'{Fore.LIGHTGREEN_EX} APP: {app_name} {Style.RESET_ALL}'
                               f'{Fore.MAGENTA}||')
        except Exception:
            pass


def params(packet):
    packet_process(packet)
    #packets_saver(packet)

def sniffer():
    scapy.sniff(iface=os.getenv('INTERFACE'), store=False, promisc=True, prn=params)

if __name__ == '__main__':
    sniffer()





