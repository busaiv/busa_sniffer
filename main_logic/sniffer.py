import uuid
import json
from datetime import datetime
import scapy.all as scapy
from scapy.all import Raw
import os
import psutil
from scapy.interfaces import ifaces
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from tqdm import tqdm
from colorama import Fore, Style

def request_saver(request):
    if request:
        request_id = str(uuid.uuid4())
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        request_data = {
            'request_id': request_id,
            'timestamp': timestamp,
            'request': request
        }
        with open('requests.json', 'a', encoding='utf-8') as f:
            f.write(json.dumps(request_data, ensure_ascii=False) + '\n')

def get_process(port):
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
                        app_name = get_process(packet[UDP].sport)
                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport
                    else:
                        app_name = get_process(packet[TCP].sport)
                        src_port = packet[TCP].sport
                        dst_port = packet[TCP].dport

                    request = {
                        'src_dst': f'{src_port} -> {dst_port}',
                        'url': f'{domain}',
                        'app_name': f'{app_name}'
                    }

                    tqdm.write(f'{Fore.MAGENTA}||'
                               f'{Fore.LIGHTRED_EX} {src_port} -> {dst_port} '
                               f'{Fore.MAGENTA}|'
                               f'{Fore.LIGHTBLUE_EX} URL: {domain} '
                               f'{Fore.MAGENTA}|'
                               f'{Fore.LIGHTGREEN_EX}'
                               f' APP: {app_name} '
                               f'{Fore.MAGENTA}||{Style.RESET_ALL}')
                    return request

        except Exception:
            pass
    return None


def params(packet):
    request = packet_process(packet)
    #request_saver(request)

def sniffer():
    scapy.sniff(iface=os.getenv('INTERFACE'), store=False, promisc=True, prn=params)

if __name__ == '__main__':
    sniffer()





