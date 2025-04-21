import scapy.all as scapy
import psutil
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from tqdm import tqdm
from colorama import Fore, Style

requests = []

def choice_interface():
    interfaces = psutil.net_if_addrs()
    for i in interfaces:
        tqdm.write(f'{i}: {interfaces[i]}')
    interface = input('Enter interface: ')
    return interface

def packets_saver(packet):
    request_id = len(requests) + 1
    request = {request_id: packet}
    requests.append(request)

def packet_process(packet):
    tqdm.write(f'{Fore.LIGHTWHITE_EX}------New Packet------')
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        tqdm.write(f'{Fore.LIGHTRED_EX}Source IP: {source_ip} -> Destination IP: {destination_ip}')

    if packet.haslayer(TCP):
        source_tcp = packet[TCP].sport
        destination_tcp = packet[TCP].dport
        tqdm.write(f'{Fore.LIGHTYELLOW_EX}Source TCP: {source_tcp} -> Destination TCP: {destination_tcp}')

    if packet.haslayer(UDP):
        source_udp = packet[UDP].sport
        destination_udp = packet[UDP].dport
        tqdm.write(f'{Fore.LIGHTGREEN_EX}Source UDP: {source_udp} -> Destination UDP: {destination_udp}')

    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        queried_host = packet[DNSQR].qname.decode()
        tqdm.write(f"{Fore.CYAN}DNS Query: {queried_host}")

    tqdm.write(f'{Style.RESET_ALL}')
    tqdm.write(f'{Fore.LIGHTWHITE_EX}------Packet End------\n')

def params(packet):
    packet_process(packet)
    packets_saver(packet)

def sniffer():
    scapy.sniff(store=False, prn=params, filter='udp')

if __name__ == '__main__':
    sniffer()





