import scapy.all as scapy
import os
import psutil
from scapy.interfaces import ifaces
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from tqdm import tqdm
from colorama import Fore, Style

requests = []
requests.clear()

# def choice_interface():
#     interfaces = psutil.net_if_addrs()
#     for i in interfaces:
#         tqdm.write(f'{i}: {interfaces[i]}')
#     interface = input('Enter interface: ')
#     return interface

def packets_saver(packet):
    request_id = len(requests) + 1
    request = {request_id: packet}
    requests.append(request)

def packet_process(packet):
    tqdm.write(f'{Fore.LIGHTWHITE_EX}------New Packet------')
    tqdm.write(f'{Fore.LIGHTCYAN_EX}Raw Packet Data: {packet.show(dump=True)}')
    tqdm.write(f'{Style.RESET_ALL}')
    tqdm.write(f'{Fore.LIGHTWHITE_EX}------Packet End------\n')

def params(packet):
    packet_process(packet)
    #packets_saver(packet)

def sniffer():
    scapy.sniff(iface=os.getenv('INTERFACE'), store=False, promisc=True, prn=params)

if __name__ == '__main__':
    sniffer()





