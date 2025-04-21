from scapy.all import get_if_list, get_if_addr, sniff
import psutil

if_list = get_if_list()
print(if_list)
for i in if_list:
    print(get_if_addr(i))


def choice_interface():
    interfaces = psutil.net_if_addrs()
    for i in interfaces:
        print(i)
    interface = input('Enter interface: ')
    return interface

print(choice_interface())

print(sniff(iface=choice_interface(), store=False))