import json

from scapy.all import *
import scapy.utils
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP, ICMP, UDP, IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP

# 创建一个字典来存储捕获到的数据包的详细信息
packets = []

# 回调函数，处理捕获到的数据包
def packet_handler(packet):
    packet_dict = {}

    # 解析以太网层协议

    eth_dict = {}

    # 添加更多的以太网层信息
    eth_dict["dst"] = packet[Ether].dst
    eth_dict["src"] = packet[Ether].src
    eth_dict["type"] = packet[Ether].type
    eth_dict["len"] = len(packet[Ether])
    eth_dict["flags"] = getattr(packet[Ether], 'flags', "N/A")
    eth_dict["tos"] = getattr(packet[Ether], 'tos', "N/A")
    eth_dict["vlan"] = getattr(packet[Ether], 'vlan', "VLAN tag not present")
    eth_dict["priority"] = getattr(packet[Ether], 'priority', "N/A")
    eth_dict["id"] = getattr(packet[Ether], 'id', "N/A")
    eth_dict["version"] = getattr(packet[Ether], 'version', "N/A")

    packet_dict["Ethernet"] = eth_dict

    if ARP in packet:
        arp_dict = {}
        arp_dict["hwtype"] = packet[ARP].hwtype
        arp_dict["ptype"] = packet[ARP].ptype
        arp_dict["hwlen"] = packet[ARP].hwlen
        arp_dict["plen"] = packet[ARP].plen
        arp_dict["op"] = packet[ARP].op
        arp_dict["hwsrc"] = packet[ARP].hwsrc
        arp_dict["psrc"] = packet[ARP].psrc
        arp_dict["hwdst"] = packet[ARP].hwdst
        arp_dict["pdst"] = packet[ARP].pdst
        packet_dict["ARP"] = arp_dict
    # 解析IP层协议
    if IP in packet:
        ip_dict = {}
        ip_dict["src"] = packet[IP].src
        ip_dict["dst"] = packet[IP].dst
        ip_dict["proto"] = packet[IP].proto

        # 添加更多的IP层信息
        ip_dict["version"] = packet[IP].version
        ip_dict["ihl"] = packet[IP].ihl
        ip_dict["tos"] = packet[IP].tos
        ip_dict["len"] = packet[IP].len
        ip_dict["id"] = packet[IP].id
        ip_dict["flags"] = packet[IP].flags
        ip_dict["frag"] = packet[IP].frag
        ip_dict["ttl"] = packet[IP].ttl

        packet_dict["IP"] = ip_dict

        # 解析TCP层协议
        if TCP in packet:
            tcp_dict = {}
            tcp_dict["sport"] = getattr(packet[TCP], 'sport', "N/A")
            tcp_dict["dport"] = getattr(packet[TCP], 'dport', "N/A")
            tcp_dict["seq"] = getattr(packet[TCP], 'seq', "N/A")
            tcp_dict["ack"] = getattr(packet[TCP], 'ack', "N/A")
            tcp_dict["flags"] = getattr(packet[TCP], 'flags', "N/A")
            tcp_dict["window"] = getattr(packet[TCP], 'window', "N/A")
            tcp_dict["urgptr"] = getattr(packet[TCP], 'urgptr', "N/A")
            packet_dict["TCP"] = tcp_dict
            data =  getattr(packet[TCP], 'payload', b'')
            if len(data) > 0:
                packet_dict["TCP_data"] = data

        # 解析UDP层协议
        if UDP in packet:
            udp_dict = {}
            udp_dict["sport"] = getattr(packet[UDP], 'sport', "N/A")
            udp_dict["dport"] = getattr(packet[UDP], 'dport', "N/A")
            udp_dict["len"] = getattr(packet[UDP], 'len', "N/A")
            packet_dict["UDP"] = udp_dict
            data = getattr(packet[UDP], 'payload', b'')
            if len(data) > 0:
                packet_dict["UDP_data"] = data

            # 解析DNS协议
            if DNS in packet:
                dns_dict = {}
                dns_dict["id"] = getattr(packet[DNS], 'id', "N/A")
                dns_dict["qdcount"] = getattr(packet[DNS], 'qdcount', "N/A")
                dns_dict["qr"] = getattr(packet[DNS], 'qr', "N/A")
                dns_dict["qname"] = getattr(packet[DNS], 'qname', "N/A")
                dns_dict["qtype"] = getattr(packet[DNS], 'qtype', "N/A")
                dns_dict["qclass"] = getattr(packet[DNS], 'qclass', "N/A")
                packet_dict["DNS"] = dns_dict

            # 解析DHCP协议
            if DHCP in packet:
                dhcp_dict = {}
                dhcp_dict["options"] = getattr(packet[DHCP], 'options', "N/A")
                dhcp_dict["options_raw"] = getattr(packet[DHCP], 'options_raw', "N/A")
                dhcp_dict["optionslen"] = getattr(packet[DHCP], 'optionslen', "N/A")
                dhcp_dict["op"] = getattr(packet[DHCP], 'op', "N/A")
                dhcp_dict["htype"] = getattr(packet[DHCP], 'htype', "N/A")
                dhcp_dict["hlen"] = getattr(packet[DHCP], 'hlen', "N/A")
                dhcp_dict["hops"] = getattr(packet[DHCP], 'hops', "N/A")
                dhcp_dict["xid"] = getattr(packet[DHCP], 'xid', "N/A")
                dhcp_dict["secs"] = getattr(packet[DHCP], 'secs', "N/A")
                dhcp_dict["flags"] = getattr(packet[DHCP], 'flags', "N/A")
                dhcp_dict["ciaddr"] = getattr(packet[DHCP], 'ciaddr', "N/A")
                dhcp_dict["yiaddr"] = getattr(packet[DHCP], 'yiaddr', "N/A")
                dhcp_dict["siaddr"] = getattr(packet[DHCP], 'siaddr', "N/A")
                dhcp_dict["giaddr"] = getattr(packet[DHCP], 'giaddr', "N/A")
                dhcp_dict["chaddr"] = getattr(packet[DHCP], 'chaddr', "N/A")
                packet_dict["DHCP"] = dhcp_dict

            # 解析HTTP协议
            if TCP in packet:

                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    http_dict = {}
                    http_dict["method"] = getattr(packet[TCP].payload, 'method', "N/A")
                    http_dict["host"] = getattr(packet[TCP].payload, 'host', "N/A")
                    http_dict["path"] = getattr(packet[TCP].payload, 'path', "N/A")
                    http_dict["user_agent"] = getattr(packet[TCP].payload, 'User-Agent', "N/A")
                    http_dict["accept"] = getattr(packet[TCP].payload, 'Accept', "N/A")
                    http_dict["accept_language"] = getattr(packet[TCP].payload, 'Accept-Language', "N/A")
                    http_dict["accept_encoding"] = getattr(packet[TCP].payload, 'Accept-Encoding', "N/A")
                    http_dict["referer"] = getattr(packet[TCP].payload, 'Referer', "N/A")
                    http_dict["cookie"] = getattr(packet[TCP].payload, 'Cookie', "N/A")
                    http_dict["content_type"] = getattr(packet[TCP].payload, 'Content-Type', "N/A")
                    packet_dict["HTTP"] = http_dict

            # 解析FTP协议
            if TCP in packet:
                if packet[TCP].dport == 21 or packet[TCP].sport == 21:
                    ftp_dict = {}
                    ftp_dict["user"] = getattr(packet[TCP].payload, 'user', "N/A")
                    ftp_dict["pass"] = getattr(packet[TCP].payload, 'pass', "N/A")
                    ftp_dict["cmd"] = getattr(packet[TCP].payload, 'cmd', "N/A")
                    ftp_dict["response"] = getattr(packet[TCP].payload, 'resp', "N/A")
                    packet_dict["FTP"] = ftp_dict

            # 解析SSH协议
            if TCP in packet:
                if packet[TCP].dport == 22 or packet[TCP].sport == 22:
                    ssh_dict = {}
                    ssh_dict["packet_type"] = getattr(packet[TCP].payload, 'packet_type', "N/A")
                    ssh_dict["message"] = getattr(packet[TCP].payload, 'message', "N/A")
                    ssh_dict["cipher"] = getattr(packet[TCP].payload, 'cipher', "N/A")
                    ssh_dict["keysize"] = getattr(packet[TCP].payload, 'keysize', "N/A")
                    ssh_dict["lang"] = getattr(packet[TCP].payload, 'lang', "N/A")
                    ssh_dict["cookie"] = getattr(packet[TCP].payload, 'cookie', "N/A")
                    packet_dict["SSH"] = ssh_dict
            if IPv6 in packet:
                ipv6_dict = {}
                ipv6_dict["src"] = packet[IPv6].src
                ipv6_dict["dst"] = packet[IPv6].dst
                ipv6_dict["version"] = packet[IPv6].version
                ipv6_dict["traffic_class"] = packet[IPv6].tc
                ipv6_dict["flow_label"] = packet[IPv6].fl
                ipv6_dict["next_header"] = packet[IPv6].nh
                ipv6_dict["hop_limit"] = packet[IPv6].hlim
                packet_dict["IPv6"] = ipv6_dict

            if ICMP in packet:
                icmp_dict = {}
                icmp_dict["type"] = packet[ICMP].type
                icmp_dict["code"] = packet[ICMP].code
                icmp_dict["id"] = packet[ICMP].id
                icmp_dict["seq"] = packet[ICMP].seq
                packet_dict["ICMP"] = icmp_dict

            packet_dict["Raw_data"] = scapy.utils.hexdump(packet, dump=True)



            # 解析SSL/TLS协议
            # 解析 SSL/TLS 协议
            if TCP in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
                tls_dict = {}
                tls_dict["content_type"] = getattr(packet[TCP].payload, 'content_type', "N/A")
                tls_dict["version"] = getattr(packet[TCP].payload, 'version', "N/A")
                tls_dict["cipher"] = getattr(packet[TCP].payload, 'cipher', "N/A")
                packet_dict["SSL/TLS"] = tls_dict

    # 将当前捕获的数据包信息存储到列表中
    packets.append(packet_dict)

def start_sniffing():
    # 开始监听网络流量
    sniff(iface="WLAN", prn=packet_handler, count=1000)
    # show_packet(0)
    show_packets()
def save_packets():
    # 将捕获的数据包信息写入到文件中
    with open("packets.json", "w") as f:
        json.dump(packets, f, indent=4)

def show_packet(packet_number):
    # 显示指定序号的数据包信息
    packet_info = packets[packet_number]
    for layer_name, layer_info in packet_info.items():
        print(f"Layer: {layer_name}")
        if hasattr(layer_info, 'items'):
            for field_name, field_value in layer_info.items():
                print(f"\t{field_name}: {field_value}")
        else:
            print(f"\t{layer_info}")



def show_packets():
    for packet_number, packet_info in enumerate(packets):
        print(f"Packet {packet_number + 1}:")
        for layer_name, layer_info in packet_info.items():
            print(f"\tLayer: {layer_name}")
            if hasattr(layer_info, 'items'):
                for field_name, field_value in layer_info.items():
                    print(f"\t\t{field_name}: {field_value}")
            else:
                print(f"\t\t{layer_info}")

def get_src_and_dst(packet):
    if packet.haslayer('IP'):
        src = packet['IP'].src
        dst = packet['IP'].dst
    else:
        src = packet[0].src
        dst = packet[0].dst
        if dst == 'ff:ff:ff:ff:ff:ff':
            dst = 'Broadcast'
    return src, dst

start_sniffing()