from scapy.all import *
import signal
from PyQt5.QtWidgets import *
from packet_info import PacketInfo
class Sniffer:
    def __init__(self,_ui: QWidget):
        self.packets = []
        self.packet = None
        self.signal = signal.Signals()
        self.ui: QWidget = _ui
        self.nif = ''
        self.number = 0
        self.time = 0
        self.is_running = False
        self.signals = signal.Signals()




    def get_nif(self):
        if_list = [nif.name for nif in get_working_ifaces() if nif.mac]
        return if_list

    def set_nif(self, nif):
        self.nif = nif

    def set_filter(self, filter_str):
        self.filter = filter_str

    def handle(self, packet):
        self.number += 1
        self.packet = packet

        self.packets.append(packet)
        raw_data = packet.show(dump=True)
        hex_info = hexdump(packet, dump=True)
        time = str(packet.time-self.time)
        src, dst = self.get_src_and_dst()
        protocol = self.get_protocol()

        length = len(packet)
        info = self.get_info(protocol)
        packet_info = PacketInfo()
        payload = str(bytes(packet.payload.payload.payload))
        packet_info.from_args(self.number, time, src, dst, protocol, length, info, raw_data, hex_info, payload)
        self.packets.append(packet_info)

        self.signals.update_table.emit(packet_info)

    def start(self):
        self.nif = self.ui.nif_combobox.currentText()
        self.time = time.time()
        if self.nif == '选择网卡':
            return
        self.sniffer = AsyncSniffer(iface=self.nif, prn=self.handle, filter=None)
        print(111111111111111111111111111111111111111111111111111)
        self.sniffer.start()

    def stop(self):
        self.sniffer.stop()

    def get_packets(self):
        return self.packets

    def print_packets(self):
        for packet in self.packets:
            packet.show()

    def get_packet(self, index):
        return self.packets[index]

    def analyze_protocol(self, packet):
        protocol_list = packet.summary().split('/')
        arp_protocol_list = ['ARP', 'RARP', 'DHCP']
        for protocol in arp_protocol_list:
            if protocol in protocol_list[1]:
                return protocol
        if 'IP' in protocol_list[1]:
            if 'Raw' in protocol_list[-1] or 'Padding' in protocol_list[-1]:
                upper_protocol = protocol_list[-2]
            else:
                upper_protocol = protocol_list[-1]
            return upper_protocol.strip().split(' ')[0]


    def parse_packet(self, packet):

        # 解析物理层协议（以太网）

        ether_fields = {}

        ether = packet.getlayer('Ether')

        if ether:
            ether_fields = {"source": ether.src, "destination": ether.dst, "type": ether.type}

        # 解析网络层协议（IPv4或IPv6）

        ip_fields = ipv6_fields = {}

        if packet.haslayer('IP'):

            ip = packet.getlayer('IP')

            ip_fields = {"version": ip.version, "source": ip.src, "destination": ip.dst, "protocol": ip.proto,
                         "ttl": ip.ttl}

        elif packet.haslayer('IPv6'):

            ipv6 = packet.getlayer('IPv6')

            ipv6_fields = {"version": ipv6.version, "source": ipv6.src, "destination": ipv6.dst,
                           "protocol": ipv6.nh}

        # 解析传输层协议（TCP或UDP）

        tcp_fields = udp_fields = {}

        if packet.haslayer('TCP'):

            tcp = packet.getlayer('TCP')

            tcp_fields = {"source_port": tcp.sport, "destination_port": tcp.dport, "sequence_number": tcp.seq,
                          "ack_number": tcp.ack}

        elif packet.haslayer('UDP'):

            udp = packet.getlayer('UDP')

            udp_fields = {"source_port": udp.sport, "destination_port": udp.dport}

        # 解析应用层协议（HTTP或SMTP）

        http_fields = smtp_fields = {}

        if packet.haslayer('HTTP'):

            http = packet.getlayer('HTTP')

            http_fields = {"method": http.Method, "host": http.Host, "path": http.Path,
                           "user_agent": http.User_Agent}

        elif packet.haslayer('SMTP'):

            smtp = packet.getlayer('SMTP')

            smtp_fields = {"command": smtp.command, "response": smtp.response}

        # 返回一个包含所有解析结果的字典

        fields = {"ethernet": ether_fields, "ip": ip_fields, "ipv6": ipv6_fields, "tcp": tcp_fields,
                  "udp": udp_fields,

                  "http": http_fields, "smtp": smtp_fields}

        return fields

    def parse_packets(self, packets):
        result = []
        for packet in packets:
            result.append(self.parse_packet(packet))
        return result

    def get_src_and_dst(self):
        if self.packet.haslayer('IP'):
            src = self.packet['IP'].src
            dst = self.packet['IP'].dst
        else:
            src = self.packet[0].src
            dst = self.packet[0].dst
            if dst == 'ff:ff:ff:ff:ff:ff':
                dst = 'Broadcast'
        return src, dst


    def clear(self):
        self.packets.clear()


    def get_packet_summary(self, packet):
        return packet.summary()
    # Scapy Packet 对象有一个内置的方法 summary()，可以返回这个数据包的简要信息，包括源 IP 和目标 IP、协议类型、源端口和目标端口，以及一些其他相关信息。

    def get_packet_payload(self, packet):
        return packet.payload
#     从给定的 Scapy Packet 对象中提取出 payload 部分（即有效载荷）。
#     payload 是指一个 IP 封包中从 IP 头部之后开始的那部分数据，
#     也就是说，它是一个 IP 封包的正文部分。不同类型的网络协议有不同的 payload 格式，
#     比如在 TCP 协议中，payload 就是数据流，而在 ICMP 协议中，payload 则可以包含错误信息等等。
#     在这里，这个方法将被用于提取某个数据包的 payload 部分，以进行进一步的数据分析。

    def get_protocol(self):
        protocol_list = self.packet.summary().split('/')
        # protocol_list:  ['Ether ', ' IP ', ' TCP 192.168.31.253:8051 > 175.27.204.206:https FA']
        # print(protocol_list)
        arp_protocol_list = ['ARP', 'RARP', 'DHCP']
        # arp protocol_list:  ['Ether ', ' ARP who has 192.168.31.1 says 192.168.31.253']
        for protocol in arp_protocol_list:
            if protocol in protocol_list[1]:
                return protocol
        if 'IP' in protocol_list[1]:
            if 'Raw' in protocol_list[-1] or 'Padding' in protocol_list[-1]:
                upper_protocol = protocol_list[-2]
            else:
                upper_protocol = protocol_list[-1]
            return upper_protocol.strip().split(' ')[0]
        # if 'TCP' in p.summary
        # ipv6:
        # ['Ether ', ' IPv6 ', ' UDP ', ' DNS Ans "fe80::10e1:13bd:be7:8c38" ']
        elif 'IPv6' in protocol_list[1]:
            return 'IPv6/' + protocol_list[2].strip().split(' ')[0]
        # DNS and others
        else:
            protocol = protocol_list[2].strip().split(' ')[0]
            if protocol != '':
                protocol += '/'
            protocol += protocol_list[2].split(' ')[1]
            return protocol

    def get_info(self, protocol):
        protocol_list = self.packet.summary().split("/")
        if "Ether" in protocol_list[0]:
            # protocol = self.get_protocol(p)
            # arp protocol_list:  ['Ether ', ' ARP who has 192.168.31.1 says 192.168.31.253']
            # ['Ether ', ' ARP is at 54:48:e6:99:c9:1c says 192.168.31.1']
            if 'ARP' in protocol:
                arp_info = protocol_list[1].strip()
                pattern_request = r'ARP who has (\S+) says (\S+)'
                pattern_reply = r'ARP is at (\S+) says (\S+)'
                if match := re.match(pattern_request, arp_info):
                    target = match.group(1)
                    sender = match.group(2)
                    info = f'Who has {target}? Tell {sender}'
                elif match := re.match(pattern_reply, arp_info):
                    mac = match.group(1)
                    sender = match.group(2)
                    info = f'{sender} is at {mac}'
                else:
                    info = protocol_list[1].strip()
            # DNS protocol_list:  ['Ether ', ' IP ', ' UDP ', ' DNS Qry "b\'lb._dns-sd._udp.local.\'" ']
            elif 'DNS' in protocol:
                info = protocol_list[-1].strip()
            # tcp/udp ['Ether ', ' IP ', ' UDP 192.168.31.253:54915 > 172.19.83.255:54915 ', ' Raw']
            elif 'TCP' in protocol or 'UDP' in protocol:
                info = ' '.join(protocol_list[2:]).strip()
            else:
                info = ' '.join(protocol_list[1:]).strip()
            return info
        else:
            return self.packet.summary()

    def get_packet_hexdump(self, packet):
        return packet.hexdump()

    def get_packet_len(self, packet):
        return packet.len



#
# snif = Sniffer()
# nif_list = snif.get_nif()
# print(nif_list)
#
# snif.set_nif('以太网')
# snif.set_filter(None)
# snif.start()
# time.sleep(2)
# snif.stop()
# packets = snif.get_packets()
# # analyze_results = snif.parse_packets(packets)
# # snif.print_packets()
# # print(analyze_results)
#
# # hex_data = packets[0].hexdump()
# #
# # print(hex_data)
#
# packet_hex_data = snif.get_packet_hexdump(packets[0])
# print(packet_hex_data)
# packet_len = snif.get_packet_len(packets[0])
# print(packet_len)
# packet_payload = snif.get_packet_payload(packets[0])
# print(packet_payload)
# packet_summary = snif.get_packet_summary(packets[0])
# print(packet_summary)
#
# # hex_data = packets[0].hexdump()
# # print(hex_data)