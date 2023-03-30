from scapy.all import *

class Sniffer:
    def __init__(self):
        self.packets = []

    def get_nif(self):
        if_list = [nif.name for nif in get_working_ifaces() if nif.mac]
        return if_list

    def set_nif(self, nif):
        self.nif = nif

    def set_filter(self, filter_str):
        self.filter = filter_str

    def handle(self, packet):
        self.packets.append(packet)

    def start(self):
        self.sniffer = AsyncSniffer(iface=self.nif, prn=self.handle, filter=self.filter)
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
            result.append("\n\n\n\n")
        return result


    def clear(self):
        self.packets.clear()

snif = Sniffer()
nif_list = snif.get_nif()
print(nif_list)

snif.set_nif('以太网')
snif.set_filter(None)
snif.start()
time.sleep(5)
snif.stop()
packets = snif.get_packets()
analyze_result = snif.parse_packets(packets)
# snif.print_packets()
print(analyze_result)