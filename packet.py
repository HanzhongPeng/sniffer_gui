from PyQt5.QtGui import *
import re


ethernet_pattern = r'''###\[ Ethernet \]### 
  dst       = (.*)
  src       = (.*)
  type      = (.*)'''

ip_pattern = r'''###\[ IP \]### 
     version   = (.*)
     ihl       = (.*)
     tos       = (.*)
     len       = (.*)
     id        = (.*)
     flags     = (.*)
     frag      = (.*)
     ttl       = (.*)
     proto     = (.*)
     chksum    = (.*)
     src       = (.*)
     dst       = (.*)
     \\options   \\'''

ipv6_pattern = r'''###\[ IPv6 \]### 
     version   = (.*)
     tc        = (.*)
     fl        = (.*)
     plen      = (.*)
     nh        = (.*)
     hlim      = (.*)
     src       = (.*)
     dst       = (.*)'''

tcp_pattern = r'''###\[ TCP \]### 
        sport     = (.*)
        dport     = (.*)
        seq       = (.*)
        ack       = (.*)
        dataofs   = (.*)
        reserved  = (.*)
        flags     = (.*)
        window    = (.*)
        chksum    = (.*)
        urgptr    = (.*)
        options   = (.*)'''

udp_pattern = r'''###\[ UDP \]### 
        sport     = (.*)
        dport     = (.*)
        len       = (.*)
        chksum    = (.*)'''

arp_pattern = r'''###\[ ARP \]### 
     hwtype    = (.*)
     ptype     = (.*)
     hwlen     = (.*)
     plen      = (.*)
     op        = (.*)
     hwsrc     = (.*)
     psrc      = (.*)
     hwdst     = (.*)
     pdst      = (.*)'''

icmp_pattern = r'''###\[ ICMP \]### 
        type      = (.*)
        code      = (.*)
        chksum    = (.*)
        id        = (.*)
        seq       = (.*)
        unused    = (.*)'''

raw_pattern = r'''###\[ Raw \]### 
           load      = (.*)'''

padding_pattern = r'''###\[ Padding \]### 
           load      = (.*)'''

http_pattern = r'HTTP/1\.\d\s+(\w+)\s+(.*)\r\n((.*:.*\r\n)*)\r\n(.*)'



class PacketInfo:

    def __init__(self):

        self.number = None
        self.time = None
        self.protocol = None
        self.src = None
        self.dst = None
        self.length = None
        self.info = None
        self.detail_info = {}
        self.raw_data = None
        self.hex_info = None
        self.payload = None
        self.color = None

    def from_args(self, number, time, src, dst, protocol, length, info, raw_data, hex_info, payload=''):
        self.number = number
        self.time = time
        self.protocol = protocol
        self.src = src
        self.dst = dst
        self.length = length
        self.info = info
        self.detail_info = {}
        self.raw_data = raw_data
        self.hex_info = hex_info
        self.payload = payload

        self.get_color()
        self.get_detail()

    def from_dict(self, packet_dict: dict):
        for key, value in packet_dict.items():
            self.__dict__[key] = value
        self.get_color()

    def get_color(self):
        if self.protocol == 'TCP':
            self.color = QColor('#FFC947')  # yellow
        elif self.protocol == 'UDP' or self.protocol == 'DNS':
            self.color = QColor('#00BFFF')  # blue
        elif self.protocol == 'ICMP':
            self.color = QColor('#FF5733')  # orange
        elif self.protocol == 'ARP':
            self.color = QColor('#00FF00')  # green
        elif self.protocol == 'IPv6':
            self.color = QColor('#FF0000')  # red
        elif self.protocol == 'ICMPv6':
            self.color = QColor('#FF00FF')  # purple
        elif self.protocol == 'IPv6ExtHdrHopByHop/IPv6ExtHdrHopByHop':
            self.color = QColor('#FF11FF')
        elif self.protocol == 'Raw/Raw':
            self.color = QColor('#0022FF')
        elif self.protocol == 'DHCP6OptOptReq':
            self.color = QColor('#0033FF')
        elif self.protocol == 'LLMNRQuery':
            self.color = QColor('#0044FF')
        else:
            self.color = QColor('#FFFFFF')  # white

    def get_detail(self):
        # print(self.raw_data)
        pattern = r'###\[ (\w+) \]###'
        layers = re.findall(pattern, self.raw_data)
        self.detail_info = self.detail_info.fromkeys(layers)
        if 'Ethernet' in layers:
            match = re.search(ethernet_pattern, self.raw_data)
            self.detail_info['Ethernet'] = {'dst(目的地址)': match.group(1),
                                            'src(源地址)': match.group(2),
                                            'type(类型)': match.group(3)}
        if 'IP' in layers:
            match = re.search(ip_pattern, self.raw_data)
            attributes = ['version(版本)', 'ihl(报头长度)', 'tos(服务类型)', 'len(总长度)', 'id(标识)', 'flags(分段标志)',
                          'frag(段偏移)', 'ttl(生存期)', 'proto(协议)', 'chksum(校验和)', 'src(源地址)', 'dst(目的地址)']
            self.detail_info['IP'] = dict.fromkeys(attributes)
            for i, attr in enumerate(attributes):
                self.detail_info['IP'][attr] = match.group(i + 1)
        if 'IPv6' in layers:
            match = re.search(ipv6_pattern, self.raw_data)
            attributes = ['vsersion(版本)', 'tc(流量分类)', 'fl(流标签)', 'plen(有效载荷长度)', 'nh(下一个头类型)',
                          'hlim(最大跳数)', 'src(源地址)', 'dst(目的地址)']
            self.detail_info['IPv6'] = dict.fromkeys(attributes)
            for i, attr in enumerate(attributes):
                self.detail_info['IPv6'][attr] = match.group(i + 1)
        if 'TCP' in layers:
            match = re.search(tcp_pattern, self.raw_data)
            attributes = ['sport(源端口)', 'dport(目的端口)', 'seq(序号)', 'ack(确认号)', 'dataofs(数据偏移)',
                          'reserved(保留位)', 'flags(标志位)', 'window(窗口大小)', 'chksum(校验和)', 'urgptr(紧急指针)',
                          'options(选项)']
            self.detail_info['TCP'] = dict.fromkeys(attributes)
            for i, attr in enumerate(attributes):
                self.detail_info['TCP'][attr] = match.group(i + 1)
        if 'HTTP' in layers:
            match = re.search(http_pattern, self.raw_data)
            attributes = ['method(方法)', 'url(地址)', 'version(版本)', 'headers(头部)', 'body(正文)']
            self.detail_info['HTTP'] = dict.fromkeys(attributes)
            for i, attr in enumerate(attributes):
                self.detail_info['HTTP'][attr] = match.group(i + 1)
        if 'UDP' in layers:
            match = re.search(udp_pattern, self.raw_data)
            attributes = ['sport(源端口)', 'dport(目的端口)', 'len(长度)', 'chksum(校验和)']
            self.detail_info['UDP'] = dict.fromkeys(attributes)
            for i, attr in enumerate(attributes):
                self.detail_info['UDP'][attr] = match.group(i + 1)
        if 'ARP' in layers:
            match = re.search(arp_pattern, self.raw_data)
            # print(self.raw_data)

            attributes = ['hwtype(硬件类型)', 'ptype(协议类型)', 'hwlen(硬件地址长度)', 'plen(协议长度)', 'op(操作类型)',
                          'hwsrc(源MAC地址)', 'psrc(源IP地址)', 'hwdst(目的MAC地址)', 'pdst(目的IP地址)']
            self.detail_info['ARP'] = dict.fromkeys(attributes)
            # print(self.detail_info['ARP'])
            for i, attr in enumerate(attributes):
                self.detail_info['ARP'][attr] = match.group(i + 1)
        if 'ICMP' in layers:
            match = re.search(icmp_pattern, self.raw_data)
            attributes = ['type(类型)', 'code(代码)', 'chksum(校验和)', 'id(标识)', 'seq(序号)', 'unused(未使用)']
            self.detail_info['ICMP'] = dict.fromkeys(attributes)
            for i, attr in enumerate(attributes):
                self.detail_info['ICMP'][attr] = match.group(i + 1)
        if 'Raw' in layers:
            match = re.search(raw_pattern, self.raw_data)
            self.detail_info['Raw'] = {}
            if match:
                self.detail_info['Raw']['load'] = match.group(1)
            else:
                self.detail_info['Raw']['load'] = ''
        if 'Padding' in layers:
            match = re.search(padding_pattern, self.raw_data)
            self.detail_info['Padding'] = {}
            if match:
                self.detail_info['Padding']['load'] = match.group(1)
            else:
                self.detail_info['Padding']['load'] = ''
        # print(self.detail_info)

    def to_dict(self):
        return {'number': self.number, 'time': self.time, 'src': self.src, 'dst': self.dst,
                'protocol': self.protocol, 'length': self.length, 'info': self.info, 'detail_info': self.detail_info,
                'hex_info': self.hex_info, 'payload': self.payload}
