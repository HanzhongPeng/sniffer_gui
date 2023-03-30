from scapy.all import *

class sniffer:
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

Sniffer = sniffer()
nif_list = Sniffer.get_nif()
print(nif_list)

Sniffer.set_nif('以太网')
Sniffer.set_filter('tcp')
Sniffer.start()
time.sleep(5)
Sniffer.stop()
Sniffer.print_packets()