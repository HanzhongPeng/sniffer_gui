from PyQt5.QtCore import pyqtSignal, QObject
from packet_info import PacketInfo


class Signals(QObject):
    update_table = pyqtSignal(PacketInfo)
