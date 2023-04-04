from scapy.all import *
from PyQt5.QtWidgets import *
from packet import PacketInfo

import sniffer

import json
import time
import ast

ui: QWidget
s: sniffer.Sniffer



def modify(_ui: QWidget):
    global ui
    global s
    ui = _ui
    s = sniffer.Sniffer(ui)

    # signals = s.signals
    set_table()

    get_nif(ui.nif_combobox)  # 获取网卡
    initialize()  # 初始化

    set_if_box()
    set_signal()  # 设置信号



# 获取网卡
def get_nif(nif_box: QComboBox):
    nif_list = [nif.name for nif in get_working_ifaces() if nif.mac]
    nif_box.addItems(nif_list)
    return nif_list


# 初始化动作
def initialize():
    ui.start_button.setEnabled(False)
    ui.start_button.clicked.connect(start)
    ui.stop_button.setEnabled(False)
    ui.stop_button.clicked.connect(stop)
    ui.clear_button.setEnabled(False)
    ui.clear_button.clicked.connect(clear)


# 设置信息展示表格
def set_table():
    ui.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    ui.table.setColumnWidth(0, 50)
    ui.table.setColumnWidth(2, 150)
    ui.table.setColumnWidth(3, 150)
    ui.table.setColumnWidth(4, 100)
    ui.table.setColumnWidth(5, 50)
    ui.table.horizontalHeader().setStretchLastSection(True)
    ui.table.setStyleSheet('QTableWidget::item:selected{background-color: #ACACAC}')
    ui.table.itemClicked.connect(show_protocal_data)
    ui.table.itemClicked.connect(show_hex_data)
    # ui.table.itemClicked.connect(change_color)





def set_if_box():
    ui.nif_combobox.currentIndexChanged.connect(check_nif)



def set_signal():
    s.signals.update_table.connect(add_row)

# 退出界面
def exit():
    reply = QMessageBox.question(ui, '温馨提示',
                                 "确定退出吗?",
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
    if reply == QMessageBox.Yes:
        ui.close()




# 添加行
def add_row(packet_info: Packet):
    table: QTableWidget = ui.table
    rows = table.rowCount()
    table.insertRow(rows)
    headers = ['number', 'protocol', 'time', 'src', 'dst', 'length', 'info']
    for i, header in enumerate(headers):
        item = QTableWidgetItem(str(packet_info.__dict__[header]))
        item.setBackground(packet_info.color)
        table.setItem(rows, i, item)
    table.scrollToBottom()

def check_nif(index):
    if index != 0 and not s.is_running:
        ui.start_button.setEnabled(True)
        # ui.action_start.setEnabled(True)
        # ui.action_restart.setEnabled(True)
    else:
        ui.start_button.setEnabled(False)
        # ui.action_start.setEnabled(False)
        # ui.action_restart.setEnabled(False)



# 清除信息
def clear():
    ui.table.clearContents()
    ui.table.setRowCount(0)
    ui.protocal_data_tree.clear()
    ui.hex_data_text.clear()
    s.clear()


# 清除数据包显示表




# 开始嗅探
def start():
    s.start()
    ui.start_button.setEnabled(False)
    ui.stop_button.setEnabled(True)
    ui.clear_button.setEnabled(True)
    # ui.action_stop.setEnabled(True)
    # ui.action_start.setEnabled(False)
    # ui.action_restart.setEnabled(False)
    # ui.action_clean_all.setEnabled(False)
    # ui.action_save_as.setEnabled(False)
    # ui.action_exit.setEnabled(False)
    # ui.action_open_file.setEnabled(False)
    # ui.action_filter.setEnabled(True)





# 停止嗅探
def stop():
    s.stop()
    ui.start_button.setEnabled(True)
    ui.stop_button.setEnabled(False)
    ui.clear_button.setEnabled(True)
    # ui.action_stop.setEnabled(False)
    # ui.action_restart.setEnabled(True)
    # ui.action_start.setEnabled(True)
    # ui.action_clean_all.setEnabled(True)
    # ui.action_save_as.setEnabled(True)
    # ui.action_open_file.setEnabled(True)
    # ui.action_filter.setEnabled(True)
    # ui.action_exit.setEnabled(True)


# # 清除内容
# def clean_all():
#     reply = QMessageBox.question(ui, '温馨提示',
#                                  "该操作将会清除所有内容！",
#                                  QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
#     if reply == QMessageBox.Yes:
#         clear()
#         ui.action_save_as.setEnabled(False)


# 展示详细信息
def show_protocal_data(item: QTableWidgetItem):
    tree: QTreeWidget = ui.protocal_data_tree
    # tab: QTabWidget = ui.tab
    tree.clear()
    row = item.row()

    number = int(ui.table.item(row, 0).text()) - 1
    info = s.packets[number].detail_info
    # print(info)
    for layer, layer_info in info.items():
        root = QTreeWidgetItem(tree)
        root.setText(0, layer)
        # print(layer_info)
        if layer_info:
            for key, value in layer_info.items():
                print(key, value)
                if value is None:
                    value = ''
                node = QTreeWidgetItem(root)
                node.setText(0, key)
                node.setText(1, value)
                root.addChild(node)
    tree.expandAll()
    # tab.setCurrentIndex(0)





# 展示hex信息
def show_hex_data(item: QTableWidgetItem):
    row = item.row()
    number = int(ui.table.item(row, 0).text()) - 1
    text: QTextBrowser = ui.hex_data_text
    text.clear()
    hex_info = s.packets[number].hex_info
    text.setText(hex_info)

