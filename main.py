from PyQt5 import uic
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QIcon
import sys
import ui_func


class Loader:
    def __init__(self):
        self.ui = uic.loadUi("main_window.ui")
        ui_func.modify(self.ui)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    loader = Loader()
    loader.ui.showMaximized()
    sys.exit(app.exec_())
