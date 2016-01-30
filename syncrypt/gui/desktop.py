# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import QDir, QFile, QFileInfo, QIODevice, QUrl
from PyQt5.QtNetwork import QNetworkAccessManager, QNetworkRequest

from .ui_main import Ui_SyncryptWindow
from .ui_vaultitem import Ui_VaultItem

import json

class VaultItemWidget(Ui_VaultItem, QtWidgets.QWidget):
    def __init__(self, parent=None):
        super(VaultItemWidget, self).__init__(parent)
        self.setupUi(self)

    def setFolder(self, s):
        self.folder.setText(s)

    def setName(self, s):
        self.name.setText(s)

class SyncryptStore(QtCore.QObject):
    vaultsChanged = QtCore.pyqtSignal()
    connectedChanged = QtCore.pyqtSignal()

    def __init__(self, api_url):
        super(SyncryptStore, self).__init__()
        self.api_url = api_url
        self.url = QUrl()
        self.vaults = []
        self.connected = False
        self.qnam = QNetworkAccessManager()

    def get(self, url):
        url = QUrl(self.api_url + url)
        print("Querying " + url.url())
        self.reply = self.qnam.get(QNetworkRequest(url))
        self.reply.finished.connect(self.get_finished)
        self.reply.readyRead.connect(self.get_ready)
        #self.reply.downloadProgress.connect(self.updateDataReadProgress)

    def get_finished(self, *args):
        print ("get_finished", self.reply.error())
        if self.reply.error() == 0:
            content = self.reply.readAll()
            print (bytes(content))
            self.vaults = json.loads(bytes(content).decode())
            self.vaultsChanged.emit()
            self.connected = True
            self.connectedChanged.emit()

    def get_ready(self, *args):
        pass

    def updateVaults(self):
        self.get('vault/')

class SyncryptDesktop(QtWidgets.QMainWindow, Ui_SyncryptWindow):
    def __init__(self, parent=None):
        super(SyncryptDesktop, self).__init__(parent)
        self.setupUi(self)
        self.statusbar.showMessage("Connecting to daemon...")
        self.store = SyncryptStore('http://127.0.0.1:28080/v1/')
        self.store.updateVaults()
        self.store.vaultsChanged.connect(self.refreshVaults)
        self.store.connectedChanged.connect(self.refreshStatusBar)

    def refreshStatusBar(self):
        if self.store.connected:
            self.statusbar.showMessage("Connected")
        else:
            self.statusbar.showMessage("Connecting to daemon...")

    def refreshVaults(self):
        for vault in self.store.vaults:
            name = ""
            this_item = QtWidgets.QListWidgetItem()
            widget = VaultItemWidget()
            widget.setFolder(vault.get('folder'))
            widget.setName(vault.get('id'))
            this_item.setSizeHint(QtCore.QSize(0, 64))
            self.vaultList.addItem(this_item)
            self.vaultList.setItemWidget(this_item, widget)

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    SyncryptWindow = SyncryptDesktop()
    SyncryptWindow.show()
    sys.exit(app.exec_())

