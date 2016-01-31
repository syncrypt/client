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
    statsChanged = QtCore.pyqtSignal()

    def __init__(self, api_url):
        super(SyncryptStore, self).__init__()
        self.api_url = api_url
        self.url = QUrl()
        self.vaults = []
        self.replies = []
        self.stats = {}
        self.connected = False
        self.qnam = QNetworkAccessManager()

    def get(self, url, cb=None):
        print("Querying " + (self.api_url + url))
        url = QUrl(self.api_url + url)
        reply = self.qnam.get(QNetworkRequest(url))
        self.replies.append(reply)
        def finished():
            print ("Network reply _finished", reply.error())
            if cb: cb(reply)
            self.replies.remove(reply)
        reply.finished.connect(finished)

    def setConnected(self, connected=True):
        self.connected = connected
        self.connectedChanged.emit()

    def updateVaults_finished(self, reply):
        if reply.error() == 0:
            content = reply.readAll()
            print (bytes(content))
            self.vaults = json.loads(bytes(content).decode())
            self.vaultsChanged.emit()
            self.setConnected(True)
        else:
            self.setConnected(False)

    def updateStats_finished(self, reply):
        if reply.error() == 0:
            content = reply.readAll()
            print (bytes(content))
            self.stats = json.loads(bytes(content).decode())
            self.statsChanged.emit()
            self.setConnected(True)
        else:
            self.setConnected(False)

    def updateVaults(self):
        self.get('vault/', self.updateVaults_finished)

    def updateStats(self):
        self.get('stats', self.updateStats_finished)

    def pull(self):
        self.get('pull')

    def push(self):
        self.get('push')

class SyncryptDesktop(QtWidgets.QMainWindow, Ui_SyncryptWindow):
    def __init__(self, parent=None):
        super(SyncryptDesktop, self).__init__(parent)
        self.setupUi(self)
        self.statusbar.showMessage("Connecting to daemon...")
        self.store = SyncryptStore('http://127.0.0.1:28080/v1/')
        self.store.vaultsChanged.connect(self.refreshVaults)
        self.store.connectedChanged.connect(self.refreshStatusBar)
        self.store.statsChanged.connect(self.refreshStatusBar)
        self.store.updateVaults()
        self.store.updateStats()

        self.statsTimer = QtCore.QTimer(self)
        self.statsTimer.setInterval(2500)
        self.statsTimer.timeout.connect(self.store.updateStats)
        self.statsTimer.start()

        self.actionDebugPushAll.triggered.connect(self.store.push)
        self.actionDebugPullAll.triggered.connect(self.store.pull)

        self.action_Quit.triggered.connect(QtCore.QCoreApplication.instance().quit)

    def refreshStatusBar(self):
        if self.store.connected:
            self.statusbar.showMessage("Connected " + str(self.store.stats))
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
