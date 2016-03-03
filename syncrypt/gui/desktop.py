# -*- coding: utf-8 -*-
import json
import logging

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import QDir, QFile, QFileInfo, QIODevice, QSettings, QUrl
from PyQt5.QtNetwork import QNetworkAccessManager, QNetworkRequest

from .ui_main import Ui_SyncryptWindow
from .ui_vaultitem import Ui_VaultItem

SC_COMPANY_NAME = 'Syncrypt UG'
SC_NAME = 'Syncrypt'

logger = logging.getLogger(__name__)

class VaultItemWidget(Ui_VaultItem, QtWidgets.QWidget):
    def __init__(self, parent=None):
        super(VaultItemWidget, self).__init__(parent)
        self.setupUi(self)

    def isFolder(self, s):
        return self._folder == s

    def setFolder(self, s):
        self._folder = s
        self.folder.setText(s)

    def setName(self, s):
        self.name.setText(s)

    def setStatus(self, s):
        self.status.setText(s)

    def setUserCount(self, s):
        self.user_count.setText(str(s))

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

    def get(self, url, cb=None, method='get', payload=None):
        logger.debug("Querying %s", self.api_url + url)
        url = QUrl(self.api_url + url)
        if payload:
            assert type(payload) == bytes
            reply = getattr(self.qnam, method)(QNetworkRequest(url), payload)
        else:
            reply = getattr(self.qnam, method)(QNetworkRequest(url))
        self.replies.append(reply)
        def finished():
            if reply.error() != 0:
                logger.warn("Network request threw error code %s", reply.error())
            if cb: cb(reply)
            self.replies.remove(reply)
        reply.finished.connect(finished)

    def put(self, url, payload, cb=None):
        return self.get(url, method='put', payload=payload, cb=cb)

    def setConnected(self, connected=True):
        if not self.connected is connected:
            if connected:
                logger.info('Connected to syncrypt daemon')
            else:
                logger.warn('Disconnected from syncrypt deamon')
        self.connected = connected
        self.connectedChanged.emit()

    def updateVaults_finished(self, reply):
        if reply.error() == 0:
            content = reply.readAll()
            logger.debug("Received: %s", bytes(content)[:100])
            self.vaults = json.loads(bytes(content).decode())
            self.vaultsChanged.emit()
            self.setConnected(True)
        else:
            self.setConnected(False)

    def updateStats_finished(self, reply):
        if reply.error() == 0:
            content = reply.readAll()
            logger.debug("Received: %s", bytes(content)[:100])
            self.stats = json.loads(bytes(content).decode())
            self.statsChanged.emit()
            self.setConnected(True)
        else:
            self.setConnected(False)

    def updateVaults(self):
        self.get('vault/', self.updateVaults_finished)

    def addVault_finished(self, reply):
        self.updateVaults()

    def addVault(self, fname):
        self.put('vault/', bytes(fname.encode('utf-8')), self.addVault_finished)

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
        self.actionDebugRefresh.triggered.connect(self.refreshAll)

        self.actionQuit.triggered.connect(QtCore.QCoreApplication.instance().quit)
        self.actionAddVault.triggered.connect(self.addVault)

        settings = QSettings(SC_COMPANY_NAME, SC_NAME)
        for vault_dir in settings.value('list_vaults', type=str):
            self.store.addVault(vault_dir)


    def refreshAll(self):
        self.store.updateVaults()
        self.store.updateStats()

    def addVault(self):
        fname = QtWidgets.QFileDialog.getExistingDirectory(self, 'Select directory')
        logger.info('Trying to add new folder %s', fname)
        self.store.addVault(fname)

    def refreshStatusBar(self):
        if 'stats' in self.store.stats:
            stats = self.store.stats['stats']
            if self.store.connected:
                self.statusbar.showMessage("Connected " + str(stats))
            else:
                self.statusbar.showMessage("Connecting to daemon...")
        if 'states' in self.store.stats:
            states = self.store.stats['states']
            for (folder, state) in states.items():
                for i in range(self.vaultList.count()):
                    item = self.vaultList.item(i)
                    widget = self.vaultList.itemWidget(item)
                    if widget.isFolder(folder):
                        widget.setStatus(state)

    def refreshVaults(self):
        self.vaultList.clear()
        for vault in self.store.vaults:
            name = ""
            this_item = QtWidgets.QListWidgetItem()
            widget = VaultItemWidget()
            widget.setFolder(vault.get('folder'))
            widget.setName(vault.get('id'))
            widget.setUserCount(vault.get('user_count'))
            widget.setStatus(vault.get('state'))
            this_item.setSizeHint(QtCore.QSize(0, 64+24))
            self.vaultList.addItem(this_item)
            self.vaultList.setItemWidget(this_item, widget)
        vault_dirs = [vault.get('folder') for vault in self.store.vaults]
        settings = QSettings(SC_COMPANY_NAME, SC_NAME)
        settings.setValue('list_vaults', vault_dirs)
        del settings # trigger store

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    SyncryptWindow = SyncryptDesktop()
    SyncryptWindow.show()
    sys.exit(app.exec_())

