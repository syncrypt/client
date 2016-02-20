# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'syncrypt/gui/main.ui'
#
# Created by: PyQt5 UI code generator 5.5.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_SyncryptWindow(object):
    def setupUi(self, SyncryptWindow):
        SyncryptWindow.setObjectName("SyncryptWindow")
        SyncryptWindow.setWindowModality(QtCore.Qt.NonModal)
        SyncryptWindow.resize(360, 303)
        SyncryptWindow.setDocumentMode(False)
        SyncryptWindow.setTabShape(QtWidgets.QTabWidget.Rounded)
        SyncryptWindow.setUnifiedTitleAndToolBarOnMac(False)
        self.centralwidget = QtWidgets.QWidget(SyncryptWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setObjectName("gridLayout")
        self.vaultList = QtWidgets.QListWidget(self.centralwidget)
        self.vaultList.setObjectName("vaultList")
        self.gridLayout.addWidget(self.vaultList, 0, 0, 1, 1)
        self.gridLayout_2.addLayout(self.gridLayout, 0, 0, 1, 1)
        SyncryptWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(SyncryptWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 360, 22))
        self.menubar.setObjectName("menubar")
        self.menuHilfe = QtWidgets.QMenu(self.menubar)
        self.menuHilfe.setObjectName("menuHilfe")
        self.menuHilfe_2 = QtWidgets.QMenu(self.menubar)
        self.menuHilfe_2.setObjectName("menuHilfe_2")
        self.menuDEBUG = QtWidgets.QMenu(self.menubar)
        self.menuDEBUG.setObjectName("menuDEBUG")
        SyncryptWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(SyncryptWindow)
        self.statusbar.setObjectName("statusbar")
        SyncryptWindow.setStatusBar(self.statusbar)
        self.actionFeedback_senden = QtWidgets.QAction(SyncryptWindow)
        self.actionFeedback_senden.setObjectName("actionFeedback_senden")
        self.action_ber = QtWidgets.QAction(SyncryptWindow)
        self.action_ber.setObjectName("action_ber")
        self.actionAddVault = QtWidgets.QAction(SyncryptWindow)
        self.actionAddVault.setObjectName("actionAddVault")
        self.actionQuit = QtWidgets.QAction(SyncryptWindow)
        self.actionQuit.setObjectName("actionQuit")
        self.actionDebugPullAll = QtWidgets.QAction(SyncryptWindow)
        self.actionDebugPullAll.setObjectName("actionDebugPullAll")
        self.actionDebugPushAll = QtWidgets.QAction(SyncryptWindow)
        self.actionDebugPushAll.setObjectName("actionDebugPushAll")
        self.actionDebugRefresh = QtWidgets.QAction(SyncryptWindow)
        self.actionDebugRefresh.setObjectName("actionDebugRefresh")
        self.menuHilfe.addAction(self.actionAddVault)
        self.menuHilfe.addAction(self.actionQuit)
        self.menuHilfe_2.addAction(self.actionFeedback_senden)
        self.menuHilfe_2.addAction(self.action_ber)
        self.menuDEBUG.addAction(self.actionDebugPullAll)
        self.menuDEBUG.addAction(self.actionDebugPushAll)
        self.menuDEBUG.addAction(self.actionDebugRefresh)
        self.menubar.addAction(self.menuHilfe.menuAction())
        self.menubar.addAction(self.menuDEBUG.menuAction())
        self.menubar.addAction(self.menuHilfe_2.menuAction())

        self.retranslateUi(SyncryptWindow)
        QtCore.QMetaObject.connectSlotsByName(SyncryptWindow)

    def retranslateUi(self, SyncryptWindow):
        _translate = QtCore.QCoreApplication.translate
        SyncryptWindow.setWindowTitle(_translate("SyncryptWindow", "Syncrypt"))
        self.menuHilfe.setTitle(_translate("SyncryptWindow", "Syncrypt"))
        self.menuHilfe_2.setTitle(_translate("SyncryptWindow", "Help"))
        self.menuDEBUG.setTitle(_translate("SyncryptWindow", "DEBUG"))
        self.actionFeedback_senden.setText(_translate("SyncryptWindow", "Feedback senden"))
        self.action_ber.setText(_translate("SyncryptWindow", "Über"))
        self.actionAddVault.setText(_translate("SyncryptWindow", "Add a Vault..."))
        self.actionQuit.setText(_translate("SyncryptWindow", "&Quit"))
        self.actionDebugPullAll.setText(_translate("SyncryptWindow", "Pull all"))
        self.actionDebugPushAll.setText(_translate("SyncryptWindow", "Push all"))
        self.actionDebugRefresh.setText(_translate("SyncryptWindow", "Refresh data"))

