# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'main.ui'
#
# Created by: PyQt5 UI code generator 5.5.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_SyncryptWindow(object):
    def setupUi(self, SyncryptWindow):
        SyncryptWindow.setObjectName("SyncryptWindow")
        SyncryptWindow.setWindowModality(QtCore.Qt.NonModal)
        SyncryptWindow.resize(507, 511)
        SyncryptWindow.setDocumentMode(False)
        SyncryptWindow.setTabShape(QtWidgets.QTabWidget.Rounded)
        SyncryptWindow.setUnifiedTitleAndToolBarOnMac(False)
        self.centralwidget = QtWidgets.QWidget(SyncryptWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.vaultList = QtWidgets.QListWidget(self.centralwidget)
        self.vaultList.setGeometry(QtCore.QRect(0, 0, 471, 401))
        self.vaultList.setObjectName("vaultList")
        SyncryptWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(SyncryptWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 507, 22))
        self.menubar.setObjectName("menubar")
        self.menuHilfe = QtWidgets.QMenu(self.menubar)
        self.menuHilfe.setObjectName("menuHilfe")
        self.menuHilfe_2 = QtWidgets.QMenu(self.menubar)
        self.menuHilfe_2.setObjectName("menuHilfe_2")
        SyncryptWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(SyncryptWindow)
        self.statusbar.setObjectName("statusbar")
        SyncryptWindow.setStatusBar(self.statusbar)
        self.actionFeedback_senden = QtWidgets.QAction(SyncryptWindow)
        self.actionFeedback_senden.setObjectName("actionFeedback_senden")
        self.action_ber = QtWidgets.QAction(SyncryptWindow)
        self.action_ber.setObjectName("action_ber")
        self.actionAdd_a_Vault = QtWidgets.QAction(SyncryptWindow)
        self.actionAdd_a_Vault.setObjectName("actionAdd_a_Vault")
        self.action_Quit = QtWidgets.QAction(SyncryptWindow)
        self.action_Quit.setObjectName("action_Quit")
        self.menuHilfe.addAction(self.actionAdd_a_Vault)
        self.menuHilfe.addAction(self.action_Quit)
        self.menuHilfe_2.addAction(self.actionFeedback_senden)
        self.menuHilfe_2.addAction(self.action_ber)
        self.menubar.addAction(self.menuHilfe.menuAction())
        self.menubar.addAction(self.menuHilfe_2.menuAction())

        self.retranslateUi(SyncryptWindow)
        QtCore.QMetaObject.connectSlotsByName(SyncryptWindow)

    def retranslateUi(self, SyncryptWindow):
        _translate = QtCore.QCoreApplication.translate
        SyncryptWindow.setWindowTitle(_translate("SyncryptWindow", "Syncrypt"))
        self.menuHilfe.setTitle(_translate("SyncryptWindow", "Syncrypt"))
        self.menuHilfe_2.setTitle(_translate("SyncryptWindow", "Help"))
        self.actionFeedback_senden.setText(_translate("SyncryptWindow", "Feedback senden"))
        self.action_ber.setText(_translate("SyncryptWindow", "Über"))
        self.actionAdd_a_Vault.setText(_translate("SyncryptWindow", "Add a Vault..."))
        self.action_Quit.setText(_translate("SyncryptWindow", "&Quit"))

