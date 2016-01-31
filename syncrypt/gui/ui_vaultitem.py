# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'syncrypt/gui/vaultitem.ui'
#
# Created by: PyQt5 UI code generator 5.5.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_VaultItem(object):
    def setupUi(self, VaultItem):
        VaultItem.setObjectName("VaultItem")
        VaultItem.resize(452, 64)
        VaultItem.setMinimumSize(QtCore.QSize(0, 40))
        self.name = QtWidgets.QLabel(VaultItem)
        self.name.setGeometry(QtCore.QRect(80, 10, 231, 16))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.name.setFont(font)
        self.name.setObjectName("name")
        self.folder = QtWidgets.QLabel(VaultItem)
        self.folder.setGeometry(QtCore.QRect(80, 30, 241, 16))
        self.folder.setObjectName("folder")
        self.label_3 = QtWidgets.QLabel(VaultItem)
        self.label_3.setGeometry(QtCore.QRect(320, 20, 31, 20))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")

        self.retranslateUi(VaultItem)
        QtCore.QMetaObject.connectSlotsByName(VaultItem)

    def retranslateUi(self, VaultItem):
        _translate = QtCore.QCoreApplication.translate
        VaultItem.setWindowTitle(_translate("VaultItem", "Form"))
        self.name.setText(_translate("VaultItem", "Vault Name"))
        self.folder.setText(_translate("VaultItem", "/folder/"))
        self.label_3.setText(_translate("VaultItem", "2"))

