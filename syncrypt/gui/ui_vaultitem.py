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
        VaultItem.resize(452, 81)
        VaultItem.setMinimumSize(QtCore.QSize(0, 40))
        self.gridLayout_2 = QtWidgets.QGridLayout(VaultItem)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtWidgets.QLabel(VaultItem)
        self.label.setMaximumSize(QtCore.QSize(64, 64))
        self.label.setBaseSize(QtCore.QSize(64, 64))
        self.label.setText("")
        self.label.setPixmap(QtGui.QPixmap(":/syncrypt/vault.png"))
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.name = QtWidgets.QLabel(VaultItem)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Maximum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.name.sizePolicy().hasHeightForWidth())
        self.name.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.name.setFont(font)
        self.name.setObjectName("name")
        self.verticalLayout.addWidget(self.name)
        self.folder = QtWidgets.QLabel(VaultItem)
        self.folder.setObjectName("folder")
        self.verticalLayout.addWidget(self.folder)
        self.horizontalLayout.addLayout(self.verticalLayout)
        self.user_count = QtWidgets.QLabel(VaultItem)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(20)
        sizePolicy.setHeightForWidth(self.user_count.sizePolicy().hasHeightForWidth())
        self.user_count.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.user_count.setFont(font)
        self.user_count.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.user_count.setObjectName("user_count")
        self.horizontalLayout.addWidget(self.user_count)
        self.status = QtWidgets.QLabel(VaultItem)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(50)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.status.sizePolicy().hasHeightForWidth())
        self.status.setSizePolicy(sizePolicy)
        self.status.setObjectName("status")
        self.horizontalLayout.addWidget(self.status)
        self.gridLayout_2.addLayout(self.horizontalLayout, 1, 1, 1, 1)

        self.retranslateUi(VaultItem)
        QtCore.QMetaObject.connectSlotsByName(VaultItem)

    def retranslateUi(self, VaultItem):
        _translate = QtCore.QCoreApplication.translate
        VaultItem.setWindowTitle(_translate("VaultItem", "Form"))
        self.name.setText(_translate("VaultItem", "Vault Name"))
        self.folder.setText(_translate("VaultItem", "/folder/"))
        self.user_count.setText(_translate("VaultItem", "2"))
        self.status.setText(_translate("VaultItem", "/folder/"))

from . import syncrypt_rc
