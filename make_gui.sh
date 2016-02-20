pyrcc5 syncrypt/gui/assets/syncrypt.qrc -o syncrypt/gui/syncrypt_rc.py
pyuic5 --from-imports syncrypt/gui/vaultitem.ui -o syncrypt/gui/ui_vaultitem.py
pyuic5 --from-imports syncrypt/gui/main.ui -o syncrypt/gui/ui_main.py

