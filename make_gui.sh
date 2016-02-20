pyrcc5 syncrypt/gui/assets/resources.qrc -o syncrypt/gui/resources_rc.py
pyuic5 --from-imports syncrypt/gui/vaultitem.ui -o syncrypt/gui/ui_vaultitem.py
pyuic5 --from-imports syncrypt/gui/main.ui -o syncrypt/gui/ui_main.py

