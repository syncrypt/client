# -*- mode: python -*-

import os.path

block_cipher = None

a = Analysis(['scripts/syncrypt'],
             pathex=[os.path.abspath('.')],
             binaries=None,
             datas=None,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)

b = Analysis(['scripts/syncrypt_gui'],
             pathex=[os.path.abspath('.')],
             binaries=None,
             datas=None,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)

MERGE((a, 'syncrypt', 'syncrypt'), (b, 'syncrypt_gui', 'syncrypt_gui'))

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='syncrypt',
          debug=False,
          strip=True,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               name='syncrypt')

pyz = PYZ(b.pure, b.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          b.scripts,
          exclude_binaries=True,
          name='syncrypt_gui',
          debug=False,
          strip=True,
          upx=True,
          console=True )
coll = COLLECT(exe,
               b.binaries,
               b.zipfiles,
               b.datas,
               strip=False,
               upx=True,
               name='syncrypt_gui')
