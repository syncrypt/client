# -*- mode: python -*-

import os.path
from PyInstaller.utils.hooks import exec_statement

cert_datas = exec_statement("""
    import ssl
    print(ssl.get_default_verify_paths().cafile)""").strip().split()
cert_datas = [(f, 'lib') for f in cert_datas]

block_cipher = None

a = Analysis(['scripts/syncrypt'],
             pathex=[os.path.abspath('.')],
             binaries=None,
             datas=cert_datas,
             hiddenimports=[
                 'six',
                 'packaging',
                 'packaging.version',
                 'packaging.specifiers',
                 'packaging.requirements',
             ],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='syncrypt-bin',
          debug=False,
          strip=True,
          upx=True,
          console=True )

b = Analysis(['scripts/syncrypt_daemon'],
             pathex=[os.path.abspath('.')],
             binaries=None,
             datas=cert_datas,
             hiddenimports=[
                 'six',
                 'packaging',
                 'packaging.version',
                 'packaging.specifiers',
                 'packaging.requirements',
             ],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(b.pure, b.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          b.scripts,
          b.binaries,
          b.zipfiles,
          b.datas,
          name='syncrypt_daemon',
          debug=False,
          strip=True,
          upx=True,
          console=True )

MERGE((a, 'syncrypt', 'syncrypt'), (b, 'syncrypt_daemon', 'syncrypt_daemon'))
