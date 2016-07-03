# Always prefer setuptools over distutils
import os
import sys
from codecs import open
from distutils.core import Command, setup
from os import path

from setuptools import find_packages, setup

__name__ = 'syncrypt'
__version__ = '0.1.4'

here = path.abspath(path.dirname(__file__))

cmdclass = {}

# import build_ui
try:
    from pyqt_distutils.build_ui import build_ui
    cmdclass['build_ui'] = build_ui
except ImportError:
    build_ui = None  # user won't have pyqt_distutils when deploying

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

class DistCommand(Command):
    description = "packages syncrypt client for the current platform"
    user_options = []

    def initialize_options(self): pass

    def finalize_options(self):
        self.cwd = os.getcwd()

    def run(self):
        import platform

        assert os.getcwd() == self.cwd, 'Must be in package root: %s' % self.cwd
        os.system('rm -rf ./dist/syncrypt')
        os.system('PYTHONPATH=lib/python3.5/site-packages/ pyinstaller syncrypt.spec')
        #os.system('cp ./dist/syncrypt_gui/* ./dist/syncrypt')
        zipname = '{name}-{version}.{platform}-{machine}.zip'.format(
                name=__name__,
                version=__version__,
                platform=platform.system().lower(),
                machine=platform.machine()
        )
        os.system('mkdir ./dist/syncrypt')
        os.system('cp README.md LICENSE ./dist/syncrypt')
        os.system('cp dist/syncrypt-bin ./dist/syncrypt/syncrypt')
        os.system('cp dist-files/* ./dist/syncrypt/')
        os.system('cd dist; rm -f {0}; zip {0} -r ./syncrypt'.format(zipname))
        os.system('cd dist; shasum -a 256 {0} > {0}.sha256'.format(zipname))
        print("Generated {0}".format(os.path.join('dist', zipname)))

cmdclass['dist'] = DistCommand

setup(
    name=__name__,

    # Versions should comply with PEP440.  For a discussion on single-sourcing
    # the version across setup.py and the project code, see
    # https://packaging.python.org/en/latest/single_source_version.html
    version=__version__,

    description='Syncrypt client',
    long_description=long_description,

    # The project's main homepage.
    url='https://github.com/syncrypt/client',

    # Author details
    author='Hannes Gräuler',
    author_email='hannes@syncrypt.space',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',

        'Intended Audience :: End Users/Desktop',

        'Development Status :: 3 - Alpha',

        'Topic :: Communications :: File Sharing',
        'Topic :: System :: Archiving',

        'Programming Language :: Python :: 3',
    ],

    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages().
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),

    scripts=[
        'scripts/syncrypt',
    ],

    # Alternatively, if you want to distribute just a my_module.py, uncomment
    # this:
    #   py_modules=["my_module"],

    # List run-time dependencies here.  These will be installed by pip when
    # your project is installed. For an analysis of "install_requires" vs pip's
    # requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=[
        'pycrypto',
        'aiofiles',
        'aiohttp',
        'umsgpack',
        'msgpack-python>=0.4.0',
        'colorlog',
        'hachiko',
        'python-snappy',
        'erlastic',
        'tzlocal',
        'iso8601'
    ],

    # List additional groups of dependencies here (e.g. development
    # dependencies). You can install these using the following syntax,
    # for example:
    # $ pip install -e .[dev,test]
    extras_require={
        'dev': [
            'pyqt-distutils'
        ],
        'dist': [
            'pyinstaller'
        ],
        'test': [
            'pytest-runner',
            'pytest',
            'asynctest',
            'hypothesis'
        ],
    },

    cmdclass=cmdclass
)
