# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

from syncrypt import __version__

__name__ = 'syncrypt_desktop'

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

from distutils.core import setup, Command
import os, sys

class DistCommand(Command):
    description = "packages syncrypt and syncrypt gui for the current platform"

    def run(self):
        assert os.getcwd() == self.cwd, 'Must be in package root: %s' % self.cwd
        os.system('rm -rf ./dist/syncrypt*.zip')
        os.system('rm -rf ./dist/syncrypt')
        os.system('rm -rf ./dist/syncrypt_gui')
        os.system('PYTHONPATH=lib/python3.5/site-packages/ pyinstaller syncrypt.spec')
        os.system('cp ./dist/syncrypt_gui/* ./dist/syncrypt')
        os.system('cd dist; zip syncrypt-0.0.1-linux-amd64.zip -r ./syncrypt')

cmdclass['dist'] = DistCommand

setup(
    name=__name__,

    # Versions should comply with PEP440.  For a discussion on single-sourcing
    # the version across setup.py and the project code, see
    # https://packaging.python.org/en/latest/single_source_version.html
    version=__version__,

    description='A Syncrypt client',
    long_description=long_description,

    # The project's main homepage.
    url='https://github.com/bakkdoor/syncrypt_desktop',

    # Author details
    author='Hannes Gräuler',
    author_email='hannes@smasi.de',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',

        'Programming Language :: Python :: 3',
    ],

    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages().
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),

    scripts=[
        'scripts/syncrypt',
        'scripts/syncrypt_daemon',
        'scripts/syncrypt_gui',
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
        'colorlog',
        'hachiko',
        # PyQt is not available on PyPI
        #'pyqt5',
        'python-snappy',
        'erlastic',
        'bert==2.1.0'
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

    # Download bert from github (https://github.com/samuel/python-bert/issues/7)
    dependency_links=[
        'http://github.com/samuel/python-bert/tarball/master#egg=bert-2.1.0'
    ],

    cmdclass=cmdclass
)
