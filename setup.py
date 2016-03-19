# Always prefer setuptools over distutils
import os
import sys
from codecs import open
from distutils.core import Command, setup
from os import path

from setuptools import find_packages, setup

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

class DistCommand(Command):
    description = "packages syncrypt and syncrypt gui for the current platform"
    user_options = []

    def initialize_options(self): pass

    def finalize_options(self):
        self.cwd = os.getcwd()

    def run(self):
        import platform

        assert os.getcwd() == self.cwd, 'Must be in package root: %s' % self.cwd
        os.system('rm -rf ./dist/syncrypt*.zip')
        os.system('rm -rf ./dist/syncrypt')
        os.system('rm -rf ./dist/syncrypt_gui')
        os.system('PYTHONPATH=lib/python3.5/site-packages/ pyinstaller syncrypt.spec')
        os.system('cp ./dist/syncrypt_gui/* ./dist/syncrypt')
        zipname = '{name}-{version}.{platform}-{machine}.zip'.format(
                name=__name__,
                version=__version__,
                platform=platform.system().lower(),
                machine=platform.machine()
        )
        os.system('cd dist; zip {0} -r ./syncrypt'.format(zipname))
        print("Generated {0}".format(os.path.join('dist', zipname)))

cmdclass['dist'] = DistCommand

setup(
    name=__name__,

    # Versions should comply with PEP440.  For a discussion on single-sourcing
    # the version across setup.py and the project code, see
    # https://packaging.python.org/en/latest/single_source_version.html
    version='0.0.3',

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
