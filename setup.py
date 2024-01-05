# Always prefer setuptools over distutils
import os
import sys
from codecs import open
from distutils.core import Command, setup
from os import path

from setuptools import find_packages, setup

from syncrypt.utils.version import get_git_version

__name__ = 'syncrypt'
__version__ = get_git_version()

here = path.abspath(path.dirname(__file__))

cmdclass = {}

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
        zipname = '{name}-{version}.{platform}-{machine}.zip'.format(
                name=__name__,
                version=__version__,
                platform=platform.system().lower(),
                machine=platform.machine()
        )
        if platform.system().lower() == 'windows':
            os.system('pyinstaller --onefile scripts/syncrypt')
            os.system('pyinstaller --onefile scripts/syncrypt_daemon')
        else:
            os.system('rm -rf ./dist/syncrypt')
            exit_code = os.system(('{0} syncrypt.spec').format(os.environ.get("PYINSTALLER", "pyinstaller")))
            if exit_code != 0:
                raise OSError('pyinstaller ({0}) did not run correctly'.format(os.environ.get("PYINSTALLER", "pyinstaller")))
            os.system('mkdir ./dist/syncrypt')
            os.system('cp README.md LICENSE ./dist/syncrypt')
            os.system('cp dist/syncrypt-bin ./dist/syncrypt/syncrypt')
            os.system('cp dist/syncrypt_daemon ./dist/syncrypt/syncrypt_daemon')
            os.system('chmod u+x ./dist/syncrypt/syncrypt ./dist/syncrypt/syncrypt_daemon')
            os.system('cp dist-files/* ./dist/syncrypt/')
            os.system('cd dist; rm -f {0}'.format(zipname))
            os.system('cd dist/syncrypt/; zip ../{0} -r .'.format(zipname))
            os.system('cd dist; shasum -a 256 {0} > {0}.sha256'.format(zipname))
        print("Generated {0}".format(os.path.join('dist', zipname)))


class DeployCommand(Command):
    description = "deploys package to syncrypt artifact tray"
    user_options = []

    def initialize_options(self): pass

    def finalize_options(self):
        self.cwd = os.getcwd()

    def run(self):
        import platform

        assert os.getcwd() == self.cwd, 'Must be in package root: %s' % self.cwd
        dist_name = '{name}-{version}.{platform}-{machine}.zip'.format(
                name=__name__,
                version=__version__,
                platform=platform.system().lower(),
                machine=platform.machine()
        )
        store_name = '{name}-{platform}-{machine}.zip'.format(
                name=__name__,
                platform=platform.system().lower(),
                machine=platform.machine()
        )
        store_endpoint = os.environ.get('ARTIFACT_TRAY_STORE_URL')
        os.system(('curl -X POST'
            ' --header "Content-Type: application/octet-stream"'
            ' --data-binary "@dist/{dist_name}"'
            ' "{store_endpoint}{store_name}/{channel}/{version}/"'
            ).format(dist_name=dist_name, store_endpoint=store_endpoint,
                     store_name=store_name, version=__version__.replace('+', '%2b'),
                     channel=os.environ.get('BRANCH', 'master')))

cmdclass['dist'] = DistCommand
cmdclass['deploy'] = DeployCommand

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
    author='Syncrypt UG',
    author_email='support@syncrypt.space',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',

        'Intended Audience :: End Users/Desktop',

        'Development Status :: 4 - Beta',

        'Topic :: Communications :: File Sharing',
        'Topic :: System :: Archiving',
        'Topic :: Security :: Cryptography',

        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8'
    ],

    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages().
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),

    scripts=[
        'scripts/syncrypt',
        'scripts/syncrypt_daemon',
    ],

    python_requires='>=3.6',

    # Alternatively, if you want to distribute just a my_module.py, uncomment
    # this:
    #   py_modules=["my_module"],

    # List run-time dependencies here.  These will be installed by pip when
    # your project is installed. For an analysis of "install_requires" vs pip's
    # requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=[
        'aiohttp>=3.5',
        'certifi',
        'colorlog',
        'erlastic',
        'trio==0.13.0',
        'outcome==1.0.0',
        'trio-asyncio==0.10.0',
        'trio-typing==0.3.0',
        'async_generator', # for python 3.6
        'typing_extensions>=3.7.2',
        'iso8601',
        'pycryptodomex==3.19.1',
        'python-snappy',
        'smokesignal',
        'sqlalchemy>=1.2.13',
        'tenacity>=5.0.4',
        'tzlocal',
        'u-msgpack-python==2.5.1',
        'watchdog>=0.9.0'
    ],

    # List additional groups of dependencies here (e.g. development
    # dependencies). You can install these using the following syntax,
    # for example:
    # $ pip install -e .[dev,test]
    extras_require={
        'dist': [
            'pyinstaller==3.5',
            'six',
            'packaging'
        ],
        'win': [
            'win_unicode_console'
        ],
        'test': [
            'pytest-runner',
            'pytest==3.6.0',
            'pytest-trio==0.5.2',
            'trio-websocket',
            'attrs>=19.2.0',
            'mypy==0.750',  # used for static type checking
            'pylint'  # used for static code analysis
        ],
        'uvloop': [
            'uvloop'
        ]
    },

    cmdclass=cmdclass
)
