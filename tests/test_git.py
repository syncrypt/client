import logging
from glob import glob
import os
import os.path
import shutil
import unittest

import pytest
import asyncio
import asynctest
from syncrypt.models import Bundle, Vault
from syncrypt.app import SyncryptApp
from syncrypt.backends import BinaryStorageBackend
from tests.base import VaultTestCase
from subprocess import call

__all__ = ('BinaryServerTests',)
@pytest.mark.requires_server
@pytest.mark.requires_git
class GitTests(VaultTestCase):
    '''
    High level git integration tests.
    '''
    folder = 'tests/testbinaryempty/'

    def test_git_push(self):
        app = self.app
        yield from app.open_or_init(self.vault)
        backend = self.vault.backend

        git_folder = os.path.join(self.working_dir, 'gitrepo')
        git_folder_dst = os.path.join(self.working_dir, 'gitrepo2')

        if os.path.exists(git_folder):
            shutil.rmtree(git_folder)
        if os.path.exists(git_folder_dst):
            shutil.rmtree(git_folder_dst)

        call(["git", "init", git_folder])
        os.chdir(git_folder)

        self.assertTrue(os.path.exists(os.path.join(git_folder, '.git')))

        git_remote = 'syncrypt://' + self.vault.folder

        call(["git", "remote", "add", "origin", git_remote])

        with open(os.path.join(git_folder, 'content.txt'), 'w') as f:
            f.write('Hello from test_git_push!\n')

        call(["touch", "hello.txt"])

        call(["git", "add", "."])
        call(["git", "commit", "-a", "-m", "Initial commit"])

        os.environ['PATH'] = '{0}:{1}'.format(
                os.path.abspath(os.path.join(os.path.dirname(__file__), '../scripts/')),
                os.environ.get('PATH', ''))
        os.environ['PYTHONPATH'] = \
                os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))

        call(["git", "push", "-u", "origin", "master"])

        call(["git", "clone", git_remote, git_folder_dst])
        os.chdir(git_folder_dst)

