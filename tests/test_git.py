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


    def setUp(self):
        super(GitTests, self).setUp()

        os.environ['PATH'] = '{0}:{1}'.format(
                os.path.abspath(os.path.join(os.path.dirname(__file__), '../scripts/')),
                os.environ.get('PATH', ''))
        os.environ['PYTHONPATH'] = \
                os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))

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

        call(["git", "push", "-u", "origin", "master"])

        # TODO: also test cloning to git_folder_dst without creating it inb4
        #call(["git", "clone", git_remote, git_folder_dst])
        os.makedirs(git_folder_dst)
        os.chdir(git_folder_dst)
        call(["git", "clone", git_remote, '.'])


        self.assertTrue(os.path.exists(os.path.join(git_folder_dst, 'hello.txt')))
        self.assertTrue(os.path.exists(os.path.join(git_folder_dst, 'content.txt')))

        with open(os.path.join(git_folder_dst, 'content.txt'), 'a') as f:
            f.write('Hello from git_folder_dst!\n')

        call(["git", "commit", "-a", "-m", "Second commit"])
        call(["git", "push", "-u", "origin", "master"])

        os.chdir(git_folder)
        call(["git", "pull", "origin", "master"])

        with open(os.path.join(git_folder, 'content.txt'), 'r') as f:
            self.assertEqual(f.read(), 'Hello from test_git_push!\nHello from git_folder_dst!\n')


    def test_git_ls_remote(self):
        app = self.app
        yield from app.open_or_init(self.vault)
        backend = self.vault.backend

        git_folder = os.path.join(self.working_dir, 'gitrepo')
        git_folder_dst = os.path.join(self.working_dir, 'gitrepo2')

        if os.path.exists(git_folder):
            shutil.rmtree(git_folder)

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
        call(["git", "push", "-u", "origin", "master"])

        call(["git", "checkout", "-b", "branch1"])

        with open(os.path.join(git_folder_dst, 'content.txt'), 'a') as f:
            f.write('Hello from git_folder_dst!\n')

        call(["git", "commit", "-a", "-m", "Second commit"])
        call(["git", "push", "-u", "origin", "branch1"])

        call(["git", "checkout", "master"])
        call(["git", "tag", "master_tag"])
        call(["git", "push", "--tags"])

        call(["git", "ls-remote", "-q", "origin"]) # TODO assert that tags refs are different

