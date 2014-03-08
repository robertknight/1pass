#!/usr/bin/env python

# Test for the 1pass client app using
# pexpect to drive the client interactively

from __future__ import print_function
import clipboard
import os
import pexpect
import random
import shutil
import sys
import termios
import unittest

TEST_PASSWD = 'test-pwd'

test_log = open('client_test.log', 'w')

# wrapper around pexpect which runs 1pass with
# a given command and provides expect(), sendline()
# and wait() methods to interact with the command.
#
# expect() and sendline() return self so method chaining
# can be used to create a sequence of interactions
class OnePassCmd:
    def __init__(self, test, vault, cmd):
        self.test = test
        onepass_cmd = './1pass -low-security -vault %s %s' % (vault, cmd)
        print('Running %s' % onepass_cmd, file=test_log)
        self.child = pexpect.spawn(onepass_cmd)

        # unset ONLCR flag
        # disable conversion of '\n' to '\r\n' in child's output
        attr = termios.tcgetattr(self.child.child_fd)
        attr[1] &= ~termios.ONLCR
        termios.tcsetattr(self.child.child_fd, termios.TCSANOW, attr)

        self.child.logfile = test_log

        # disable the delays that pexpect adds by default
        # before sending to children and after closing
        # the process. The issues described in the pexpect
        # documentation are not an issue in this case
        self.child.delaybeforesend = 0
        self.child.delayafterclose = 0

    def expect(self, pattern):
        try:
            self.child.expect(pattern, timeout=3)
        except pexpect.TIMEOUT:
            self.test.fail("Child did not produce expected output '%s'" % pattern)
        except pexpect.EOF:
            self.test.fail("Child exited before producing expected output '%s'" % pattern)
        return self

    def sendline(self, line):
        self.child.sendline(line)
        return self

    def wait(self, expect_status=0):
        self.expect(pexpect.EOF)
        self.child.close()
        self.test.assertEqual(self.child.exitstatus, expect_status)

class OnePassTests(unittest.TestCase):
    def exec_1pass(self, cmd):
        return OnePassCmd(self, self.vault_path, cmd)

    def setUp(self):
        tmpdir = os.getenv('TMPDIR') or '/tmp'
        self.vault_path = '%s/1pass-test-%d.agilekeychain' % (tmpdir, random.randint(0,2**16))
        if os.path.exists(self.vault_path):
            shutil.rmtree(self.vault_path)

    def tearDown(self):
        shutil.rmtree(self.vault_path)

    def _createVault(self):
        # Setup a new vault
        (self.exec_1pass('new')
          .expect('Creating new vault.*' + self.vault_path)
          .expect('Enter master password')
          .sendline(TEST_PASSWD)
          .expect('Re-enter master password')
          .sendline(TEST_PASSWD)
          .wait())
        # Unlock vault
        (self.exec_1pass('list')
          .expect('Master password')
          .sendline(TEST_PASSWD)
          .wait())

    def _addLoginItem(self, name, user, passwd, site):
       # Add a new item to the vault
        (self.exec_1pass('add login %s' % name)
          .expect('username')
          .sendline(user)
          .expect('password')
          .sendline(passwd)
          .expect('Re-enter')
          .sendline(passwd)
          .expect('website')
          .sendline(site)
          .expect("Added new item '%s'" % name)
          .wait())

    def testLockUnlock(self):
        self._createVault()

        # Ensure new vault is locked
        (self.exec_1pass('lock')
          .wait())

        # List vault contents - should be empty
        (self.exec_1pass('list')
          .expect('Master password')
          .sendline(TEST_PASSWD)
          .wait())

        # List again, no password required
        (self.exec_1pass('list')
          .wait())

        # Lock vault
        (self.exec_1pass('lock')
          .wait())

        # List again, password should
        # be requested
        (self.exec_1pass('list')
          .expect('Master password')
          .sendline(TEST_PASSWD)
          .wait())

    def testAddEditItem(self):
        self._createVault()

        # Add a new item to the vault
        self._addLoginItem('mysite', 'myuser', 'mypass', 'mysite.com')

        # Show the new item
        (self.exec_1pass('show mysite')
          .expect('mysite.com')
          .expect('myuser')
          .expect('mypass')
          .wait())

        # Add a custom field to the new item
        (self.exec_1pass('edit mysite')
          .expect('Section')
          .sendline('CustomSection')
          .expect('Field')
          .sendline('CustomField')
          .expect('CustomField')
          .sendline('CustomFieldValue')
          .wait())

        # Update the custom field
        (self.exec_1pass('edit mysite')
          .expect('Section')
          .sendline('1')
          .expect('Field')
          .sendline('1')
          .expect('CustomField')
          .sendline('NewCustomFieldValue')
          .wait())

        (self.exec_1pass('show mysite')
          .expect('NewCustomFieldValue')
          .wait())

        # List the vault contents
        (self.exec_1pass('list')
          .expect('mysite')
          .wait())

        # List vault contents by type
        (self.exec_1pass('list login')
          .expect('mysite')
          .wait())

        # List vault contents by type and pattern
        (self.exec_1pass('list login:mys')
          .expect('mysite')
          .wait())
        (self.exec_1pass('list login:')
          .expect('mysite')
          .wait())

        # Remove item
        (self.exec_1pass('remove mysite')
          .expect("Remove 'mysite' from vault")
          .sendline('y')
          .wait())

        (self.exec_1pass('show mysite')
          .expect('No matching items')
          .wait())

    def testRenameItem(self):
        self._createVault()
        self._addLoginItem('mysite', 'myuser', 'mypass', 'mysite.com')

        (self.exec_1pass('rename mysite newname')
         .wait())
        (self.exec_1pass('show newname')
         .expect('mysite.com')
         .wait())

    def testTrashRestoreItem(self):
        self._createVault()
        self._addLoginItem('mysite', 'myuser', 'mypass', 'mysite.com')

        (self.exec_1pass('trash mysite')
         .wait())
        (self.exec_1pass('list')
         .expect('mysite.*(in trash)')
         .wait())
        (self.exec_1pass('restore mysite')
         .wait())
        (self.exec_1pass('list')
         .expect('mysite')
         .wait())

    def testFolder(self):
        self._createVault()
        self._addLoginItem('mysite', 'myuser', 'mypass', 'mysite.com')

        # Create a folder
        (self.exec_1pass('add folder NewFolder')
          .wait())
        (self.exec_1pass('list folder')
          .expect('NewFolder')
          .wait())

        # Move the item to the folder
        (self.exec_1pass('move mysite newfolder')
          .wait())
        (self.exec_1pass('list-folder newfolder')
          .expect('mysite')
          .wait())

        # Remove the item from the folder
        (self.exec_1pass('move mysite')
          .wait())
        (self.exec_1pass('list-folder newfolder')
          .wait())

        # Remove the folder
        (self.exec_1pass('remove newfolder')
          .expect("Remove 'NewFolder' from vault")
          .sendline('y')
          .wait())

        # Check folder no longer exists
        (self.exec_1pass('list-folder newfolder')
          .expect('Failed to find folder')
          .wait(expect_status=1))

    def testTags(self):
        self._createVault()
        self._addLoginItem('mysite', 'myuser', 'mypass', 'mysite.com')
        (self.exec_1pass('add-tag mysite tag1')
         .wait())
        (self.exec_1pass('list-tags')
         .expect('tag1')
         .wait())
        (self.exec_1pass('show mysite')
         .expect('Tags: tag1')
         .wait())
        (self.exec_1pass('add-tag mysite anothertag')
         .wait())
        (self.exec_1pass('show mysite')
         .expect('Tags: tag1, anothertag')
         .wait())
        (self.exec_1pass('list-tag tag1')
         .expect('mysite')
         .wait())
        (self.exec_1pass('remove-tag mysite tag1')
         .wait())
        (self.exec_1pass('show mysite')
         .expect('Tags: anothertag')
         .wait())

    def testCopy(self):
        self._createVault()
        self._addLoginItem('mysite', 'myuser', 'mypass', 'mysite.com')

        clipboard.copy('test')
        if clipboard.paste() != 'test':
            # running on a system without clipboard support
            # (eg. Linux sans Xorg)
            self.skipTest('Clipboard not supported')
            return

        (self.exec_1pass('copy mysite')
         .wait())
        self.assertEqual(clipboard.paste(), 'mypass')

        (self.exec_1pass('copy mysite user')
         .wait())
        self.assertEqual(clipboard.paste(), 'myuser')

    def testExport(self):
        self._createVault()
        self._addLoginItem('mysite', 'myuser', 'mypass', 'mysite.com')
        self._addLoginItem('anothersite', 'anotheruser', 'anotherpass', 'foo.com')
        
        exported_path = 'mysite-exported.1pif'

        if os.path.exists(exported_path):
            shutil.rmtree(exported_path)

        (self.exec_1pass('export login mysite-exported')
         .wait())

        # FIXME - Daemon does not lock vault if it is removed
        # and replaced with another at the same path
        (self.exec_1pass('lock')
         .wait())
        shutil.rmtree(self.vault_path)

        self._createVault()

        (self.exec_1pass('import mysite-exported.1pif')
         .expect("Imported item '.*'")
         .expect("Imported item '.*'")
         .wait())
        (self.exec_1pass('show mysite')
         .expect('mysite.com')
         .wait())

    def testChangePassword(self):
        self._createVault()

        (self.exec_1pass('set-password')
          .expect('Current master password')
          .sendline(TEST_PASSWD)
          .expect('New master password')
          .sendline('new-passwd')
          .expect('Re-enter')
          .sendline('new-passwd')
          .wait())
        (self.exec_1pass('lock')
          .wait())
        (self.exec_1pass('show mysite')
          .expect('Master password')
          .sendline(TEST_PASSWD)
          .expect('Incorrect password')
          .wait(expect_status=1))
        (self.exec_1pass('show mysite')
          .expect('Master password')
          .sendline('new-passwd')
          .expect('No matching items')
          .wait())
        (self.exec_1pass('lock')
          .wait())

if __name__ == '__main__':
    unittest.main()

