#!/usr/bin/env python

# Test for the 1pass client app using
# pexpect to drive the client interactively

from __future__ import print_function
import pexpect
import shutil
import sys
import os

TEST_VAULT = '/tmp/1pass-client-test.agilekeychain'
TEST_PASSWD = 'test-pwd'

test_log = open('client_test.log', 'w')

# wrapper around pexpect which runs 1pass with
# a given command and provides expect(), sendline()
# and wait() methods to interact with the command.
#
# expect() and sendline() return self so method chaining
# can be used to create a sequence of interactions
class OnePassCmd:
    def __init__(self, vault, cmd):
        onepass_cmd = './1pass -vault %s %s' % (vault, cmd)
        print('Running %s' % onepass_cmd, file=test_log)
        self.child = pexpect.spawn(onepass_cmd)
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
            print("Child did not produce expected output '%s'" % pattern, file=sys.stderr)
            sys.exit(1)
        return self
    def sendline(self, line):
        self.child.sendline(line)
        return self
    def wait(self):
        self.child.expect(pexpect.EOF)

def exec_1pass(cmd):
    child = OnePassCmd(TEST_VAULT, cmd)
    return child

if os.path.exists(TEST_VAULT):
    shutil.rmtree(TEST_VAULT)

# Setup a new vault
(exec_1pass('new')
  .expect('Creating new vault.*' + TEST_VAULT)
  .expect('Enter master password')
  .sendline(TEST_PASSWD)
  .expect('Re-enter master password')
  .sendline(TEST_PASSWD)
  .wait())

# Ensure new vault is locked
(exec_1pass('lock')
  .wait())

# List vault contents - should be empty
(exec_1pass('list')
  .expect('Master password')
  .sendline(TEST_PASSWD)
  .wait())

# List again, no password required
(exec_1pass('list')
  .wait())

# Lock vault
(exec_1pass('lock')
  .wait())

# List again, password should
# be requested
(exec_1pass('list')
  .expect('Master password')
  .sendline(TEST_PASSWD)
  .wait())

# Add a new item to the vault
(exec_1pass('add login mysite')
  .expect('username')
  .sendline('myuser')
  .expect('password')
  .sendline('mypass')
  .expect('Re-enter')
  .sendline('mypass')
  .expect('website')
  .sendline('mysite.com')
  .wait())

# Show the new item
(exec_1pass('show mysite')
  .expect('mysite.com')
  .expect('myuser')
  .expect('mypass')
  .wait())

# Add a custom field to the new item
(exec_1pass('add-field mysite')
  .expect('Section')
  .sendline('CustomSection')
  .expect('Field')
  .sendline('CustomField')
  .expect('CustomField')
  .sendline('CustomFieldValue')
  .wait())

# Update the custom field
(exec_1pass('add-field mysite')
  .expect('Section')
  .sendline('1')
  .expect('Field')
  .sendline('1')
  .expect('CustomField')
  .sendline('NewCustomFieldValue')
  .wait())

(exec_1pass('show mysite')
  .expect('NewCustomFieldValue')
  .wait())

# List the vault contents
(exec_1pass('list')
  .expect('mysite')
  .wait())

# List vault contents by type
(exec_1pass('list login')
  .expect('mysite')
  .wait())

# Remove item
(exec_1pass('remove mysite')
  .expect("Remove 'mysite' from vault")
  .sendline('y')
  .wait())

(exec_1pass('show mysite')
  .expect('No matching items')
  .wait())

print('Interactive tests passed')

