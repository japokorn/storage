#!/usr/bin/python
# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['stableinterface'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: crypt_dev

short_description: Manage encrypted (LUKS) devices

version_added: "2.5"

description:
    Module manages LUKS on given device. Supports creating, destroying,
    opening and closing of LUKS container and adding or removing new keys.

options:
    device:
        description:
            Device to work with (e.g. '/dev/sda1'). Needed in most cases.
        type: string
    state:
        description:
            Based on its value creates or destroys the LUKS container on
            a given device. Container creation requires 'device' and 'key'
            options to be supplied.
        default: "present"
        choices: "present", "absent"
        type: string
    open:
        description:
            Based on its value unlocks or locks an existing LUKS container
            on a given device. Use the 'name' option to set the name of
            the opened container. Otherwise the name will be generated
            automatically and returned in the result.
        default: false
        type: bool
    name:
        description:
            Sets container name when 'open' is true. Can be used
            instead of 'device' when closing the container
            (i.e. when 'open' is set to false).
        type: string
    key:
        description:
            Used to unlock the container and needed for most of the operations.
            Parameter value is the path to keyfile with the passphrase.
            WARNING: Working with keyfiles in plaintext is dangerous.
            Use Ansible Vault to protect them.
        type: string
    new_key:
        description:
            Adds additional key to given container. Needs 'key' option
            for authorization. LUKS container supports up to 8 keys.
            Parameter value is the path to keyfile with the passphrase.
            WARNING: Working with keyfiles in plaintext is dangerous.
            Use Ansible Vault to protect them.
        type: string
    remove_key:
        description:
            Removes given key from given container.
            Parameter value is the path to keyfile with the passphrase.
            WARNING: It is possible to remove even the last key from the
            container. Data in there will be irreversibly lost.
            WARNING: Working with keyfiles in plaintext is dangerous.
            Use Ansible Vault to protect them.
        type: string

requirements:
    cryptsetup

notes:
    This module does not support check mode. The reason being that
    while it is possible to chain several operations together
    (e.g. "create" and "open"), the latter usually depends on changes
    to the system done by the previous one. (LUKS cannot be opened,
    when it does not exist.)

author:
    Jan Pokorny (japokorn@redhat.com)
'''

EXAMPLES = '''
- name: create and open the LUKS container
  crypt_dev:
    device: "/dev/loop0"
    state: "present"
    open: "true"
    key: "/vault/keyfile"

- name: close the LUKS container "mycrypt"
  crypt_dev:
    open: "false"
    name: "mycrypt"

- name: add new key to the LUKS container
  crypt_dev:
    device: "/dev/loop0"
    state: "present"
    key: "/vault/keyfile"
    new_key: "/vault/keyfile2"

- name: remove existing key from the LUKS container
  crypt_dev:
    device: "/dev/loop0"
    remove_key: "/vault/keyfile2"

- name: completely remove the LUKS container and its contents
  crypt_dev:
    device: "/dev/loop0"
    state: "absent"
'''

RETURN = '''
name:
    description:
        When 'open' option is used returns (generated or given) name
        of LUKS container. Returns None if no name is supplied.
    returned: success
    type: string
    sample: "luks-c1da9a58-2fde-4256-9d9f-6ab008b4dd1b"
'''

import re

from ansible.module_utils.basic import AnsibleModule

RETURN_CODE = 0
STDOUT = 1
STDERR = 2

# used to get <luks-name> out of lsblk output in format 'crypt <luks-name>'
# regex takes care of any possible blank characters
LUKS_NAME_REGEX = re.compile(r'\s*crypt\s+([^\s]*)\s*')
# used to get </luks/device> out of lsblk output
# in format 'device: </luks/device>'
LUKS_DEVICE_REGEX = re.compile(r'\s*device:\s+([^\s]*)\s*')


class CryptHandler(object):

    def __init__(self, module):
        self._module = module

    def _run_command(self, command):
        return self._module.run_command(command)

    def run_luks_create(self, device, keyfile):
        # create a new luks container; use batch mode to auto confirm
        result = self._run_command(['cryptsetup', 'luksFormat',
                                    '-q', device, keyfile])
        if result[RETURN_CODE] != 0:
            raise ValueError('Error while creating LUKS on %s: %s'
                             % (device, result[STDERR]))

    def run_luks_open(self, device, keyfile, name):
        result = self._run_command(['cryptsetup', '--key-file', keyfile,
                                    'open', '--type', 'luks', device, name])
        if result[RETURN_CODE] != 0:
            raise ValueError('Error while opening LUKS container on %s: %s'
                             % (device, result[STDERR]))

    def run_luks_close(self, name):
        result = self._run_command(['cryptsetup', 'close', name])
        if result[RETURN_CODE] != 0:
            raise ValueError('Error while closing LUKS container %s' % (name))

    def run_luks_remove(self, device):

        name = self.get_container_name_by_device(device)
        if name is not None:
            self.run_luks_close(name)
        result = self._run_command(['wipefs', '--all', device])
        if result[RETURN_CODE] != 0:
            raise ValueError('Error while wiping luks container %s: %s'
                             % (device, result[STDERR]))

    def run_luks_add_key(self, device, key, new_key):
        ''' Add 'new_key' to given 'device'; authentization done using 'key'
            Raises ValueError when command fails
        '''
        result = self._run_command(['cryptsetup', 'luksAddKey', device,
                                    new_key, '--key-file', key])
        if result[RETURN_CODE] != 0:
            raise ValueError('Error while adding new LUKS key to %s: %s'
                             % (device, result[STDERR]))

    def run_luks_remove_key(self, device, key):
        ''' Remove key from given device
            Raises ValueError when command fails
        '''
        result = self._run_command(['cryptsetup', 'luksRemoveKey', device,
                                    '-q', '--key-file', key])
        if result[RETURN_CODE] != 0:
            raise ValueError('Error while removing LUKS key from %s: %s'
                             % (device, result[STDERR]))

    def generate_luks_name(self, device):
        ''' Generate name for luks based on device UUID ('luks-<UUID>').
            Raises ValueError when obtaining of UUID fails.
        '''
        result = self._run_command(['lsblk', '-n', device, '-o', 'UUID'])

        if result[RETURN_CODE] != 0:
            raise ValueError('Error while generating LUKS name for %s: %s'
                             % (device, result[STDERR]))
        dev_uuid = result[STDOUT].strip()
        return 'luks-%s' % dev_uuid

    def is_luks(self, device):
        ''' check if the LUKS device does exist
        '''
        result = self._run_command(['cryptsetup', 'isLuks', device])
        return result[RETURN_CODE] == 0

    def get_container_name_by_device(self, device):
        ''' obtain LUKS container name based on the device where it is located
            return None if not found
            raise ValueError if lsblk command fails
        '''
        result = self._run_command(['lsblk', device, '-nlo', 'type,name'])
        if result[RETURN_CODE] != 0:
            raise ValueError('Error while obtaining LUKS name for %s: %s'
                             % (device, result[STDERR]))

        m = LUKS_NAME_REGEX.search(result[STDOUT])

        try:
            name = m.group(1)
        except AttributeError as e:
            name = None
        return name

    def get_container_device_by_name(self, name):
        ''' obtain device name based on the LUKS container name
            return None if not found
            raise ValueError if lsblk command fails
        '''
        # apparently each device can have only one LUKS container on it
        result = self._run_command(['cryptsetup', 'status', name])
        if result[RETURN_CODE] != 0:
            return None

        m = LUKS_DEVICE_REGEX.search(result[STDOUT])
        device = m.group(1)
        return device


class Conditions(CryptHandler):

    def __init__(self, module):
        super(Conditions, self).__init__(module)

    def luks_create(self):
        return self._module.params['device'] is not None and\
               self._module.params['key'] is not None and\
               self._module.params['state'] == 'present' and\
               not self.is_luks(self._module.params['device'])

    def luks_open(self):
        if self._module.params['device'] is None or\
           self._module.params['key'] is None or\
           self._module.params['open'] == False:
            return False

        if self._module.params['state'] == 'absent':
            # better warn the user to recheck the configuration
            self._module.fail_json(msg="Contradiction in setup: LUKS set "
                                   "to be 'absent' and 'open'.")

        # try to obtain luks name - it may be already opened
        name = self.get_container_name_by_device(self._module.params['device'])
        if name is not None:
            if name != self._module.params['name']:
                # the container is already open but with different name:
                # suspicious. back off
                self._module.fail_json(msg="LUKS container is already opened "
                                       "under different name '%s'." % name)
            else:
                # the container of this name is already open. nothing to do
                return False
        # container is not open
        return True

    def luks_close(self):
        if (self._module.params['name'] is None and
           self._module.params['device'] is None) or\
           self._module.params['open'] == True or\
           self._module.params['state'] == 'absent':
            return False

        if self._module.params['device'] is not None:
            name = self.get_container_name_by_device(
                self._module.params['device'])
            # sucessfully getting name based on device means that luks is open
            luks_is_open = name is not None

        if self._module.params['name'] is not None:
            device = self.get_container_device_by_name(
                self._module.params['name'])
            # sucessfully getting device based on name means that luks is open
            luks_is_open = device is not None

        return luks_is_open

    def luks_add_key(self):
        if self._module.params['device'] is None or\
           self._module.params['key'] is None or\
           self._module.params['new_key'] is None:
            return False

        if self._module.params['state'] == 'absent':
            self._module.fail_json(msg="Contradiction in setup: Asking to "
                                   "add a key to absent LUKS.")

        return True

    def luks_remove_key(self):
        if self._module.params['device'] is None or\
           self._module.params['remove_key'] is None:
            return False

        if self._module.params['state'] == 'absent':
            self._module.fail_json(msg="Contradiction in setup: Asking to "
                                   "remove a key from absent LUKS.")

        return True

    def luks_remove(self):
        return self._module.params['device'] is not None and\
               self._module.params['state'] == 'absent' and\
               self.is_luks(self._module.params['device'])


def run_module():
    # available arguments/parameters that a user can pass
    module_args = dict(
        device=dict(type='str', required=False),
        state=dict(type='str', required=False, default='present'),
        open=dict(type='bool', required=False, default=False),
        name=dict(type='str', required=False),
        key=dict(type='str', required=False),
        new_key=dict(type='str', required=False),
        remove_key=dict(type='str', required=False)
    )

    # seed the result dict in the object
    result = dict(
        changed=False,
        name=None
    )

    module = AnsibleModule(argument_spec=module_args,
                           supports_check_mode=False)

    crypt = CryptHandler(module)
    conditions = Conditions(module)

    if module.params['state'] not in [None, 'present', 'absent']:
        module.fail_json(msg="Invalid 'state' value: '%s'. "
                         "Allowed values are: 'present', 'absent'"
                         % module.params['state'])

    # The conditions are in order to allow more operations in one run.
    # (e.g. create luks and add a key to it)

    # luks create
    if conditions.luks_create():
        try:
            crypt.run_luks_create(module.params['device'],
                                  module.params['key'])
        except ValueError as e:
            module.fail_json(msg="crypt_dev error: %s" % e)
        result['changed'] = True

    # luks open
    if conditions.luks_open():
        name = module.params['name']
        if name is None:
            try:
                name = crypt.generate_luks_name(module.params['device'])
            except ValueError as e:
                module.fail_json(msg="crypt_dev error: %s" % e)
        try:
            crypt.run_luks_open(module.params['device'],
                                module.params['key'],
                                name)
        except ValueError as e:
            module.fail_json(msg="crypt_dev error: %s" % e)
        result['name'] = name
        result['changed'] = True

    # luks close
    if conditions.luks_close():
        if module.params['device'] is not None:
            name = crypt.get_container_name_by_device(module.params['device'])
        else:
            name = module.params['name']
        crypt.run_luks_close(name)
        result['changed'] = True

    # luks add key
    if conditions.luks_add_key():
        try:
            crypt.run_luks_add_key(module.params['device'],
                                   module.params['key'],
                                   module.params['new_key'])
        except ValueError as e:
            module.fail_json(msg="crypt_dev error: %s" % e)
        result['changed'] = True

    # luks remove key
    if conditions.luks_remove_key():
        try:
            crypt.run_luks_remove_key(module.params['device'],
                                      module.params['remove_key'])
        except ValueError as e:
            module.fail_json(msg="crypt_dev error: %s" % e)
        result['changed'] = True

    # luks remove
    if conditions.luks_remove():
        crypt.run_luks_remove(module.params['device'])
        result['changed'] = True

    # Success - return result
    module.exit_json(**result)


def main():
    run_module()

if __name__ == '__main__':
    main()
