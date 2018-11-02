#!/usr/bin/python

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: crypt_dev

short_description: Manage encrypted devices  

version_added: "2.5"

description:
    - "Module manages encryption on given devices"

options:
    device:
        description:
            - String
            - Device to work with (e.g. '/dev/sda1')
        required: false
    state:
        description:
            - String
            - Allowed values: present, absent
            - Default value: present
            - Desired state of LUKS device
        required: false
    open:
        description:
            - Bool
            - Desired state of LUKS container 
        required: false
    name:
        description:
            - String
            - name of LUKS container
        required: false
    key:
        description:
            - TODO
        required: false
    new_key:
        description:
            - TODO
        required: false
    remove_key:
        description:
            - TODO
        required: false


author:
    - Jan Pokorny (japokorn@redhat.com)
'''

EXAMPLES = '''
- name: create and open LUKS container
  crypt_dev:
    device: "/dev/loop0"
    state: "present"
    open: "true"
    key: HUGALABUGALUGALA TODO
'''

RETURN = '''
name:
    description: returns name of opened luks device, None if no device is open 
    type: str
'''

import re

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils import facts

RETURN_CODE = 0
STDOUT = 1
STDERR = 2

# used to get <luks-name> out of lsblk output in format 'crypt <luks-name>'
# regex takes care of any possible blank characters
LUKS_NAME_REGEX = re.compile(r'\s*crypt\s+([^\s]*)\s*')
# used to get </luks/device> out of lsblk output in format 'device: </luks/device>'
LUKS_DEVICE_REGEX = re.compile(r'\s*device:\s+([^\s]*)\s*')

class CryptHandler(object):

    def __init__(self, module):
        self._module = module
    #enddef

    def _run_command(self, command):
        return self._module.run_command(command)
    #enddef

    def luks_create(self, device, keyfile):
        # create a new luks container; use batch mode to auto confirm the action
        result = self._run_command(['cryptsetup', 'luksFormat', '-q', device, keyfile])
        if result[RETURN_CODE] != 0:
            raise ValueError('Error while creating LUKS on %s: %s' % (device, result[STDERR]))
    #enddef

    def luks_open(self, device, keyfile, name):
        result = self._run_command(['cryptsetup', '--key-file', keyfile,
                                  'open', '--type', 'luks', device, name
                                 ])
        if result[RETURN_CODE] != 0:
            raise ValueError('Error while opening LUKS container on %s: %s' % (device, result[STDERR]))
    #enddef

    def luks_close(self, name):
        result = self._run_command(['cryptsetup', 'close', name])
        if result[RETURN_CODE] != 0:
            raise ValueError('Error while closing LUKS container %s' % (name))
    #enddef

    def luks_remove(self, device):
        result = self._run_command(['wipefs', '--all', device])
        if result[RETURN_CODE] != 0:
            raise ValueError('Error while closing LUKS container %s' % (name))

    def luks_add_key(self, device, key, new_key):
        ''' Add 'new_key' to given 'device'; authentization done using 'key'
            Raises ValueError when command fails
        '''
        result = self._run_command(['cryptsetup', 'luksAddKey', device,
                                  new_key, '--key-file', key
                                 ])
        if result[RETURN_CODE] != 0:
            raise ValueError('Error while adding new LUKS key to %s: %s' % (device, result[STDERR]))
    #enddef

    def luks_remove_key(self, device, key):
        ''' Remove key from given device
            Raises ValueError when command fails
        '''
        result = self._run_command(['cryptsetup', 'luksRemoveKey', device,
                                  '-q', '--key-file', key
                                 ])
        if result[RETURN_CODE] != 0:
            raise ValueError('Error while removing LUKS key from %s: %s' % (device, result[STDERR]))
    #enddef

    def generate_luks_name(self, device):
        ''' Generate name for luks based on device UUID ('luks-<UUID>').
            Raises ValueError when obtaining of UUID fails.
        '''
        result = self._run_command(['lsblk', '-n', device, '-o', 'UUID'])

        if result[RETURN_CODE] != 0:
            raise ValueError('Error while generating LUKS name for %s: %s' % (device, result[STDERR]))
        dev_uuid = result[STDOUT].strip()
        return 'luks-%s' % dev_uuid
    #enddef

    def is_luks(self, device):
        ''' check if the LUKS device does exist
        '''
        result = self._run_command(['cryptsetup', 'isLuks', device])
        return result[RETURN_CODE] == 0
    #enddef

    def get_container_name_by_device(self, device):
        ''' obtain LUKS container name based on the device where it is located
            return None if not found
            raise ValueError if lsblk command fails
        '''
        result = self._run_command(['lsblk', device, '-nlo', 'type,name'])
        if result[RETURN_CODE] != 0:
            raise ValueError('Error while obtaining LUKS name for %s: %s' % (device, result[STDERR]))

        m = LUKS_NAME_REGEX.search(result[STDOUT])

        try:
            name = m.group(1)
        except AttributeError as e:
            name = None
        return name
    #enddef

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
#endclass



def run_module():
    # available arguments/parameters that a user can pass
    module_args = dict(
        device = dict(type='str', required=False),
        state = dict(type='str', required=False, default='present'),
        open = dict(type='bool', required=False),
        name = dict(type='str', required=False),
        key = dict(type='str', required=False),
        new_key = dict(type='str', required=False),
        remove_key = dict(type='str', required=False)
    )

    # seed the result dict in the object
    result = dict(
        changed=False,
        name=None
    )

    module = AnsibleModule(argument_spec=module_args,
                           supports_check_mode=True)  #TODO check_mode

    crypt = CryptHandler(module)

    if module.params['state'] not in [None, 'present', 'absent']:
        module.fail_json(msg="Invalid 'state' value: '%s'. Allowed values are: 'present', 'absent'"\
                             % module.params['state'])

    # It is possible to refactor following conditions to avoid some redundancy.
    # However keeping them this way greatly improves code readability.
    # The conditions are in order to allow more operations in one run.
    # (e.g. create luks and add a key to it)

    # luks create
    if module.params['device'] is not None and\
       module.params['key'] is not None and\
       module.params['state'] == 'present' and\
       not crypt.is_luks(module.params['device']):
        try:
            crypt.luks_create(module.params['device'], module.params['key'])
        except ValueError as e:
            module.fail_json(msg="crypt_dev error: %s" % e)
        result['changed'] = True

    # luks open 
    if module.params['device'] is not None and\
       module.params['key'] is not None and\
       module.params['open'] == True:

        if module.params['state'] == 'absent':
            # better warn the user to recheck the configuration
            module.fail_json(msg="Contradiction in setup: LUKS set to be 'absent' and 'open'.")

        # try to obtain luks name - it may be already opened
        name = crypt.get_container_name_by_device(module.params['device'])
        if name is not None:
            if name != module.params['name']:
                # the container is already open but with different name. suspicious. back off 
                module.fail_json(msg="LUKS container is already opened under different name '%s'." % name)
            else:
                # the container of this name is already open. nothing to do
                result['name'] = name
        else:
            # the container is not open
            name = module.params['name']
            if name is None:
                try:
                    name = crypt.generate_luks_name(module.params['device'])
                except ValueError as e:
                    module.fail_json(msg="crypt_dev error: %s" % e)

            try:
                crypt.luks_open(module.params['device'], module.params['key'], name)
            except ValueError as e:
                module.fail_json(msg="crypt_dev error: %s" % e)
            result['name'] = name
            result['changed'] = True

    # luks close
    if (module.params['name'] is not None or\
       module.params['device'] is not None) and\
       module.params['open'] == False and\
       module.params['state'] == 'present':
        name = module.params['name']

        if module.params['device'] is not None:
            name = crypt.get_container_name_by_device(module.params['device'])
            # sucessfully getting name based on device means that luks is open
            luks_open = name is not None

        if module.params['name'] is not None:
            device = crypt.get_container_device_by_name(module.params['name'])
            # sucessfully getting device based on name means that luks is open
            luks_open = device is not None

        if luks_open:
            crypt.luks_close(name)
            result['changed'] = True

    # luks add key
    if module.params['device'] is not None and\
       module.params['key'] is not None and\
       module.params['new_key'] is not None:
        if module.params['state'] == 'absent':
            module.fail_json(msg="Contradiction in setup: Asking to add a key to absent LUKS.")
        try:
            crypt.luks_add_key(module.params['device'], module.params['key'], module.params['new_key'])
        except ValueError as e:
            module.fail_json(msg="crypt_dev error: %s" % e)

        result['changed'] = True

    # luks remove key
    if module.params['device'] is not None and\
       module.params['remove_key'] is not None:
        if module.params['state'] == 'absent':
            module.fail_json(msg="Contradiction in setup: Asking to remove a key from absent LUKS.")
        try:
            crypt.luks_remove_key(module.params['device'], module.params['remove_key'])
        except ValueError as e:
            module.fail_json(msg="crypt_dev error: %s" % e)

        result['changed'] = True

    # luks remove
    if module.params['device'] is not None and\
       module.params['state'] == 'absent' and\
       crypt.is_luks(module.params['device']):
        crypt.luks_remove(module.params['device'])
        result['changed'] = True

    # Success - return result
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()

