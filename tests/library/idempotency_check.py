#!/usr/bin/python
# Copyright (c) 2019 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1",
                    "status": ["preview"],
                    "supported_by": "community"}

DOCUMENTATION = '''
---
module: idempotency_check

short_description: Test storage role for idempotency

version_added: "2.10"

description:
    - "Module allows to check idempotent behavior of storage role by storing
      and comparing system states. C(idempotency_check.yml) task is required
      to provide interface."

options:
    gather:
        description:
            - "Gather information about system and store its values under given name."
        type: str
    compare_1:
        description:
            - "Name of previously stored information, obtained by using I(gather)."
            - "Marks first state for comparison."
            - "Has to be used together with I(compare_2)."
        type: str
    compare_2:
        description:
            - "Name of previously stored information, obtained by using I(gather)."
            - "Marks second state for comparison."
            - "Has to be used together with I(compare_2)."
        type: str
    icy_facts:
        description:
            - "Internal parameter."
            - "Ansible facts that are created and modified by module."
            - "Module cannot get/set persistent facts, they have to be supplied by parameters."
            - "Starts as an empty dict."
        type: dict

requirements:
        - "python2-deepdiff"
        - "python3-deepdiff"

author:
    Jan Pokorny (@japokorn)
'''

EXAMPLES = '''
# idempotency_check.yml should look like this:
---

- name: Set up idempotency check facts space
  set_fact:
    icy_check: {}
    icy_diff: None
    icy_diff_details: {}
  when: icy_check is undefined

- name: Gather data
  idempotency_check:
    gather: "{{ gather | default(omit) }}"
    compare_1: "{{ compare_1 | default(omit) }}"
    compare_2: "{{ compare_2 | default(omit) }}"
    icy_facts: "{{ icy_check }}"
  register: icy_check_return

- block:
  - name: Update facts based on idempotency_check results
    set_fact:
      icy_check: "{{ icy_check_return.facts }}"
  when: gather is defined

- block:
  - name: Store comparison result
    set_fact:
      icy_diff_details: "{{ icy_check_return.diff_details }}"
      icy_diff: "{{ icy_check_return.diff }}"
  when: compare_1 is defined and compare_2 is defined


# idempotency_check.yml should be used like this:

---
- hosts: all
  become: true

  tasks:
    - include_role:
        name: storage

    - include_tasks: idempotency_check.yml
      vars:
        gather: "original_state"

    - name: First run
      debug:
        msg: "ash nazg durbatuluk"

    - include_tasks: idempotency_check.yml
      vars:
        gather: "after_first_run_state"
        compare_1: "original_state"
        compare_2: "after_first_run_state"

    - debug:
        var: icy_diff

    - debug:
        var: icy_diff_details

    - name: Second run
      debug:
        msg: "asz nazg gimbatul"

    - include_tasks: idempotency_check.yml
      vars:
        gather: "after_second_run_state"
        compare_1: "after_first_run_state"
        compare_2: "after_second_run_state"

    - debug:
        var: icy_diff

    - debug:
        var: icy_diff_details

'''

RETURN = '''
diff:
    description: "True when compared states are different, false otherwise." 
    returned: when compare_1 and compare_2 are defined
    type: bool
diff_details:
    description: 
        - "Empty dictionary when compared entities are the same,
           python deepdiff output otherwise."
    returned: "When compare_1 and compare_2 are defined"
    type: dict
facts:
    description: 
        - "Internal parameter to be used by C(idempotency_check.yml)."
        - "New set of ansible facts to replace the original one."
        - "Contains information about sytem states."
    returned: always
    type: dict
msg:
    description: "Warning or error message."
    returned: "When something goes wrong."
    type: str
'''

import shlex

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils import facts

try:
    from deepdiff import DeepDiff
except ImportError:
    deepdiff_present = False
else:
    deepdiff_present = True


LSBLK_DEVICE_TYPES = {"part": "partition"}

def get_block_info(run_cmd):
    buf = run_cmd(["lsblk", "-o", "NAME,FSTYPE,LABEL,UUID,TYPE", "-p", "-P", "-a"])[1]
    info = dict()
    for line in buf.splitlines():
        dev = dict()
        for pair in shlex.split(line):
            try:
                key, _eq, value = pair.partition("=")
            except ValueError:
                print(pair)
                raise
            if key:
                dev[key.lower()] = LSBLK_DEVICE_TYPES.get(value, value)
        if dev:
            info[dev['name']] = dev

    return info

def compare_dicts(dict_1, dict_2):
    return True


def run_module():
    # available arguments/parameters that a user can pass
    module_args = dict(
        gather=dict(type='str', required=False),
        compare_1=dict(type='str', required=False),
        compare_2=dict(type='str', required=False),
        icy_facts=dict(type='dict', required=True)
    )

    # seed the result dict in the object
    result = dict(
        changed=False,
        facts={},
        diff_details={},
        diff={}
    )

    module = AnsibleModule(argument_spec=module_args,
                           supports_check_mode=True)

    new_state_name = module.params['gather']
    compare_1_name = module.params['compare_1']
    compare_2_name = module.params['compare_2']
    icy_facts = module.params['icy_facts']

    # exactly one of the compare_# has been used => fail
    if (compare_1_name is None) != (compare_2_name is None):
        module.fail_json(msg="Both or none of 'compare_#'s must be used")

    # new state name given => create new 'snapshot'
    if new_state_name is not None:
        icy_facts[new_state_name] = get_block_info(module.run_command)

    result['facts'] = icy_facts

    # both compare_#s are defined => run comparison
    if (compare_1_name is not None and
        compare_2_name is not None):
        # compare states

        if deepdiff_present:
            diff_details = dict(DeepDiff(icy_facts[compare_1_name], icy_facts[compare_2_name]))
            diff = diff_details != {}
        else:
            result['msg'] = "WARNING: DeepDiff could not be imported, full comparison not available"
            diff_details = {}
            diff = icy_facts[compare_1_name] == icy_facts[compare_2_name]

        result['diff_details'] = diff_details
        result['diff'] = diff
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()

