import pytest
import crypt_dev
from ansible.module_utils.basic import AnsibleModule, _ANSIBLE_ARGS


class DummyModule(object):
    def __init__(self):
        self.params = dict()

    def fail_json(self, msg=""):
        raise ValueError(msg)


# ===== CryptHandler methods tests =====
def test_generate_luks_name(monkeypatch):
    monkeypatch.setattr(crypt_dev.CryptHandler, "_run_command",
                        lambda x, y: [0, "UUID", ""])
    crypt = crypt_dev.CryptHandler(None)
    assert crypt.generate_luks_name("/dev/dummy") == "luks-UUID"


def test_get_container_name_by_device(monkeypatch):
    monkeypatch.setattr(crypt_dev.CryptHandler, "_run_command",
                        lambda x, y: [0, "crypt container_name", ""])
    crypt = crypt_dev.CryptHandler("dummy")
    assert crypt.get_container_name_by_device("/dev/dummy") == "container_name"


def test_get_container_device_by_name(monkeypatch):
    monkeypatch.setattr(crypt_dev.CryptHandler, "_run_command",
                        lambda x, y: [0, "device:  /dev/luksdevice", ""])
    crypt = crypt_dev.CryptHandler("dummy")
    assert crypt.get_container_device_by_name("dummy") == "/dev/luksdevice"


def test_run_luks_remove(monkeypatch):
    def run_command_check(self, command):
        # check that wipefs command is actually called
        assert command[0] == "wipefs"
        return [0, "", ""]

    monkeypatch.setattr(crypt_dev.CryptHandler,
                        "get_container_name_by_device",
                        lambda x, y: None)
    monkeypatch.setattr(crypt_dev.CryptHandler,
                        "_run_command",
                        run_command_check)
    crypt = crypt_dev.CryptHandler("dummy")
    crypt.run_luks_remove("dummy")


# ===== Conditions methods tests =====
def test_luks_create(monkeypatch):

    param_vector = [
        {"device": "dummy", "key": "key", "state": "present", "is_luks": False,
         "result": True},
        {"device": None, "key": "key", "state": "present", "is_luks": False,
         "result": False},
        {"device": "dummy", "key": None, "state": "present", "is_luks": False,
         "result": False},
        {"device": "dummy", "key": "key", "state": "absent", "is_luks": False,
         "result": False},
        {"device": "dummy", "key": "key", "state": "present", "is_luks": True,
         "result": False},
                   ]

    module = DummyModule()
    for param_set in param_vector:
        module.params["device"] = param_set["device"]
        module.params["key"] = param_set["key"]
        module.params["state"] = param_set["state"]

        monkeypatch.setattr(crypt_dev.Conditions, "is_luks",
                            lambda x, y: param_set["is_luks"])
        conditions = crypt_dev.Conditions(module)
        assert conditions.luks_create() == param_set["result"]


def test_luks_remove(monkeypatch):

    param_vector = [
        {"device": "dummy", "state": "absent", "is_luks": True,
         "result": True},
        {"device": None, "state": "absent", "is_luks": True,
         "result": False},
        {"device": "dummy", "state": "present", "is_luks": True,
         "result": False},
        {"device": "dummy", "state": "absent", "is_luks": False,
         "result": False},
                   ]

    module = DummyModule()
    for param_set in param_vector:
        module.params["device"] = param_set["device"]
        module.params["state"] = param_set["state"]

        monkeypatch.setattr(crypt_dev.Conditions, "is_luks",
                            lambda x, y: param_set["is_luks"])
        conditions = crypt_dev.Conditions(module)
        assert conditions.luks_remove() == param_set["result"]


def test_luks_open(monkeypatch):

    param_vector = [
            {"device": "dummy", "key": "key", "state": "present",
             "open": True, "name": "name", "name_by_dev": None,
             "result": True},
            {"device": None, "key": "key", "state": "present",
             "open": True, "name": "name", "name_by_dev": None,
             "result": False},
            {"device": "dummy", "key": None, "state": "present",
             "open": True, "name": "name", "name_by_dev": None,
             "result": False},
            {"device": "dummy", "key": "key", "state": "present",
             "open": False, "name": "name", "name_by_dev": None,
             "result": False},
            {"device": "dummy", "key": "key", "state": "absent",
             "open": True, "name": "name", "name_by_dev": None,
             "result": "exception"},
            {"device": "dummy", "key": "key", "state": "present",
             "open": True, "name": "name", "name_by_dev": "name",
             "result": False},
            {"device": "dummy", "key": "key", "state": "present",
             "open": True, "name": "different_name", "name_by_dev": "name",
             "result": "exception"}
                   ]

    module = DummyModule()
    for param_set in param_vector:
        module.params["device"] = param_set["device"]
        module.params["key"] = param_set["key"]
        module.params["open"] = param_set["open"]
        module.params["state"] = param_set["state"]
        module.params["name"] = param_set["name"]

        monkeypatch.setattr(crypt_dev.Conditions,
                            "get_container_name_by_device",
                            lambda x, y: param_set["name_by_dev"])
        conditions = crypt_dev.Conditions(module)
        try:
            assert conditions.luks_open() == param_set["result"]
        except ValueError:
            assert param_set["result"] == "exception"


def test_luks_close(monkeypatch):
    param_vector = [
            {"device": "dummy", "dev_by_name": "dummy",
             "name": "name", "name_by_dev": "name",
             "state": "present", "open": False,
             "result": True},
            {"device": None, "dev_by_name": "dummy",
             "name": "name", "name_by_dev": "name",
             "state": "present", "open": False,
             "result": True},
            {"device": "dummy", "dev_by_name": "dummy",
             "name": None, "name_by_dev": "name",
             "state": "present", "open": False,
             "result": True},
            {"device": None, "dev_by_name": "dummy",
             "name": None, "name_by_dev": "name",
             "state": "present", "open": False,
             "result": False},
            {"device": "dummy", "dev_by_name": "dummy",
             "name": "name", "name_by_dev": "name",
             "state": "present", "open": True,
             "result": False},
            {"device": "dummy", "dev_by_name": "dummy",
             "name": "name", "name_by_dev": "name",
             "state": "absent", "open": False,
             "result": False}
                   ]

    module = DummyModule()
    for param_set in param_vector:
        module.params["device"] = param_set["device"]
        module.params["name"] = param_set["name"]
        module.params["state"] = param_set["state"]
        module.params["open"] = param_set["open"]

        monkeypatch.setattr(crypt_dev.Conditions,
                            "get_container_name_by_device",
                            lambda x, y: param_set["name_by_dev"])
        monkeypatch.setattr(crypt_dev.Conditions,
                            "get_container_device_by_name",
                            lambda x, y: param_set["dev_by_name"])
        conditions = crypt_dev.Conditions(module)
        assert conditions.luks_close() == param_set["result"]


def test_luks_add_key(monkeypatch):
    param_vector = [
        {"device": "dummy", "key": "key", "new_key": "new_key",
         "state": "present", "result": True},
        {"device": None, "key": "key", "new_key": "new_key",
         "state": "present", "result": False},
        {"device": "dummy", "key": None, "new_key": "new_key",
         "state": "present", "result": False},
        {"device": "dummy", "key": "key", "new_key": None,
         "state": "present", "result": False},
        {"device": "dummy", "key": "key", "new_key": "new_key",
         "state": "absent", "result": "exception"}
                   ]

    module = DummyModule()
    for param_set in param_vector:
        module.params["device"] = param_set["device"]
        module.params["key"] = param_set["key"]
        module.params["new_key"] = param_set["new_key"]
        module.params["state"] = param_set["state"]

        conditions = crypt_dev.Conditions(module)
        try:
            assert conditions.luks_add_key() == param_set["result"]
        except ValueError:
            assert param_set["result"] == "exception"


def test_luks_remove_key(monkeypatch):
    param_vector = [
        {"device": "dummy", "remove_key": "key", "state": "present",
         "result": True},
        {"device": None, "remove_key": "key", "state": "present",
         "result": False},
        {"device": "dummy", "remove_key": None, "state": "present",
         "result": False},
        {"device": "dummy", "remove_key": "key", "state": "absent",
            "result": "exception"}
                   ]

    module = DummyModule()
    for param_set in param_vector:
        module.params["device"] = param_set["device"]
        module.params["remove_key"] = param_set["remove_key"]
        module.params["state"] = param_set["state"]

        conditions = crypt_dev.Conditions(module)
        try:
            assert conditions.luks_remove_key() == param_set["result"]
        except ValueError:
            assert param_set["result"] == "exception"
