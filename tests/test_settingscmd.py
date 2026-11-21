"""`om config`: every key of the om.env template is known, values are checked, the file stays 0600, secrets stay masked."""
import argparse
import contextlib
import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _env  # noqa: F401

from gitops import omsettings, settingscmd


def run(action, arg=None, **kw):
    out, err = io.StringIO(), io.StringIO()
    args = argparse.Namespace(action=action, arg=arg, reveal=kw.get("reveal", False), json=kw.get("json", False))
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            settingscmd.cmd_config(args)
            code = 0
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="om-config-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.env = self.tmp / "om.env"
        patcher = mock.patch.object(omsettings, "USER_ENV", self.env)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_schema_matches_the_template(self):
        template = set(omsettings.parse_env_file_text(omsettings.USER_ENV_TEMPLATE))
        self.assertEqual(settingscmd.KEYS, template)

    def test_values_are_checked(self):
        good = {"OM_HTTP_PORT": "8081", "OM_FIREWALL_EXTRA_TCP": "22, 1714-1764", "OM_FIREWALL_EXTRA_UDP": "",
                "OM_POLICY": "warn", "OM_SIGNED": "enforce", "OM_NOTIFY": "desktop,webhook", "OM_LAN_IP": "192.168.1.5",
                "OM_NOTIFY_URL": "https://ntfy.sh/topic", "OM_TRUSTED_USERS": "alice,bob-2", "OM_WALLPAPERS_DIR": "~/Pictures"}
        bad = {"OM_HTTP_PORT": "0", "OM_HTTPS_PORT": "70000", "OM_FIREWALL_EXTRA_TCP": "1764-1714", "OM_POLICY": "off",
               "OM_SIGNED": "maybe", "OM_NOTIFY": "email", "OM_LAN_IP": "not-an-ip", "OM_NOTIFY_URL": "http://example.com/x",
               "OM_TRUSTED_USERS": "Bad Name", "OM_FIREWALL_EXTRA_UDP": "80;rm"}
        for key, value in good.items():
            self.assertIsNone(settingscmd.check_value(key, value), (key, value))
        for key, value in bad.items():
            self.assertIsNotNone(settingscmd.check_value(key, value), (key, value))

    @unittest.skipIf(os.name == "nt", "POSIX modes")
    def test_set_writes_a_private_file_and_unset_restores_the_default(self):
        code, out, _ = run("set", "OM_POLICY=warn")
        self.assertEqual(code, 0)
        self.assertEqual(self.env.stat().st_mode & 0o777, 0o600)
        self.assertEqual(omsettings.load_settings()["OM_POLICY"], "warn")
        code, out, _ = run("set", "OM_HTTP_PORT=8081")
        self.assertIn("om firewall apply", out)
        run("unset", "OM_POLICY")
        self.assertEqual(omsettings.load_settings()["OM_POLICY"], "enforce")
        self.assertEqual(omsettings.load_settings()["OM_HTTP_PORT"], "8081")

    def test_bad_input_changes_nothing(self):
        self.assertNotEqual(run("set", "OM_HTTP_PORT=99999")[0], 0)
        self.assertNotEqual(run("set", "OM_POLICY")[0], 0)                      # no `=`
        code, _, err = run("set", "OM_HTTP_PROT=80")
        self.assertNotEqual(code, 0)
        self.assertIn("OM_HTTP_PORT", err)                                      # did you mean
        self.assertFalse(self.env.exists())

    def test_vpn_keys_keep_their_own_commands(self):
        for key in ("OM_VPN", "OM_VPN_ALLOW"):
            code, _, err = run("set", f"{key}=10.0.0.1")
            self.assertNotEqual(code, 0)
            self.assertIn("om vpn", err)
        self.assertFalse(self.env.exists())

    def test_secrets_are_masked_unless_revealed(self):
        url = "https://ntfy.sh/very-secret-topic"
        _, out, _ = run("set", f"OM_NOTIFY_URL={url}")
        self.assertNotIn("very-secret-topic", out)
        self.assertNotIn("very-secret-topic", run("show")[1])
        self.assertNotIn("very-secret-topic", run("get", "OM_NOTIFY_URL")[1])
        self.assertIn("very-secret-topic", run("get", "OM_NOTIFY_URL", reveal=True)[1])

    def test_show_json_lists_every_key(self):
        import json
        code, out, _ = run("show", json=True)
        self.assertEqual(code, 0)
        self.assertEqual(set(json.loads(out)), settingscmd.KEYS)


if __name__ == "__main__":
    unittest.main()
