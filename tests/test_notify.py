import unittest
from unittest import mock

import _env  # noqa: F401  (sets OM_HOME before importing om modules)

from gitops import notify


class TestNotify(unittest.TestCase):
    def setUp(self):
        notify.SEEN.unlink(missing_ok=True)
        notify.LOG.unlink(missing_ok=True)

    def _settings(self, **kw):
        return mock.patch.object(notify.omsettings, "load_settings", return_value=kw)

    def test_auto_is_desktop_only_and_off_is_none(self):
        for raw, want in (("auto", ["desktop"]), ("off", []), ("", []), ("desktop, webhook", ["desktop", "webhook"])):
            with self._settings(OM_NOTIFY=raw):
                self.assertEqual(notify.channels(), want, raw)
        with self._settings():
            self.assertEqual(notify.channels(), ["desktop"])  # unset means the default, auto

    def test_no_channels_still_logs(self):
        with self._settings(OM_NOTIFY="off"):
            self.assertEqual(notify.notify("t", "hello"), [])
        self.assertIn("t: hello", notify.LOG.read_text(encoding="utf-8"))

    def test_key_sends_once(self):
        calls = []
        with self._settings(OM_NOTIFY="webhook", OM_NOTIFY_URL="https://x.invalid/t"), \
                mock.patch.dict(notify.CHANNELS, {"webhook": lambda t, b: calls.append((t, b)) or (True, "ok")}):
            self.assertEqual(notify.notify("t", "b", key="k"), [("webhook", True, "ok")])
            self.assertEqual(notify.notify("t", "b", key="k"), [])
            self.assertEqual(len(notify.notify("t", "b", key="other")), 1)
        self.assertEqual(len(calls), 2)

    def test_webhook_needs_a_url_and_unknown_channels_are_reported(self):
        with self._settings(OM_NOTIFY="webhook,pigeon"):
            res = notify.notify("t", "b")
        self.assertEqual([(c, ok) for c, ok, _ in res], [("webhook", False), ("pigeon", False)])

    def test_webhook_posts_title_and_body(self):
        sent = {}

        class Resp:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_open(req, timeout=0):
            sent["url"], sent["data"], sent["method"] = req.full_url, req.data, req.get_method()
            return Resp()

        with self._settings(OM_NOTIFY_URL="https://ntfy.example/topic"), mock.patch.object(notify.urllib.request, "urlopen", fake_open):
            self.assertEqual(notify._webhook("T", "B"), (True, "HTTP 200"))
        self.assertEqual(sent, {"url": "https://ntfy.example/topic", "data": b"T\nB", "method": "POST"})

    def test_desktop_without_notify_send(self):
        with mock.patch.object(notify.sys, "platform", "linux"), mock.patch.object(notify.shutil, "which", return_value=None):
            ok, detail = notify._desktop("t", "b")
        self.assertFalse(ok)
        self.assertIn("notify-send", detail)


if __name__ == "__main__":
    unittest.main()


class TestWebhookUrl(unittest.TestCase):
    def test_https_anywhere_and_http_only_to_this_machine_or_a_private_address(self):
        for url in ("https://ntfy.sh/topic", "https://x.example:8443/t", "http://localhost:8080/t", "http://127.0.0.1/t", "http://192.168.1.9/t", "http://[::1]/t"):
            self.assertTrue(notify.webhook_url_ok(url), url)
        for url in ("http://ntfy.sh/topic", "http://8.8.8.8/t", "http://example.com", "ftp://x/y", "file:///etc/passwd", "https://", "ntfy.sh/topic", ""):
            self.assertFalse(notify.webhook_url_ok(url), url)
