#!/usr/bin/env python3
import unittest

import _env  # noqa: F401  (sets up sandboxed OM_HOME and python path)
from gitops import stream


class TestStreamLabels(unittest.TestCase):
    def test_default_private_slot_stream(self):
        labels = {"om.tcp": "25565"}
        meta, probs = stream.parse_stream_meta(labels, "mc")
        self.assertEqual(probs, [])
        self.assertIsNotNone(meta)
        self.assertEqual(meta["container_port"], 25565)
        self.assertIsNone(meta["host_port"])
        self.assertEqual(meta["scope"], "private")
        self.assertEqual(meta["log"], "on")

    def test_explicit_host_port_public_and_nolog(self):
        labels = {
            "om.tcp": "25565",
            "om.tcp.port": "25565",
            "dashboard.scope": "public",
            "om.log": "off",
        }
        meta, probs = stream.parse_stream_meta(labels, "mc")
        self.assertEqual(probs, [])
        self.assertIsNotNone(meta)
        self.assertEqual(meta["container_port"], 25565)
        self.assertEqual(meta["host_port"], 25565)
        self.assertEqual(meta["scope"], "public")
        self.assertEqual(meta["log"], "off")

    def test_scope_fails_closed_to_private(self):
        for bad_scope in ("", "pub", "PUBLIC_LAN", "local", "invalid"):
            labels = {"om.tcp": "25565", "dashboard.scope": bad_scope}
            meta, probs = stream.parse_stream_meta(labels, "mc")
            self.assertEqual(probs, [])
            self.assertEqual(meta["scope"], "private")

    def test_reject_privileged_host_ports(self):
        for p in (1, 22, 53, 80, 443, 1023):
            labels = {"om.tcp": "8080", "om.tcp.port": str(p)}
            meta, probs = stream.parse_stream_meta(labels, "svc")
            self.assertIsNone(meta)
            self.assertTrue(any("privileged" in pr or "clashes" in pr for pr in probs), probs)

    def test_reject_reserved_and_clashing_ports(self):
        # Exact clash: 80, 443, 8080, 8443
        for p in (8080, 8443):
            labels = {"om.tcp": "9000", "om.tcp.port": str(p)}
            meta, probs = stream.parse_stream_meta(labels, "svc")
            self.assertIsNone(meta)
            self.assertTrue(any("clashes" in pr for pr in probs), probs)

        # HTTP per-service range: 20000 - 21199
        for p in (20000, 20050, 20199, 21000, 21100, 21199):
            labels = {"om.tcp": "9000", "om.tcp.port": str(p)}
            meta, probs = stream.parse_stream_meta(labels, "svc")
            self.assertIsNone(meta)
            self.assertTrue(any("clashes with HTTP" in pr for pr in probs), probs)

        # Default stream range: 22000 - 22199
        for p in (22000, 22050, 22199):
            labels = {"om.tcp": "9000", "om.tcp.port": str(p)}
            meta, probs = stream.parse_stream_meta(labels, "svc")
            self.assertIsNone(meta)
            self.assertTrue(any("clashes with default stream" in pr for pr in probs), probs)

    def test_reject_invalid_container_ports(self):
        for bad in ("abc", "-1", "0", "70000", "25565a"):
            labels = {"om.tcp": bad}
            meta, probs = stream.parse_stream_meta(labels, "svc")
            self.assertIsNone(meta)
            self.assertTrue(len(probs) > 0)

    def test_no_tcp_label_returns_none_cleanly(self):
        meta, probs = stream.parse_stream_meta({"dashboard.port": "8080"}, "web")
        self.assertIsNone(meta)
        self.assertEqual(probs, [])


if __name__ == "__main__":
    unittest.main()
