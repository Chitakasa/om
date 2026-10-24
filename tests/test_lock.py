import tempfile
import unittest
from pathlib import Path

import _env  # noqa: F401  (sets OM_HOME before importing om modules)
from gitops import lock

A = "sha256:" + "a" * 64
B = "sha256:" + "b" * 64


class TestLock(unittest.TestCase):
    def test_parse_ref(self):
        self.assertEqual(lock.parse_ref("nginx:1.31-alpine"), ("docker.io", "library/nginx", "1.31-alpine", ""))
        self.assertEqual(lock.parse_ref("jellyfin/jellyfin"), ("docker.io", "jellyfin/jellyfin", "latest", ""))
        self.assertEqual(lock.parse_ref("ghcr.io/a/b:1.2"), ("ghcr.io", "a/b", "1.2", ""))
        self.assertEqual(lock.parse_ref("localhost:5000/x:dev"), ("localhost:5000", "x", "dev", ""))
        self.assertEqual(lock.parse_ref(f"caddy:2@{A}"), ("docker.io", "library/caddy", "2", A))

    def test_images_skips_builds(self):
        cfg = {"services": {"a": {"image": "x:1"}, "b": {"image": "y:1", "build": {"context": "."}}, "c": {}}}
        self.assertEqual(lock.images(cfg), {"a": "x:1"})

    def test_update_modes(self):
        cfg = {"services": {
            "a": {"image": "x:1", "labels": {"om.update": "hold"}},
            "b": {"image": "y:1", "labels": ["om.update=Manual"]},
            "c": {"image": "z:1", "labels": {"om.update": "auto"}},
            "d": {"image": "w:1"},
            "e": {"image": "v:1", "build": {"context": "."}, "labels": {"om.update": "hold"}},
        }}
        modes, bad = lock.update_modes(cfg)
        self.assertEqual(modes, {"a": "hold", "b": "manual", "c": "manual", "d": "manual"})
        self.assertEqual(bad, ["c: om.update=auto"])

    def test_describe_picks_this_platform(self):
        import json, platform
        arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine().lower(), "amd64")
        index = {"manifests": [{"digest": A, "platform": {"os": "linux", "architecture": arch}},
                               {"digest": B, "platform": {"os": "linux", "architecture": "s390x"}}]}
        image = {"config": {"digest": B}, "layers": [{"size": 10}, {"size": 5}]}
        bodies = {f"manifests/{B}": index, f"manifests/{A}": image, f"blobs/{B}": {"created": "2026-10-20T01:02:03Z"}}
        orig = lock._open
        try:
            lock._open = lambda ref, path, method="GET": (None, json.dumps(bodies[path]).encode("utf-8"))
            self.assertEqual(lock.describe("x:1", B), {"size": 15, "created": "2026-10-20"})
            lock._open = lambda ref, path, method="GET": (None, b"")
            self.assertEqual(lock.describe("x:1", B), {})
        finally:
            lock._open = orig

    def test_resolve_prefers_pin_then_running_then_registry(self):
        orig = (lock.registry_digest, lock.local_digest)
        try:
            lock.registry_digest = lambda ref: B
            lock.local_digest = lambda rt, ref: A if ref == "running:1" else ""
            pinned, missing = lock.resolve("podman", ["pinned:1", "running:1", "new:1"], {"pinned:1": A})
            self.assertEqual(pinned, {"pinned:1": A, "running:1": A, "new:1": B})
            self.assertEqual(missing, [])
            # om update moves everything to the registry's current digest
            pinned, _ = lock.resolve("podman", ["pinned:1", "running:1"], {"pinned:1": A}, refresh=True)
            self.assertEqual(pinned, {"pinned:1": B, "running:1": B})
            lock.registry_digest = lambda ref: ""
            self.assertEqual(lock.resolve("podman", ["gone:1"])[1], ["gone:1"])
        finally:
            lock.registry_digest, lock.local_digest = orig

    def test_read_write_and_override(self):
        root = Path(tempfile.mkdtemp())
        (root / ".om").mkdir()
        lock.write(root, {"x:1": A, "bad:1": "latest"})
        self.assertEqual(lock.read(root), {"x:1": A})  # invalid digests are ignored
        cfg = {"services": {"web": {"image": "x:1"}, "db": {"image": "y:1"}}}
        path = lock.write_override("ws", "/p", cfg, lock.read(root))
        text = path.read_text(encoding="utf-8")
        self.assertIn(f'image: "x:1@{A}"', text)
        self.assertNotIn('"db"', text)
        self.assertIsNone(lock.write_override("ws", "/p", cfg, {}))


if __name__ == "__main__":
    unittest.main()
