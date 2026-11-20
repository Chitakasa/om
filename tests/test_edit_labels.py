"""`om edit`: setting dashboard labels in a compose file (scaffold.edit_labels), for seven layouts of the file and four
edits. Expected files recorded before the editing was moved out of cmd_edit."""
import argparse
import unittest

import _env  # noqa: F401

from gitops import scaffold

TEXTS={
 "labels with scope": 'services:\n  web:\n    image: nginx\n    labels:\n      - "dashboard.scope=private"\n      - "dashboard.name=Web"\n    expose:\n      - "80"\n',
 "labels without it": 'services:\n  web:\n    image: nginx\n    labels:\n      - "workspace.id=x"\n    expose:\n      - "80"\n',
 "labels at end": 'services:\n  web:\n    image: nginx\n    labels:\n      - "workspace.id=x"\n',
 "no labels": 'services:\n  web:\n    image: nginx\n    container_name: c\n    expose:\n      - "80"\n',
 "no image no name": 'services:\n  web:\n    build: .\n',
 "comment in labels": 'services:\n  web:\n    image: n\n    labels:\n      # keep\n      - "dashboard.icon=a"\n      - "x=1"\n    restart: always\n',
 "deeper indent": 'services:\n    web:\n        image: n\n        labels:\n            - "dashboard.port=1"\n        restart: always\n',
}
CASES=[{"scope": "public"},{"port": 9090},{"icon": "X","desc": "d","name": "N"},{"scope": "PUBLIC","port": 1,"icon": "i"}]
EXPECTED = {'labels with scope|0': 'services:\n  web:\n    image: nginx\n    labels:\n      - "dashboard.scope=public"\n      - "dashboard.name=Web"\n    expose:\n      - "80"\n', 'labels with scope|1': 'services:\n  web:\n    image: nginx\n    labels:\n      - "dashboard.scope=private"\n      - "dashboard.name=Web"\n      - "dashboard.port=9090"\n    expose:\n      - "80"\n', 'labels with scope|2': 'services:\n  web:\n    image: nginx\n    labels:\n      - "dashboard.scope=private"\n      - "dashboard.name=N"\n      - "dashboard.icon=X"\n      - "dashboard.description=d"\n    expose:\n      - "80"\n', 'labels with scope|3': 'services:\n  web:\n    image: nginx\n    labels:\n      - "dashboard.scope=public"\n      - "dashboard.name=Web"\n      - "dashboard.port=1"\n      - "dashboard.icon=i"\n    expose:\n      - "80"\n', 'labels without it|0': 'services:\n  web:\n    image: nginx\n    labels:\n      - "workspace.id=x"\n      - "dashboard.scope=public"\n    expose:\n      - "80"\n', 'labels without it|1': 'services:\n  web:\n    image: nginx\n    labels:\n      - "workspace.id=x"\n      - "dashboard.port=9090"\n    expose:\n      - "80"\n', 'labels without it|2': 'services:\n  web:\n    image: nginx\n    labels:\n      - "workspace.id=x"\n      - "dashboard.icon=X"\n      - "dashboard.description=d"\n      - "dashboard.name=N"\n    expose:\n      - "80"\n', 'labels without it|3': 'services:\n  web:\n    image: nginx\n    labels:\n      - "workspace.id=x"\n      - "dashboard.scope=public"\n      - "dashboard.port=1"\n      - "dashboard.icon=i"\n    expose:\n      - "80"\n', 'labels at end|0': 'services:\n  web:\n    image: nginx\n    labels:\n      - "workspace.id=x"\n      - "dashboard.scope=public"\n', 'labels at end|1': 'services:\n  web:\n    image: nginx\n    labels:\n      - "workspace.id=x"\n      - "dashboard.port=9090"\n', 'labels at end|2': 'services:\n  web:\n    image: nginx\n    labels:\n      - "workspace.id=x"\n      - "dashboard.icon=X"\n      - "dashboard.description=d"\n      - "dashboard.name=N"\n', 'labels at end|3': 'services:\n  web:\n    image: nginx\n    labels:\n      - "workspace.id=x"\n      - "dashboard.scope=public"\n      - "dashboard.port=1"\n      - "dashboard.icon=i"\n', 'no labels|0': 'services:\n  web:\n    image: nginx\n    labels:\n      - "dashboard.scope=public"\n    container_name: c\n    expose:\n      - "80"\n', 'no labels|1': 'services:\n  web:\n    image: nginx\n    labels:\n      - "dashboard.port=9090"\n    container_name: c\n    expose:\n      - "80"\n', 'no labels|2': 'services:\n  web:\n    image: nginx\n    labels:\n      - "dashboard.icon=X"\n      - "dashboard.description=d"\n      - "dashboard.name=N"\n    container_name: c\n    expose:\n      - "80"\n', 'no labels|3': 'services:\n  web:\n    image: nginx\n    labels:\n      - "dashboard.scope=public"\n      - "dashboard.port=1"\n      - "dashboard.icon=i"\n    container_name: c\n    expose:\n      - "80"\n', 'no image no name|0': 'services:\n  web:\n    build: .\n', 'no image no name|1': 'services:\n  web:\n    build: .\n', 'no image no name|2': 'services:\n  web:\n    build: .\n', 'no image no name|3': 'services:\n  web:\n    build: .\n', 'comment in labels|0': 'services:\n  web:\n    image: n\n    labels:\n      # keep\n      - "dashboard.icon=a"\n      - "x=1"\n      - "dashboard.scope=public"\n    restart: always\n', 'comment in labels|1': 'services:\n  web:\n    image: n\n    labels:\n      # keep\n      - "dashboard.icon=a"\n      - "x=1"\n      - "dashboard.port=9090"\n    restart: always\n', 'comment in labels|2': 'services:\n  web:\n    image: n\n    labels:\n      # keep\n      - "dashboard.icon=X"\n      - "x=1"\n      - "dashboard.description=d"\n      - "dashboard.name=N"\n    restart: always\n', 'comment in labels|3': 'services:\n  web:\n    image: n\n    labels:\n      # keep\n      - "dashboard.icon=i"\n      - "x=1"\n      - "dashboard.scope=public"\n      - "dashboard.port=1"\n    restart: always\n', 'deeper indent|0': 'services:\n    web:\n        image: n\n        labels:\n            - "dashboard.port=1"\n          - "dashboard.scope=public"\n        restart: always\n', 'deeper indent|1': 'services:\n    web:\n        image: n\n        labels:\n          - "dashboard.port=9090"\n        restart: always\n', 'deeper indent|2': 'services:\n    web:\n        image: n\n        labels:\n            - "dashboard.port=1"\n          - "dashboard.icon=X"\n          - "dashboard.description=d"\n          - "dashboard.name=N"\n        restart: always\n', 'deeper indent|3': 'services:\n    web:\n        image: n\n        labels:\n          - "dashboard.port=1"\n          - "dashboard.scope=public"\n          - "dashboard.icon=i"\n        restart: always\n'}


def args(**kw):
    base = {"service": "web", "scope": None, "port": None, "icon": None, "desc": None, "name": None}
    return argparse.Namespace(**{**base, **kw})


class TestEditLabels(unittest.TestCase):
    def test_every_layout_and_edit_as_recorded(self):
        for text_name, text in TEXTS.items():
            for i, kw in enumerate(CASES):
                with self.subTest(f"{text_name}|{i}"):
                    self.assertEqual(scaffold.edit_labels(text, scaffold.label_updates(args(**kw))), EXPECTED[f"{text_name}|{i}"])

    def test_nothing_to_edit_and_unsafe_values_are_refused(self):
        with self.assertRaisesRegex(ValueError, "No edits specified"):
            scaffold.label_updates(args())
        for bad in ('quo"te', "back\\slash", "new\nline"):
            with self.subTest(bad), self.assertRaisesRegex(ValueError, "must not contain"):
                scaffold.label_updates(args(icon=bad))

    def test_scope_is_lowercased_and_port_is_text(self):
        self.assertEqual(scaffold.label_updates(args(scope="PUBLIC", port=8080)), {"dashboard.scope": "public", "dashboard.port": "8080"})

    def test_editing_twice_changes_nothing_more(self):
        once = scaffold.edit_labels(TEXTS["no labels"], {"dashboard.scope": "public"})
        self.assertEqual(scaffold.edit_labels(once, {"dashboard.scope": "public"}), once)


if __name__ == "__main__":
    unittest.main()
