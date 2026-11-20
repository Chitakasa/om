"""svclabels.service_labels: compose labels as a dict, from the mapping form, the list form or nothing."""
import unittest

import _env  # noqa: F401

from gitops import network, policy
from gitops.svclabels import service_labels


class TestServiceLabels(unittest.TestCase):
    def test_both_forms_and_nothing(self):
        self.assertEqual(service_labels({"labels": {"a": "b"}}), {"a": "b"})
        self.assertEqual(service_labels({"labels": ["a=b", "c=d=e", "bare"]}), {"a": "b", "c": "d=e", "bare": ""})
        for empty in (None, {}, {"labels": None}, {"labels": []}, {"image": "x"}):
            self.assertEqual(service_labels(empty), {})

    def test_the_names_other_modules_use_are_the_same_function(self):
        self.assertIs(policy._labels, service_labels)
        self.assertEqual(network.shares_workspace_network({"services": {"a": {"labels": ["om.network=shared"]}}}), True)
        self.assertEqual(network.shares_workspace_network({"services": {"a": {"labels": {"om.network": "private"}}}}), False)


if __name__ == "__main__":
    unittest.main()
