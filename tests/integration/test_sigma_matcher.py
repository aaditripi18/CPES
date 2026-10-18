"""The evaluation's Sigma matcher must follow Sigma semantics exactly."""

from __future__ import annotations

import unittest

from evaluation.sigma import Unsupported, compile_rule


def rule(detection: dict, category: str = "process_creation", **extra) -> object:
    return compile_rule({"title": "t", "id": "x", "level": "high", "logsource": {"product": "windows", "category": category}, "detection": detection, **extra})


class SigmaMatcherTests(unittest.TestCase):
    def test_default_is_case_insensitive_wildcard_equality(self) -> None:
        r = rule({"selection": {"Image": "*\\FodHelper.exe"}, "condition": "selection"})
        self.assertTrue(r.match({"Image": "C:\\Windows\\System32\\fodhelper.EXE"}))
        self.assertFalse(r.match({"Image": "C:\\x\\fodhelper.exe.bak"}))
        self.assertFalse(r.match({}))

    def test_modifiers_and_lists(self) -> None:
        r = rule({"sel": {"CommandLine|contains|all": ["-enc", "bypass"], "Image|endswith": ["\\cmd.exe", "\\powershell.exe"]}, "condition": "sel"})
        self.assertTrue(r.match({"CommandLine": "x -ENC y BYPASS", "Image": "c:\\a\\powershell.exe"}))
        self.assertFalse(r.match({"CommandLine": "x -enc y", "Image": "c:\\a\\powershell.exe"}))
        self.assertTrue(rule({"s": {"CommandLine|windash|contains": " -decode "}, "condition": "s"}).match({"CommandLine": "certutil /decode a b"}))
        self.assertTrue(rule({"s": {"Image|re": r"\\[a-z]{3}\.exe$"}, "condition": "s"}).match({"Image": "c:\\abc.exe"}))
        self.assertFalse(rule({"s": {"Image|re": r"\\[a-z]{3}\.exe$"}, "condition": "s"}).match({"Image": "c:\\ABC.exe"}))  # regex is case-sensitive
        self.assertTrue(rule({"s": {"Image|re|i": r"\\[a-z]{3}\.exe$"}, "condition": "s"}).match({"Image": "c:\\ABC.exe"}))

    def test_null_and_exists(self) -> None:
        self.assertTrue(rule({"s": {"ParentImage": None}, "condition": "s"}).match({"Image": "a"}))
        self.assertTrue(rule({"s": {"Hashes|exists": True}, "condition": "s"}).match({"Hashes": "SHA256=1"}))
        self.assertFalse(rule({"s": {"Hashes|exists": True}, "condition": "s"}).match({}))

    def test_condition_grammar(self) -> None:
        detection = {
            "selection_img": {"Image|endswith": "\\sdclt.exe"},
            "selection_cli": {"CommandLine|contains": "/kickoffelev"},
            "filter_main": {"ParentImage|endswith": "\\explorer.exe"},
            "condition": "all of selection_* and not 1 of filter_*",
        }
        r = rule(detection)
        self.assertTrue(r.match({"Image": "c:\\sdclt.exe", "CommandLine": "sdclt /KickOffElev", "ParentImage": "c:\\cmd.exe"}))
        self.assertFalse(r.match({"Image": "c:\\sdclt.exe", "CommandLine": "sdclt /KickOffElev", "ParentImage": "c:\\explorer.exe"}))
        self.assertTrue(rule({"a": {"Image": "x"}, "b": {"Image": "y"}, "condition": "1 of them"}).match({"Image": "y"}))
        self.assertTrue(rule({"a": {"Image": "x"}, "b": {"User": "u"}, "condition": "(a or b) and not a"}).match({"Image": "z", "User": "U"}))

    def test_list_of_maps_is_or(self) -> None:
        r = rule({"s": [{"Image|endswith": "\\a.exe"}, {"OriginalFileName": "b.exe"}], "condition": "s"})
        self.assertTrue(r.match({"OriginalFileName": "B.EXE"}))

    def test_unsupported_features_are_refused(self) -> None:
        for detection in (
            {"s": {"CommandLine|base64offset|contains": "x"}, "condition": "s"},
            {"s": {"Image": "x"}, "condition": "s | count() > 5"},
            {"s": ["keyword"], "condition": "s"},
        ):
            with self.assertRaises(Unsupported):
                rule(detection)
        with self.assertRaises(Unsupported):
            compile_rule({"logsource": {"product": "windows", "service": "security"}, "detection": {"s": {"EventID": 1}, "condition": "s"}})


if __name__ == "__main__":
    unittest.main()
