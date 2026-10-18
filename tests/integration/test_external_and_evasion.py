"""External data manifest, the pre-registered category table, and the evasion gate."""

from __future__ import annotations

import unittest

from evaluation import data, external


@unittest.skipUnless(external.SAMPLES.exists(), "external samples not fetched")
class ExternalDatasetTests(unittest.TestCase):
    def test_downloaded_files_match_the_pinned_manifest(self) -> None:
        self.assertEqual(len(external.verify_manifest()), 66)

    def test_every_sysmon_sample_has_a_pre_registered_category(self) -> None:
        from evaluation import evtx_source

        for path in sorted(external.SAMPLES.glob("*.evtx")):
            has_sysmon = bool(evtx_source.sysmon_records(path))
            self.assertIn(external.category(path.name, has_sysmon), external.CATEGORY_ORDER)


@unittest.skipUnless(data.CORPUS.exists() and data.LABELS.exists(), "private lab corpus not present")
class EvasionGateTests(unittest.TestCase):
    def test_research_signal_replication_equals_the_labelled_table(self) -> None:
        from evaluation import research_signals

        flags = research_signals.signal_flags(data.documents())
        self.assertEqual({u.guid: u.research_signals for u in data.units()}, {u.guid: tuple(flags.get(u.guid, ())) for u in data.units()})


if __name__ == "__main__":
    unittest.main()
