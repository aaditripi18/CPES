from __future__ import annotations
import unittest
from datetime import datetime, timezone
from decimal import Decimal
from cpes.adapters import CanonicalEvent
from cpes.orchestration import CpesPipeline, EventFieldPresenceObservationGenerator, EventFieldPresenceRule, PipelineConfiguration
from cpes.scoring.models import EvidenceModel, EvidenceTerm
from cpes.windowing import SlidingWindowParameters

class PipelineTests(unittest.TestCase):
    def test_runs_c5_downstream_pipeline_and_retains_stage_artifacts(self) -> None:
        events = (
            CanonicalEvent("2026-07-20T00:00:00Z", "root-event", "1", "root", None, 1, "Medium", None, None, "root.exe", None),
            CanonicalEvent("2026-07-20T00:00:30Z", "child-event", "1", "child", "root", 2, "High", "cmd /c whoami", None, "child.exe", None),
        )
        configuration = PipelineConfiguration(SlidingWindowParameters(datetime(2026, 7, 20, tzinfo=timezone.utc), datetime(2026, 7, 20, 0, 2, tzinfo=timezone.utc), 120, 60), EvidenceModel(Decimal("0"), (EvidenceTerm("command", Decimal("2")),)), Decimal("1"), EventFieldPresenceObservationGenerator((EventFieldPresenceRule("command", "command_line"),)))
        result = CpesPipeline().run(events, configuration)
        self.assertEqual(len(result.canonical_events), 2)
        self.assertEqual(len(result.process_nodes), 2)
        self.assertEqual(len(result.lineage_chains), 1)
        self.assertEqual(len(result.lineage_contexts), 1)
        self.assertEqual(len(result.detection_windows), 1)
        self.assertTrue(result.threshold_decisions[0].is_detected)
        self.assertEqual(result.threshold_decisions[0].cpes_score_result.cpes_score, Decimal("2"))
