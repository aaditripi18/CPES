import unittest
from decimal import Decimal
from cpes.derivation.evidence import derive_evidence_model
from cpes.derivation.models import *
class EvidenceTests(unittest.TestCase):
 def test_requires_explicit_policy(self):
  with self.assertRaises(ValueError): derive_evidence_model((),0,None) # type: ignore[arg-type]
