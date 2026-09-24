import unittest
from cpes.derivation.validation import validate_no_leakage
from cpes.derivation.models import FoldAssignment
class ValidationTests(unittest.TestCase):
 def test_rejects_duplicate_chain(self):
  with self.assertRaises(ValueError): validate_no_leakage((FoldAssignment('x',0),FoldAssignment('x',1)),2)
