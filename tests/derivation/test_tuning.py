import unittest
from cpes.derivation.tuning import derive_selected_parameter
from cpes.derivation.models import SelectionPolicy
class TuningTests(unittest.TestCase):
 def test_requires_explicit_selection(self):
  with self.assertRaises(ValueError): derive_selected_parameter(0,SelectionPolicy('v',('a',),()))
