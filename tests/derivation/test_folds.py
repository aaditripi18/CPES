import unittest
from cpes.derivation.folds import assign_folds
from cpes.derivation.models import (
 DerivationPolicy, DerivationRecord, EstimationPolicy, BinningPolicy, FoldPolicy, SelectionPolicy,
)
class FoldTests(unittest.TestCase):
 def test_is_deterministic(self):
  records=tuple(DerivationRecord(str(i),'attack',True,(),()) for i in range(4))
  selection=SelectionPolicy('selection-v1',('candidate',),((0,'candidate'),(1,'candidate')))
  policy=DerivationPolicy('signals-v1',FoldPolicy('folds-v1',7,2),EstimationPolicy('estimation-v1',0,0,0,0),BinningPolicy('bins-v1',1),selection,selection)
  assignments=assign_folds(records,policy)
  self.assertEqual(assignments,assign_folds(records,policy))
  self.assertTrue(all(item.metadata.signal_specification_version == 'signals-v1' for item in assignments))
