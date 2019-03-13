import unittest
from lem.score import ScoreManager
from lem.score import InvalidExample

class TestScoreManager(unittest.TestCase):
    def setUp(self):
        self.stride_pattern = r'^(\d)(\d)(\d)(\d)(\d)(\d)$'
        self.skipped_pattern = r'^(19|20)(\d\d)[- /.](0[1-9]|1[012])[- /.](0[1-9]|[12][0-9]|3[01])$|^(19|20)(\d\d)(0[1-9]|1[012])(0[1-9]|[12][0-9]|3[01])$'
        self.manager = ScoreManager()

    def test_add(self):
        self.assertEqual(len(self.manager.scores), 0)
        self.manager.add_score('stride', self.stride_pattern)
        self.assertEqual(len(self.manager.scores), 1)
        self.assertIn('stride', self.manager.scores.keys())
        #Add again, ensure it doesn't grow and the patter doesn't change
        self.manager.add_score('stride', r'\d\d\d\d\d\d\d')
        self.assertEqual(len(self.manager.scores), 1)
        self.assertEqual(self.stride_pattern, self.manager.get_pattern('stride'))
        #Add new score
        self.manager.add_score('skipped', self.skipped_pattern)
        self.assertEqual(len(self.manager.scores), 2)
        self.assertIn('stride', self.manager.scores.keys())
        self.assertIn('skipped', self.manager.scores.keys())

    def test_delete_no_key(self):
        with self.assertRaises(KeyError):
            self.manager.delete_score('stride')

    def test_delete(self):
        self.manager.add_score('stride', self.stride_pattern)
        self.assertEqual(len(self.manager.scores), 1)
        self.manager.delete_score('stride')
        self.assertEqual(len(self.manager.scores), 0)

    def test_bad_example(self):
        with self.assertRaises(InvalidExample) as error:
            self.manager.add_score('badstride', self.stride_pattern, '1234568')
        self.assertEqual(str(error.exception), "For score badstride, example 1234568 does not match pattern ^(\\d)(\\d)(\\d)(\\d)(\\d)(\\d)$.")
