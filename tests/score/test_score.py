import unittest
import os
from elem.score import Score
from elem.score import InvalidExample

class TestStrideScore(unittest.TestCase):
    def setUp(self):
        self.pattern = '^(\d)(\d)(\d)(\d)(\d)(\d)$'
        self.stride = Score('stride', self.pattern)

    def test_name(self):
        self.assertEqual('stride', self.stride.name)

    def test_valid(self):
        self.assertTrue(self.stride.is_valid(123456))
        self.assertTrue(self.stride.is_valid("000000"))

    def test_invalid(self):
        self.assertFalse(self.stride.is_valid('1234567'))
        self.assertFalse(self.stride.is_valid('ABCDEF'))
        self.assertFalse(self.stride.is_valid(''))
        self.assertFalse(self.stride.is_valid('2017-10-27'))

    def test_example(self):
        with self.assertRaises(InvalidExample) as error:
            stride = Score('stride', self.pattern, '1234568')
        self.assertEqual(str(error.exception), "For score stride, example 1234568 does not match pattern ^(\\d)(\\d)(\\d)(\\d)(\\d)(\\d)$.")

class TestSkippedScore(unittest.TestCase):
    def setUp(self):
        self.pattern = '^(19|20)(\d\d)[- /.](0[1-9]|1[012])[- /.](0[1-9]|[12][0-9]|3[01])$|^(19|20)(\d\d)(0[1-9]|1[012])(0[1-9]|[12][0-9]|3[01])$'
        self.skipped = Score('skipped', self.pattern)

    def test_name(self):
        self.assertEqual('skipped', self.skipped.name)

    def test_valid(self):
        self.assertTrue(self.skipped.is_valid("2017-10-27"))
        self.assertTrue(self.skipped.is_valid("20171027"))

    def test_invalid(self):
        self.assertFalse(self.skipped.is_valid("2017-10-32"))
        self.assertFalse(self.skipped.is_valid('ABCDEF'))
        self.assertFalse(self.skipped.is_valid(''))
        