import unittest
import os
from elem.core import ElemResourceCache

class TestCacheFile(unittest.TestCase):

    def setUp(self):
        self.cache_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                       '..',
                                       'test_data',
                                       'cache')
        self.cache_file = 'test_cache.txt'
        self.location = os.path.join(self.cache_path, self.cache_file)
        with open(self.location, "w") as fileobj:
            fileobj.write("")

    def test_init(self):
        test_cache_file = ElemResourceCache(self.location)
        self.assertEqual(self.location, test_cache_file.location)
        self.assertEqual(self.cache_file, test_cache_file.filename)
        self.assertEqual(self.cache_path, test_cache_file.cache_path)

    def test_init_two(self):
        test_cache_file = ElemResourceCache(self.location)
        self.assertEqual(self.location, test_cache_file.location)
        self.assertEqual(self.cache_file, test_cache_file.filename)
        self.assertEqual(self.cache_path, test_cache_file.cache_path)

    def test_exists(self):
        test_cache_file = ElemResourceCache(self.location)
        self.assertTrue(test_cache_file.exists())

    def test_delete(self):
        test_cache_file = ElemResourceCache(self.location)
        self.assertTrue(test_cache_file.exists())
        test_cache_file.delete()
        self.assertFalse(test_cache_file.exists())

    def tearDown(self):
        if os.path.isfile(self.location):
            os.remove(self.location)
