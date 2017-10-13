import unittest
import os
from elem.core import CacheFile

class TestCacheFile(unittest.TestCase):

    def setUp(self):
        self.cache_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                       '..',
                                       'test_data',
                                       'cache')
        self.cache_file = 'test_cache.txt'
        self.full_path = os.path.join(self.cache_path, self.cache_file)
        with open(self.full_path, "w") as fileobj:
            fileobj.write("")

    def test_init(self):
        test_cache_file = CacheFile(self.cache_file, self.cache_path)
        self.assertEqual(self.full_path, test_cache_file.full_path)
        self.assertEqual(self.cache_file, test_cache_file.filename)
        self.assertEqual(self.cache_path, test_cache_file.cache_path)

    def test_init_two(self):
        test_cache_file = CacheFile(self.full_path)
        self.assertEqual(self.full_path, test_cache_file.full_path)
        self.assertEqual(self.cache_file, test_cache_file.filename)
        self.assertEqual(self.cache_path, test_cache_file.cache_path)

    def test_exists(self):
        test_cache_file = CacheFile(self.full_path)
        self.assertTrue(test_cache_file.exists())

    def test_delete(self):
        test_cache_file = CacheFile(self.full_path)
        self.assertTrue(test_cache_file.exists())
        test_cache_file.delete()
        self.assertFalse(test_cache_file.exists())

    def tearDown(self):
        if os.path.isfile(self.full_path):
            os.remove(self.full_path)
