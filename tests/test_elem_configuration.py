import unittest
from elem import ElemConfiguration
import os

class TestElemConfiguration(unittest.TestCase):

    def setUp(self):
       os.environ["ELEMCONFPATH"] = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'test_config')
       self.config = ElemConfiguration()
        
    def test_get_config(self):
        self.assertEqual(os.getenv("ELEMCONFPATH"), self.config.path)

    def tearDown(self):
        os.remove(self.config.file)
        os.rmdir(self.config.path)

if __name__ == '__main__':
    unittest.main()