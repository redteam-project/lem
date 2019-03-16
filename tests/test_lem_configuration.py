import unittest
import os
from lem import LemConfiguration


class TestLemConfiguration(unittest.TestCase):

    def setUp(self):
        os.environ["LEMCONFPATH"] = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'test_config')
        self.config = LemConfiguration()

    def test_get_config(self):
        self.assertEqual(os.getenv("LEMCONFPATH"), self.config.path)

    def tearDown(self):
        os.remove(self.config.file)
        os.rmdir(self.config.path)


if __name__ == '__main__':
    unittest.main()
