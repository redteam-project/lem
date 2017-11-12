import unittest
import os
import mock

from elem.host import YumAssessor


class TestYumAssessor(unittest.TestCase):

    def setUp(self):
        test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                           '..',
                                           'test_data',
                                           'assess',
                                           'cve_list.txt')
        with open(test_data_path, 'r') as cve_file:
            self.test_cves = cve_file.readlines()
        self.test_cves = [cve.replace('\n', '') for cve in self.test_cves]

        yum_output_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                           '..',
                                           'test_data',
                                           'assess',
                                           'yum_output.txt')
        with open(yum_output_path, 'r') as yum_file:
            self.yum_output = yum_file.read()

        yum_error_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                           '..',
                                           'test_data',
                                           'assess',
                                           'yum_errors.txt')
        with open(yum_error_path, 'r') as yum_file:
            self.yum_error = yum_file.read()
        
        self.yum_assessor = YumAssessor()

    @mock.patch('subprocess.Popen')
    def test_assess_good(self, mock_subproc_popen):
        process_mock = mock.Mock()
        attrs = {'communicate.return_value': (self.yum_output, self.yum_error), 'returncode': 0}
        process_mock.configure_mock(**attrs)
        mock_subproc_popen.return_value = process_mock
        self.yum_assessor.assess()
        for cve in self.test_cves:
            self.assertIn(cve, self.yum_assessor.cves)

        for cve in self.yum_assessor.cves:
            self.assertIn(cve, self.test_cves) 
        
    @mock.patch('subprocess.Popen')
    def test_assess_error(self, mock_subproc_popen):
        process_mock = mock.Mock()
        attrs = {'communicate.return_value': (self.yum_output, self.yum_error), 'returncode': 2}
        process_mock.configure_mock(**attrs)
        mock_subproc_popen.return_value = process_mock
        with self.assertRaises(OSError) as error:
            self.yum_assessor.assess()

    @mock.patch('subprocess.Popen')
    def test_assess_another_error(self, mock_subproc_popen):
        process_mock = mock.Mock()
        attrs = {'communicate.return_value': (self.yum_output, self.yum_error), 'returncode': 1}
        process_mock.configure_mock(**attrs)
        mock_subproc_popen.return_value = process_mock
        with self.assertRaises(OSError) as error:
            self.yum_assessor.assess()

