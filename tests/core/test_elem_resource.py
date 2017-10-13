import unittest
import os
import json
import gzip
import StringIO
import mock
from elem.core import ElemResource
from elem.core import decode_compressed_content

class TestResource(unittest.TestCase):

    def setUp(self):
        self.test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                           '..',
                                           'test_data')
    def test_is_not_url(self):
        file_resource = os.path.join(self.test_data_path, 'nvdcve-1.0-2016.json.gz')
        resource = ElemResource(file_resource)
        self.assertFalse(resource.location_is_url())

    def test_is_url(self):
        url_resource = 'https://access.redhat.com/labs/securitydataapi/cves.json'
        resource = ElemResource(url_resource)
        self.assertTrue(resource.location_is_url())

        update_url = 'https://access.redhat.com/labs/securitydataapi/cves.json?after=2017-10-17'
        resource = ElemResource(update_url)
        self.assertTrue(resource.location_is_url())
        
        test_archive = 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2016.json.gz'
        resource = ElemResource(test_archive)
        self.assertTrue(resource.location_is_url())

    def test_decode_compressed_content(self):
        fgz = StringIO.StringIO()
        gzip_obj = gzip.GzipFile(filename='test.gz', mode='wb', fileobj=fgz)
        gzip_obj.write("Test String")
        gzip_obj.close()
        data = decode_compressed_content(fgz.getvalue())
        self.assertEqual("Test String", data)

    def test_open_text_from_compressed_file(self):
        file_resource = os.path.join(self.test_data_path, 'simple.txt.gz')
        resource = ElemResource(file_resource)
        data = resource.read()
        self.assertEqual("This is a simple test.\n", data)
    
    def test_open_text_from_file(self):
        file_resource = os.path.join(self.test_data_path, 'simple.txt')
        resource = ElemResource(file_resource)
        data = resource.read()
        self.assertEqual("This is a simple test.\n", data)

    def test_open_json_from_compressed_file(self):
        file_resource = os.path.join(self.test_data_path, 'simple.json.gz')
        resource = ElemResource(file_resource)
        data = resource.read()
        self.assertEqual(json.loads("{ \"name\":\"John\", \"age\":31, \"city\":\"New York\" }"), data)

    def test_open_json_from_file(self):
        file_resource = os.path.join(self.test_data_path, 'simple.json')
        resource = ElemResource(file_resource)
        data = resource.read()
        self.assertEqual(json.loads("{ \"name\":\"John\", \"age\":31, \"city\":\"New York\" }"), data)


    @mock.patch('requests.get')
    def test_text_from_url(self, mock_url_call):
        mock_url_call.return_value = mock.MagicMock(status_code=200, 
                                                    headers={'content-type':"text/plain"},
                                                    content="Hello World")
        
        resource = ElemResource("http://simple.com")
        data = resource.read()
        self.assertEqual("Hello World", data)

    @mock.patch('requests.get')
    def test_json_from_url(self, mock_url_call):
        mock_url_call.return_value = mock.MagicMock(status_code=200,
                                                    headers={'content-type':"application/json"},
                                                    content="{ \"name\":\"John\", \"age\":31, \"city\":\"New York\" }")
        
        resource = ElemResource("http://simple.com")
        data = resource.read()
        self.assertEqual(json.loads("{ \"name\":\"John\", \"age\":31, \"city\":\"New York\" }"), data)


    @mock.patch('elem.core.util.decode_compressed_content')
    @mock.patch('requests.get')
    def test_compressed_text_from_url(self, mock_url_call, mock_gzip_read):
        mock_gzip_read.return_value = "Hello World"
        mock_url_call.return_value = mock.MagicMock(status_code=200,
                                                    headers={'content-type':"application/x-gzip"})
        resource = ElemResource("http://simple.com")
        data = resource.read()
        self.assertEqual("Hello World", data)

    @mock.patch('elem.core.util.decode_compressed_content')
    @mock.patch('requests.get')
    def test_compressed_json_from_url(self, mock_url_call, mock_gzip_read):
        mock_gzip_read.return_value = "{ \"name\":\"John\", \"age\":31, \"city\":\"New York\" }"
        mock_url_call.return_value = mock.MagicMock(status_code=200,
                                                    headers={'content-type':"application/x-gzip"})
        resource = ElemResource("http://simple.com")
        data = resource.read()
        self.assertEqual(json.loads("{ \"name\":\"John\", \"age\":31, \"city\":\"New York\" }"), data)

    def test_open_from_directory(self):
        test_data = ['files.csv', 
                     'platforms/linux/local/one_cve.py', 
                     'platforms/linux/remote/invalid_cve.py', 
                     'platforms/linux/remote/no_cve.php', 
                     'platforms/linux/remote/two_different_cves.txt', 
                     'platforms/linux/remote/two_different_one_same_cve.txt', 
                     'platforms/linux/remote/two_same_cves.c']
        resource = ElemResource(os.path.join(self.test_data_path, 'exploit-source'))

        data = resource.read()
        common_prefix = os.path.commonprefix(data)
        self.assertTrue(isinstance(data,list))
        for filename in data:
            self.assertIn(filename.replace(common_prefix,''), test_data)


