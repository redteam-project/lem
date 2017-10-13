import os
from elem.core import open_from_file
from elem.core import write_to_file

class CacheFile(object):
    def __init__(self, filename, cache_path=None):
        if cache_path:
            self.cache_path = cache_path
            self.filename = filename
            self.full_path = os.path.join(cache_path, filename)
        else:
            self.cache_path, self.filename = os.path.split(filename)
            self.full_path = filename
        
        if not os.path.isdir(self.cache_path):
            os.makedirs(self.cache_path)

    def exists(self):
        return os.path.isfile(self.full_path)

    def delete(self):
        if self.exists():
            os.remove(self.full_path)

    def read_data(self):
        file_content = open_from_file(self.full_path).decode('string-escape').strip('"')
        return file_content

    def write_data(self, content):
        write_to_file(self.full_path, content)
