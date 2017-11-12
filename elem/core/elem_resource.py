import os
import json
from elem.core import CacheFile
from elem.core import open_from_file
from elem.core import open_from_url
from elem.core import open_from_directory
from elem.core import location_is_url

class ElemResource(object):

    def __init__(self, location, cachepath=None, tlsverify=True):

        self.location = location
        self.tlsverify = tlsverify
        self.token = 0

        if cachepath:
            self.cache_file = CacheFile(cachepath)
        else:
            self.cache_file = None

    def configure_cache(self, cachepath):
        self.cache_file = CacheFile(cachepath)

    def delete_cache(self):
        if self.cache_file:
            self.cache_file.delete()

    def cache_path(self):
        if self.cache_file:
            return self.cache_file.full_path
        return ''

    def update(self):
        if self.cache_file:
            self.cache_file.delete()

        data = None
        if location_is_url(self.location):
            data = open_from_url(self.location, self.tlsverify)
        elif os.path.isdir(self.location):
            data = open_from_directory(self.location)
        else:
            data = open_from_file(self.location)

        if self.cache_file and location_is_url(self.location):
            self.cache_file.write_data(data)
        return data

    def read(self):
        data = None
        if self.cache_file and self.cache_file.exists():
            data = self.cache_file.read_data()
        else:
            data = self.update()

        if isinstance(data, str):
            try:
                return json.loads(data)
            except ValueError:
                pass
        return data

    def location_is_url(self):
        return location_is_url(self.location)
