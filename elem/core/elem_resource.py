import os
import json
from elem.core import ElemResourceCache
from elem.core import ElemResourceConnectorFactory

class ElemResource(object):

    def __init__(self, location, cache_location=None, tlsverify=True):

        self.location = location
        connector_args = {'tlsverify': tlsverify}

        self.connector = ElemResourceConnectorFactory.create_connector(location, **connector_args)

        if cache_location:
            self.cache = ElemResourceCache(cache_location)
        else:
            self.cache = None

    def configure_cache(self, cachepath):
        self.cache = ElemResourceCache(cachepath)

    def delete_cache(self):
        if self.cache:
            self.cache.delete()

    def cache_path(self):
        if self.cache:
            return self.cache.location
        return ''

    def update(self):
        if self.cache:
            self.cache.delete()

        data = self.connector.open()

        if self.cache:
            self.cache.write(data)
        return data

    def read(self):
        data = None
        if self.cache and self.cache.exists():
            data = self.cache.read_data()
        else:
            data = self.update()

        if isinstance(data, str):
            try:
                return json.loads(data)
            except ValueError:
                pass
        return data
