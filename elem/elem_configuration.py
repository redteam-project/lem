import os
import sys
import shutil
import ConfigParser

class ElemConfiguration(object):

    ELEM_CONF_ENV = 'ELEMCONFPATH'

    def __init__(self):
        if os.getenv(self.ELEM_CONF_ENV):
            self.path = os.getenv(self.ELEM_CONF_ENV)
        elif hasattr(sys, 'real_prefix'):
            self.path = os.path.join(sys.prefix, '.elem')
        else:
            self.path = os.path.join(os.path.expanduser("~"), '.elem')

        self.file = os.path.join(self.path, "elem.conf")

    def read_config(self):
        config = ConfigParser.ConfigParser()
        config.readfp(open(self.file))
        return config
            
