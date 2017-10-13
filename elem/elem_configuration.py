import os
import shutil
import ConfigParser

class ElemConfiguration(object):

    ELEM_CONF_ENV = 'ELEMCONFPATH'

    def __init__(self):
        if not os.getenv(self.ELEM_CONF_ENV):
            self.path =os.path.join(os.path.expanduser("~"), '.elem')
        else:
            self.path = os.getenv(self.ELEM_CONF_ENV)

        self.file = os.path.join(self.path, "elem.conf")
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        source_conf_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'config', 'elem.conf')
        if not os.path.isfile(self.file):
            shutil.copyfile(source_conf_path, self.file)

    def read_config(self):
        config = ConfigParser.ConfigParser()
        config.readfp(open(self.file))
        return config
            
