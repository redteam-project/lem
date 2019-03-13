import os
import sys
import shutil
import ConfigParser

class LemConfiguration(object):

    LEM_CONF_ENV = 'LEMCONFPATH'

    def __init__(self):
        if os.getenv(self.LEM_CONF_ENV):
            self.path = os.getenv(self.LEM_CONF_ENV)
        elif hasattr(sys, 'real_prefix'):
            self.path = os.path.join(sys.prefix, '.lem')
        else:
            self.path = os.path.join(os.path.expanduser("~"), '.lem')

        # In Python 2.6, the virtualenv cache is funky.
        if not os.path.isdir(self.path):
            os.makedirs(self.path)

        self.file = os.path.join(self.path, "lem.conf")

        dir_path = os.path.dirname(os.path.realpath(__file__))
        source_config = os.path.join(dir_path, 'config', 'lem.conf')
        if not os.path.isfile(self.file):
            print "{0} doesn't exist".format(self.file)
            shutil.copy(source_config, self.file)
        #End workaround for funky

    def read_config(self):
        config = ConfigParser.ConfigParser()
        config.readfp(open(self.file))
        return config
