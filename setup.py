from distutils.core import setup
from distutils.core import Command
import os
import sys
import setuptools
import unittest

class CleanPycCommand(Command):
    user_options = []

    def initialize_options(self):
        """Abstract method that is required to be overwritten"""
        pass

    def finalize_options(self):
        """Abstract method that is required to be overwritten"""
        pass

    def run(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        filenames = [os.path.join(d, x)
                     for d, _, files in os.walk(dir_path)
                     for x in files if os.path.splitext(x)[1] == '.pyc']
        for filename in filenames:
            os.remove(filename)

ELEM_CONF_ENV = 'ELEMCONFPATH'
if os.getenv(ELEM_CONF_ENV):
    path = os.getenv(ELEM_CONF_ENV)
elif hasattr(sys, 'real_prefix'):
    path = os.path.join(sys.prefix, '.elem')
else:
    path = os.path.join(os.path.expanduser("~"), '.elem')


setup(name='elem',
      packages=['elem', 'elem.core', 'elem.host', 'elem.score', 'elem.vulnerability', 'elem.exploit'],
      install_requires=['requests', 'python-dateutil'],
      data_files=[(path, ['elem/config/elem.conf'])],
      version='0.2.1',
      description='Tool to correlate published CVE\'s against Enterprise Linux against known exploits.',
      author='Kenneth Evensen',
      author_email='kevensen@redhat.com',
      license='GPLv3',
      url='https://github.com/fedoraredteam/elem',
      download_url='https://github.com/fedoraredteam/elem/archive/0.2.1.tar.gz',
      keywords=['cve', 'exploit', 'linux'],
      classifiers=[
            'Development Status :: 4 - Beta',
            'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
            'Programming Language :: Python :: 2.7',
      ],
      scripts=['bin/elem'],
      platforms=['Linux'],
      test_suite='tests',
      cmdclass={'tidy': CleanPycCommand})
