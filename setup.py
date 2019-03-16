from distutils.core import setup
from distutils.core import Command
import os
import sys
import unittest
import setuptools


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


LEM_CONF_ENV = 'LEMCONFPATH'
if os.getenv(LEM_CONF_ENV):
    path = os.getenv(LEM_CONF_ENV)
elif hasattr(sys, 'real_prefix'):
    path = os.path.join(sys.prefix, '.lem')
else:
    path = os.path.join(os.path.expanduser("~"), '.lem')


setup(name='lem',
      packages=['lem', 'lem.host', 'lem.score', 'lem.vulnerability', 'lem.exploit'],
      package_data={'lem': ['config/lem.conf']},
      install_requires=['requests', 'python-dateutil', 'argparse', 'cpe', 'redteamcore'],
      data_files=[(path, ['lem/config/lem.conf'])],
      version='0.3.1',
      description='Linux Exploit Mapper correlates CVEs local to a Linux system with known exploits',
      author='Kenneth Evensen',
      author_email='kdevensen@google.com',
      license='GPLv3',
      url='https://github.com/redteam-project/lem',
      download_url='https://github.com/redteam-project/lem/archive/0.3.1.tar.gz',
      keywords=['cve', 'exploit', 'linux'],
      classifiers=[
          'Development Status :: 4 - Beta',
          'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
          'Programming Language :: Python :: 2.7',
      ],
      scripts=['bin/lem'],
      platforms=['Linux'],
      test_suite='tests',
      cmdclass={'tidy': CleanPycCommand})
