from distutils.core import setup
import setuptools
setup(name='elem',
      packages=['elem'],
      install_requires=['requests', 'GitPython', 'python-dateutil'],
      version='0.1.0',
      description='Tool to correlate published CVE\'s against Enterprise Linux against known exploits.',
      author='Kenneth Evensen',
      author_email='kevensen@redhat.com',
      license='GPLv3',
      url='https://github.com/fedoraredteam/elem',
      download_url='https://github.com/fedoraredteam/elem/archive/0.1.0.tar.gz',
      keywords=['cve', 'exploit', 'linux'],
      classifiers=[
            'Development Status :: 4 - Beta',
            'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
            'Programming Language :: Python :: 2.7',
      ],
      scripts=['bin/elem'],
      platforms=['Linux'])
