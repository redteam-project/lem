from distutils.core import setup
import setuptools
setup(name='elem',
      packages=['elem'],
      install_requires=['requests', 'GitPython', 'python-dateutil'],
      version='0.0.6',
      description='Tool to correlate published CVE\'s against Enterprise Linux against known exploits.',
      author='Kenneth Evensen',
      author_email='kevensen@redhat.com',
      license='GPLv3',
      url='https://github.com/fedoraredteam/elem',
      download_url='https://github.com/fedoraredteam/elem/archive/0.0.6.tar.gz',
      keywords=['cve', 'exploit', 'linux'],
      classifiers=[
            'Development Status :: 3 - Alpha',
            'License :: OSI Approved :: Apache Software License',
            'Programming Language :: Python :: 2.7',
      ],
      include_package_data=True,
      scripts=['bin/elem'],
      platforms=['Linux'])
