# Arch Linux Unit Tests

You can use a [Vagrant](https://www.vagrantup.com/intro/getting-started/) box to test lem on Arch Linux.

## Test environment setup

```
git clone https://github.com/redteam-project/lem
cd lem/tests/environments/arch
vagrant up
vagrant ssh
```

## Unit Tests

Now from the Arch VM you can run the unit tests.

```
[vagrant@archlinux ~]$ sudo pacman -Syu
[vagrant@archlinux ~]$ sudo pacman -S python2-virtualenv
[vagrant@archlinux ~]$ cd lem
[vagrant@archlinux lem]$ rm -Rf venv
[vagrant@archlinux lem]$ virtualenv2 venv
[vagrant@archlinux lem]$ source venv/bin/activate
(venv) [vagrant@archlinux lem]$ pip install -r tests/requirements.txt
(venv) [vagrant@archlinux lem]$ python setup.py test
```

## Functional Tests

If you want to execute the local version of lem, you can build it and pip install the local tgz. Follow the unit test instructions for setting up the virtualenv.

```
(venv) [vagrant@archlinux lem]$ python setup.py sdist
(venv) [vagrant@archlinux lem]$ pip install ./dist/lem-0.3.2.tar.gz
(venv) [vagrant@archlinux lem]$ sudo pacman -S git arch-audit
(venv) [vagrant@archlinux lem]$ git clone https://github.com/redteam-project/exploit-curation
(venv) [vagrant@archlinux lem]$ lem host assess --pacman --curation exploit-curation
```
