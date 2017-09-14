# Elem
Python Enterprise Linux Exploit Mapper
## Getting Started
There are a couple of ways to get started.  Clone the Repository or PIP.
### Clone the Repository
```
git clone https://github.com/fedoraredteam/elem
git submodule update --recursive
```
### Python PIP
```
pip install elem
```
## Help
### General
```terminal
usage: elem [-h] [--exploitdb EXPLOITDB] [--exploits EXPLOITS]
            {refresh,list,score,assess} ...

Cross Reference CVE's against a Exploit-DB entries for Enterprise Linux.

positional arguments:
  {refresh,list,score,assess}

optional arguments:
  -h, --help            show this help message and exit
  --exploitdb EXPLOITDB
                        Exploit DB directory to search
  --exploits EXPLOITS   Directory to store exploit data
```
### Refresh Local Information
```terminal
usage: elem refresh [-h] [--securityapi SECURITYAPI]

optional arguments:
  -h, --help            show this help message and exit
  --securityapi SECURITYAPI
                        Red Hat Security API base URL.
```
### List Curated Exploits
```terminal
usage: elem list [-h] [--edbid EDBID]

optional arguments:
  -h, --help     show this help message and exit
  --edbid EDBID  The edbid on which to filter.
```
### Score an Exploit
```terminal
usage: elem score [-h] --edbid EDBID --version VERSION [--kind {stride}]
                  --value VALUE

optional arguments:
  -h, --help         show this help message and exit
  --edbid EDBID      Which exploit to score
  --version VERSION
  --kind {stride}    Threat Score Kind
  --value VALUE      Threat Score
```
### Assess an Enterprise Linux Host for CVE's and Mapped Exploits
```terminal
usage: elem assess [-h]

optional arguments:
  -h, --help  show this help message and exit
```
