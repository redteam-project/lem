# Elem
Python Enterprise Linux Exploit Mapper
## Background
The objective of the **elem** tool is to assist with assessments known exploits on an enterprise Linux host.  Initially the [STRIDE](https://msdn.microsoft.com/en-us/library/ee823878%28v=cs.20%29.aspx) threat scoring model will be used though this tool is designed to support additional models.
## Getting Started
There are a couple of ways to get started.  Clone the Repository or PIP.
### Clone the Repository
```
git clone --recursive https://github.com/fedoraredteam/elem
```
### Python PIP
```
pip install elem
```
### Virtualenv
You may find it useful to install and use **Virtualenv** to create an isolated Python environment for **elem**.
```terminal
sudo easy_install virtualenv
virtualenv elem
cd elem
source bin/activate
pip install elem
```
## General Usage
![General Usage](https://github.com/fedoraredteam/elem/blob/master/images/usage.png)
1. **Install** - Feel free to use the instructions above.
2. **Refresh** - Download content from **exploit-database** and **elem-curation**.
```
elem refresh
```
3. **Assess** - Under the hood, this invokes *yum updateinfo list cves*.  You do not have to be a privileged user to invoke this command.
```
elem assess
```
4. **Copy** - Copy an exploit to a destination directory and optionally **stage** the exploit if staging information is available.
```
elem copy --edbid 35370 --destination ~/ --stage
```
5. **Test** - Test the exploit on the target system.
6. **Score** - Score the exploit.  Right now only the **STRIDE** scoring schema is allowed.
```
elem score --edbid 35370 --cpe cpe:/o:redhat:enterprise_linux:7.0:ga:server --kind stride --value 000009
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
### Copy an Exploit to a Directory for Testing
```terminal
usage: elem copy [-h] [--destination DESTINATION] --edbid EDBID

optional arguments:
  -h, --help            show this help message and exit
  --destination DESTINATION
  --edbid EDBID         Which exploit to copy
```
### Path the System Against an Exploit
```terminal
usage: elem patch [-h] [--edbid EDBID]

optional arguments:
  -h, --help     show this help message and exit
  --edbid EDBID  The edbid to patch
```
