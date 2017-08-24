# PyElem
Python Enterprise Linux Exploit Mapper

```terminal

usage: elem.py [-h] {refresh,list,update} ...

Cross Reference CVE's against a Exploit-DB entries for Enterprise Linux.

positional arguments:
  {refresh,list,update}

optional arguments:
  -h, --help            show this help message and exit
```
## Refresh Local Information
```terminal
usage: elem.py refresh [-h] [--exploitdb EXPLOITDB]
                       [--securityapi SECURITYAPI] [--curatorfile CURATORFILE]

optional arguments:
  -h, --help            show this help message and exit
  --exploitdb EXPLOITDB
                        Exploit DB directory to search (default: exploit-
                        database)
  --securityapi SECURITYAPI
                        Red Hat Security API base URL. (default:
                        https://access.redhat.com/labs/securitydataapi)
  --curatorfile CURATORFILE
                        Path to curation file (default: curator.json)
```
## List Curated Exploits
```terminal
usage: elem.py list [-h] [--confidence {high,unknown,none,some,all}]
                    [--curatorfile CURATORFILE] [--csv [CSV]]

optional arguments:
  -h, --help            show this help message and exit
  --confidence {high,unknown,none,some,all}
                        List exploit values by confidence (default: all)
  --curatorfile CURATORFILE
                        Path to curation file (default: curator.json)
  --csv [CSV]
```
## Update the Confidence Level of an Exploit
```terminal
usage: elem.py update [-h] --confidence {high,unknown,none,some,all}
                      [--curatorfile CURATORFILE] --edbid EDBID

optional arguments:
  -h, --help            show this help message and exit
  --confidence {high,unknown,none,some,all}
                        Set the confidence level in the exploit (default:
                        None)
  --curatorfile CURATORFILE
                        Path to curation file (default: curator.json)
  --edbid EDBID         Which exploit to update (default: None)
```
