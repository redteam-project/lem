#!/usr/bin/python

import argparse
import sys
import subprocess
import re
import os

def get_edb_ids(edb_path, cve):
    ids = []
    pattern_string = '\s.*%s' % cve
    pattern = re.compile(pattern_string)
    for root, dirnames, filenames in os.walk(edb_path):
        for filename in filenames:
            file = open(os.path.join(root, filename), "r")
            content = file.read()
            match = pattern.search(content, re.MULTILINE)
            if match:
                ids.append(os.path.splitext(filename)[0])
    return ids


def get_cves():
    cves = []
    lines = subprocess.check_output(["yum","updateinfo","list","cves"]).split('\n')
    pattern = re.compile('\s(.*CVE-\d{4}-\d{4,})' )
    for line in lines:
        result = pattern.match(line)
        if result:
            cves.append(result.group(1))
    return list(set(cves))

def main():
    parser = argparse.ArgumentParser(description='Cross Reference CVE\'s against a Exploit-DB entries for Enterprise Linux.')
    parser.add_argument('--exploitdb',help='Exploit DB directory to search',required=True)
    args = parser.parse_args()

    cves = get_cves()
    ids = []
    for cve in cves:
        ids.extend(get_edb_ids(args.exploitdb, cve))

    for id in ids:
        print id

if __name__ == "__main__":
    main()
