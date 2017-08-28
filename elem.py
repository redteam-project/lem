#!/usr/bin/python

from datetime import timedelta, datetime
import argparse
import os
import re
import requests
import json
import dateutil.parser
import sys
import subprocess

class ExploitDatabase(object):
    def __init__(self, edb_path='exploit-database'):
        self.edb_path = edb_path

    def get_exploits_with_cves(self):
        exploits = {}
        pattern_string = 'CVE-\d{4}-\d{1,7}'
        pattern = re.compile(pattern_string)
        for root, dirnames, filenames in os.walk(self.edb_path):
            for filename in filenames:
                edb_file = open(os.path.join(root, filename), "r")
                content = edb_file.read()
                matches = pattern.findall(content, re.MULTILINE)
                edbid = os.path.splitext(filename)[0]
                if len(matches) > 0:
                    exploits[edbid] = dict(filename=edb_file.name,
                                           cves=list(set(matches)))
        return {edbid: exploit for (edbid, exploit) in exploits.iteritems() if 'windows' not in exploits[edbid]['filename']}

class SecurityAPI(object):
    def __init__(self, baseurl, cve_path='cves'):
        self.baseurl = baseurl
        self.cve_path = cve_path
        self.cve_list = []
        if not os.path.isdir(self.cve_path):
            os.mkdir(self.cve_path)

        self.load_cves()
        since_date = self.get_recent_cve_date()
        yesterday = datetime.now().replace(hour=00,
                                           minute=00,
                                           second=00,
                                           microsecond=00) - timedelta(1)
        # If our existing CVE data is older than yesterday, get new data
        if since_date != yesterday:
            self.cvedata = self.get_data('cve.json',
                                         ['per_page=50000',
                                          'after=' + str(since_date)])

            for cve in self.cvedata:
                cve = self.get_data('cve/' + cve['CVE'] + '.json')
                self.write_cve(cve)
                self.cve_list.append(cve)

    def get_data(self, query_type, params=[]):
        url = self.baseurl + '/' + query_type
        if len(params) > 0:
            url += '?'
            for param in params:
                url += param
                url += '&'
        r = requests.get(url)

        if r.status_code != 200:
            print('ERROR: Invalid request; returned {} for the following '
                  'query:\n{}'.format(r.status_code, url))
            sys.exit(1)

        if not r.json():
            print('No data returned with the following query:')
            print(url)
            sys.exit(0)

        return r.json()

    def write_cve(self, cve_json):

        cve_file_name = self.cve_path + '/' + cve_json['name'] + '.json'
        with open(cve_file_name, 'w') as cve_file:
            json.dump(cve_json, cve_file)

    def load_cves(self):

        cve_file_name_list = [f for f in os.listdir(self.cve_path) if os.path.isfile(os.path.join(self.cve_path, f))]
        for cve_file_name in cve_file_name_list:
            with open(self.cve_path + '/' + cve_file_name, 'r') as cve_file:
                self.cve_list.append(json.load(cve_file))

    def get_recent_cve_date(self):
        recent_date = dateutil.parser.parse('2010-11-10T00:00:00')
        for cve in self.cve_list:
            new_date = dateutil.parser.parse(cve['public_date'])
            if new_date > recent_date:
                recent_date = new_date
        return recent_date

class Curator(object):
    def __init__(self, curator_file_name="curator.json"):
        self.curator_file_name = curator_file_name
        self.curated_exploits = {}
        with open(self.curator_file_name, 'r') as curator_file:
            self.curated_exploits = json.load(curator_file)

    def add_exploit(self, cve_id, exploit_entries):
        if cve_id not in self.curated_exploits.keys():
            self.curated_exploits[cve_id] = {}

        for edb_id in exploit_entries.keys():
            if edb_id not in self.curated_exploits[cve_id].keys():
                self.curated_exploits[cve_id][edb_id] = \
                    dict(filename=exploit_entries[edb_id]['filename'],
                         confidence='unknown',
                         notes='empty')

    def write(self):
        with open(self.curator_file_name, 'w') as curator_file:
            self.curated_exploits = json.dump(self.curated_exploits,
                                              curator_file)

    def cves_by_exploit_id(self, edbid_to_find):
        pruned_list = \
            {cveid:
            {edbid: exploit for edbid, exploit in exploit_entries.iteritems()
                if edbid_to_find == int(edbid)}
                for cveid, exploit_entries in self.curated_exploits.iteritems()}

        final_list = \
            {cveid: exploits for cveid, exploits in pruned_list.iteritems()
            if len(exploits) > 0}
            
        if not final_list:
            print "EDB ID %s not among curated exploits. No action taken" \
                  % edbid_to_find

        return final_list

def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def refresh(args):
    exploitdb = ExploitDatabase(args.exploitdb)
    exploits = exploitdb.get_exploits_with_cves()

    securityapi = SecurityAPI(args.securityapi)
    cve_list = securityapi.cve_list

    curator = Curator(args.curatorfile)

    for cve in cve_list:
        sub_dict = { k: v for (k, v) in exploits.iteritems() if cve['name'] in exploits[k]['cves']}
        if len(sub_dict) > 0:
            curator.add_exploit(cve['name'], sub_dict)

    curator.write()

def list_exploits(args):
    curator = Curator(args.curatorfile)
    curated_exploits = curator.curated_exploits
    pruned_list = {}

    if 'all' not in args.confidence:
        pruned_list = {cveid: {edbid: exploit for edbid, exploit in exploit_entries.iteritems() if args.confidence in exploit['confidence']} for cveid, exploit_entries in curated_exploits.iteritems()}
    else:
        pruned_list = curated_exploits

    smaller_list = {cveid: exploits for cveid, exploits in pruned_list.iteritems() if len(exploits) > 0}
    if args.csv:
        print 'CVE,EDB ID,Confidence,Path to File'
        for cveid in smaller_list.keys():
            for edbid in smaller_list[cveid].keys():
                print cveid + "," + \
                      edbid + "," + \
                      smaller_list[cveid][edbid]['confidence'] + "," + \
                      smaller_list[cveid][edbid]['notes'] + "," + \
                      smaller_list[cveid][edbid]['filename']
    else:
        print smaller_list

def update_exploits(args):
    curator = Curator(args.curatorfile)
    curated_exploits = curator.cves_by_exploit_id(args.edbid)

    for cveid in curated_exploits.keys():
        curator.curated_exploits[cveid][str(args.edbid)]['confidence'] = args.confidence
        curator.curated_exploits[cveid][str(args.edbid)]['notes'] = args.notes

    curator.write()

def assess(args):
    cves = []
    try:
        lines = subprocess.check_output(["yum","updateinfo","list","cves"]).split('\n')
    except OSError:
        print "\'assess\' may only be run on an Enterprise Linux host."
        sys.exit(1)
    pattern = re.compile('\s(.*CVE-\d{4}-\d{4,})' )
    for line in lines:
        result = re.findall(pattern, line)
        if result and result[0] not in cves:
            cves.append(result[0])


    curator = Curator(args.curatorfile)
    for cveid in cves:
        try:
            if args.csv:
                for edbid in curator.curated_exploits[cveid].keys():
                    print cveid + "," + \
                          edbid + "," + \
                          curator.curated_exploits[cveid][edbid]['confidence'] + "," + \
                          curator.curated_exploits[cveid][edbid]['filename']
            else:
                print curator.curated_exploits[cveid]
        except KeyError:
            pass

def main():

    parser = argparse.ArgumentParser(description='Cross Reference CVE\'s against a Exploit-DB entries for Enterprise Linux.')

    subparsers = parser.add_subparsers()
    refresh_parser = subparsers.add_parser('refresh',
                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    refresh_parser.add_argument('--refresh',
                        required=False,
                        type=str2bool,
                        nargs='?',
                        const=True,
                        default='t',
                        help=argparse.SUPPRESS)
    refresh_parser.add_argument('--exploitdb',
                        help='Exploit DB directory to search',
                        default='exploit-database',
                        required=False)
    refresh_parser.add_argument('--securityapi',
                        help='Red Hat Security API base URL.',
                        required=False,
                        default='https://access.redhat.com/labs/securitydataapi')
    refresh_parser.add_argument('--curatorfile',
                        help='Path to curation file',
                        required=False,
                        default='curator.json')

    list_parser = subparsers.add_parser('list',
                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    list_parser.add_argument('--list',
                        required=False,
                        type=str2bool,
                        nargs='?',
                        const=True,
                        default='t',
                        help=argparse.SUPPRESS)

    list_parser.add_argument('--confidence',
                        help='List exploit values by confidence',
                        required=False,
                        choices=set(('unknown', 'none', 'some', 'high', 'all')),
                        default='all')
    list_parser.add_argument('--curatorfile',
                        help='Path to curation file',
                        required=False,
                        default='curator.json')
    list_parser.add_argument('--csv',
                        required=False,
                        type=str2bool,
                        nargs='?',
                        const=True,
                        default='f')

    update_parser = subparsers.add_parser('update',
                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    update_parser.add_argument('--update',
                        required=False,
                        type=str2bool,
                        nargs='?',
                        const=True,
                        default='t',
                        help=argparse.SUPPRESS)
    update_parser.add_argument('--confidence',
                        help='Set the confidence level in the exploit',
                        required=True,
                        choices=set(('unknown', 'none', 'some', 'high', 'all')))
    update_parser.add_argument('--notes',
                        help='Add an note',
                        required=False)
    update_parser.add_argument('--curatorfile',
                        help='Path to curation file',
                        required=False,
                        default='curator.json')
    update_parser.add_argument('--edbid',
                        help='Which exploit to update',
                        required=True,
                        type=int)

    assess_parser = subparsers.add_parser('assess',
                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    assess_parser.add_argument('--assess',
                        required=False,
                        type=str2bool,
                        nargs='?',
                        const=True,
                        default='t',
                        help=argparse.SUPPRESS)
    assess_parser.add_argument('--curatorfile',
                        help='Path to curation file',
                        required=False,
                        default='curator.json')
    assess_parser.add_argument('--csv',
                        required=False,
                        type=str2bool,
                        nargs='?',
                        const=True,
                        default='f')


    args = parser.parse_args()

    try:
        if args.refresh:
            refresh(args)
    except AttributeError:
        pass

    try:
        if args.list:
            list_exploits(args)
    except AttributeError:
        pass

    try:
        if args.update:
            update_exploits(args)
    except AttributeError:
        pass

    try:
        if args.assess:
            assess(args)
    except AttributeError:
        pass

if __name__ == "__main__":
    main()
