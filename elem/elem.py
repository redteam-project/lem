#!/usr/bin/python


from exploit_database import ExploitDatabase
from security_api import SecurityAPI
from curator import Curator


import sys
import subprocess
import re

class Elem(object):
    def __init__(self, args):
        self.args = args

    def run(self):

        if hasattr(self.args, 'refresh'):
            self.refresh(self.args)
        elif hasattr(self.args, 'list'):
            self.list_exploits(self.args)
        elif hasattr(self.args, 'update'):
            self.update_exploits(self.args)
        elif hasattr(self.args, 'assess'):
            self.assess(self.args)

    def refresh(self, args):
        exploitdb = ExploitDatabase(args.exploitdb)
        exploits = exploitdb.get_exploits_with_cves()

        securityapi = SecurityAPI(args.securityapi)
        cve_list = securityapi.cve_list

        curator = Curator()

        for cve in cve_list:
            sub_dict = { k: v for (k, v) in exploits.iteritems() if cve['name'] in exploits[k]['cves']}
            if len(sub_dict) > 0:
                curator.add_exploit(cve['name'], sub_dict)

        curator.write()

    def list_exploits(self, args):
        curator = Curator()
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

    def update_exploits(self, args):
        curator = Curator()
        curated_exploits = curator.cves_by_exploit_id(args.edbid)

        for cveid in curated_exploits.keys():
            curator.curated_exploits[cveid][str(args.edbid)]['confidence'] = args.confidence
            curator.curated_exploits[cveid][str(args.edbid)]['notes'] = args.notes

        curator.write()

    def assess(self, args):
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


        curator = Curator()
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
