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
            self.refresh(self.args.securityapi)
        elif hasattr(self.args, 'list'):
            self.list_exploits(self.args.confidence,
                               self.args.csv,
                               self.args.edbid)
        elif hasattr(self.args, 'update'):
            self.update_exploits(self.args)
        elif hasattr(self.args, 'assess'):
            self.assess(self.args)

    def refresh(self, security_api_url):
        exploitdb = ExploitDatabase()
        exploits = exploitdb.get_exploits_with_cves()

        securityapi = SecurityAPI(security_api_url)
        cve_list = securityapi.cve_list

        if securityapi.new_cves:
            curator = Curator()

            for cve in cve_list:
                sub_dict = dict((k, v) for (k, v) in exploits.iteritems() if cve['name'] in exploits[k]['cves'])
                if len(sub_dict) > 0:
                    curator.add_exploit(cve['name'], sub_dict)
            print "Adding new CVE's to curation file."
            curator.write()

    def list_exploits(self, confidence='all', csv=False, edbid=None):
        curator = Curator()
        curated_exploits = {}
        if edbid:
            curated_exploits = curator.cves_by_exploit_id(edbid)
        else:
            curated_exploits = curator.curated_exploits
        pruned_list = {}

        if 'all' not in confidence:
            pruned_list = dict((cveid, dict((edbid, exploit) for edbid, exploit in entries.iteritems() if confidence in exploit['confidence'])) for cveid, entries in curated_exploits.iteritems())
        else:
            pruned_list = curated_exploits


        if csv:
            print 'CVE,EDB ID,Confidence,Version,Path to File'
            for cveid in pruned_list.keys():
                for edbid in pruned_list[cveid].keys():
                    for confidence in pruned_list[cveid][edbid]['confidence'].keys():
                        for version in pruned_list[cveid][edbid]['confidence'][confidence]:
                            print cveid + "," + \
                                  edbid + "," + \
                                  confidence + "," + \
                                  version + "," + \
                                  pruned_list[cveid][edbid]['notes'] + "," + \
                                  pruned_list[cveid][edbid]['filename']

        else:
            print pruned_list


    def update_exploits(self, args):
        curator = Curator()
        curated_exploits = curator.cves_by_exploit_id(args.edbid)

        if len(curated_exploits) == 0:

            for cveid in curated_exploits.keys():
                curator.curated_exploits[cveid][str(args.edbid)]['confidence'][args.confidence].append(args.version)
                curator.curated_exploits[cveid][str(args.edbid)]['notes'] = args.notes

            curator.write()
        else:
            print "EDB ID %s not among curated exploits. No action taken" \
                  % args.edbid

    def assess(self, args):
        cves = []
        lines = []
        try:
            try:
                lines = subprocess.check_output(["yum","updateinfo","list","cves"]).split('\n')
            except AttributeError:
                p = subprocess.Popen(["yum","updateinfo","list","cves"], stdout=subprocess.PIPE)
                out, err = p.communicate()
                lines = out.split('\n')
        except OSError:
            print "\'assess\' may only be run on an Enterprise Linux host."
            sys.exit(1)
        pattern = re.compile('\s(.*CVE-\d{4}-\d{4,})' )
        for line in lines:
            result = re.findall(pattern, line)
            if result and result[0] not in cves:
                cves.append(result[0])


        curator = Curator()
        curated_exploits = curator.curated_exploits
        for cveid in cves:
            try:
                if args.csv:
                    for edbid in curated_exploits[cveid].keys():
                        for confidence in curated_exploits[cveid][edbid]['confidence'].keys():
                            for version in curated_exploits[cveid][edbid]['confidence'][confidence]:
                                print cveid + "," + \
                                      edbid + "," + \
                                      confidence + "," + \
                                      version + "," + \
                                      curated_exploits[cveid][edbid]['notes'] + "," + \
                                      curated_exploits[cveid][edbid]['filename']
                else:
                    print curator.curated_exploits[cveid]
            except KeyError:
                pass
