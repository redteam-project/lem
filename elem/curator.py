import os
import json

class Curator(object):
    def __init__(self,
                 curator_file_name=os.path.dirname(os.path.realpath(__file__))+"/curator.json"):
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
